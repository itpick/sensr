# In-app updates are health-gated and roll back by themselves
# (docs/research/04a §5.2, ISS-C-005; docs/PLAN.md G4).
#
# Generation A is the booted router. Its specialisations stand in for the
# releases the updater is offered, through the code path a router runs: a
# file:// update manifest, a closure archive with its sha256, `nix-store
# --import`, the system profile and `switch-to-configuration switch`, then
# the health gate (sensr-update-health).
#
#   bad-apply  the agent's checker rejects Kea's config, so the boot apply
#              holds DHCP back (the 2026-11-23 incident on the live router)
#   bad-dns    sensr-unbound cannot start
#   good       a harmless change that still restarts the agent (and with it
#              the selftest race of the same day)
#
# A bad release must end back on A with DNS and DHCP answering a LAN client,
# status "rolled-back" naming the failed check, running-release unchanged,
# and auto mode must not install it again. The good one must stay.
#
# parity: T-0381
{
  pkgs,
  sensrModules,
}:
let
  inherit (pkgs) lib;

  # A Kea whose config check rejects everything, first on the agent's PATH
  # (the agent runs `kea-dhcp4 -t` before it hands Kea a config).
  rejectingKea = pkgs.writeShellScriptBin "kea-dhcp4" ''
    echo "upgrade test: this kea-dhcp4 rejects every configuration" >&2
    exit 1
  '';

  generation = name: { environment.etc."sensr-test/generation".text = name; };

  # The LAN client's DHCP probe: one lease, its address put on eth1.
  leaseScript = pkgs.writeShellScript "udhcpc-lease" ''
    if [ "$1" = bound ]; then
      ${pkgs.iproute2}/bin/ip addr replace "$ip/24" dev "$interface"
      echo "$ip" > /tmp/lease
    fi
  '';
in
pkgs.testers.runNixOSTest {
  name = "sensr-upgrade";

  nodes.client =
    { lib, ... }:
    {
      # No static address: it gets one from the router's DHCP or not at all.
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
      networking.firewall.enable = false;
      virtualisation.memorySize = 384;
      environment.systemPackages = [ pkgs.dig ];
    };

  nodes.router =
    { lib, ... }:
    {
      imports = sensrModules ++ [ ../images/common.nix ];
      virtualisation.memorySize = 1536;
      users.users.root.hashedPassword = lib.mkForce null;
      services.sensr.seedDir = "/boot/sensr";
      systemd.tmpfiles.rules = [
        "d /boot 0755 root root -"
        "d /srv/update 0755 root root -"
      ];
      services.sensr.updates = {
        manifestUrl = "file:///srv/update/update-manifest.json";
        healthTimeout = 60;
      };
      # The test drives every check and install itself.
      systemd.timers.sensr-update.wantedBy = lib.mkForce [ ];
      environment.systemPackages = with pkgs; [
        dig
        jq
        zstd
      ];

      specialisation = {
        good.configuration = lib.mkMerge [
          (generation "good")
          { systemd.services.sensr-agent.environment.SENSR_TEST_GENERATION = "good"; }
        ];
        bad-apply.configuration = lib.mkMerge [
          (generation "bad-apply")
          { systemd.services.sensr-agent.path = lib.mkBefore [ rejectingKea ]; }
        ];
        bad-dns.configuration = lib.mkMerge [
          (generation "bad-dns")
          { systemd.services.sensr-unbound.serviceConfig.ExecStart = lib.mkForce "${pkgs.coreutils}/bin/false"; }
        ];
      };
    };

  testScript = ''
    import json
    import shlex

    UDHCPC = "${pkgs.busybox}/bin/udhcpc"
    LEASE = "${leaseScript}"
    UPD = "/srv/update"


    def sh(cmd):
        return router.succeed(cmd).strip()


    def status():
        return json.loads(sh("cat /run/sensr/updates/status.json"))


    def running():
        return sh("readlink -f /run/current-system")


    def release():
        return sh("cat /var/lib/sensr/updates/running-release")


    def publish(top, tag):
        """The release `tag` whose system is `top`, as release.yml publishes one.

        A real archive carries the whole closure; everything but the toplevel
        is in this store already, and nix-store --import skips valid paths,
        so the toplevel alone is the same import."""
        name = f"sensr-{BOARD}-{tag}.closure.tar.zst"
        router.succeed(f"nix-store --export {top} | zstd -q -f -o {UPD}/{name}")
        sha = sh(f"sha256sum {UPD}/{name} | cut -d' ' -f1")
        manifest = {
            "tag": tag,
            "version": tag,
            "notes": f"test release {tag}",
            "images": {BOARD: {"system": name, "sha256": sha, "store_path": top}},
        }
        router.succeed(f"echo {shlex.quote(json.dumps(manifest))} > {UPD}/update-manifest.json")


    def request(mode):
        """What the Updates page does: drop a request, the path unit runs it."""
        router.succeed(f"echo '{{\"mode\": \"{mode}\"}}' > /run/sensr/updates/request.json")
        # Joins the job the path unit queued (or runs once more on an empty
        # request); returns when the oneshot is done, failed or not.
        router.execute("systemctl start sensr-update.service", timeout=900)
        router.wait_until_succeeds("test ! -e /run/sensr/updates/request.json", timeout=60)
        st = status()
        print(json.dumps(st, indent=2))
        return st


    def journal(unit, n=80):
        print(router.execute(f"journalctl -b -u {unit} --no-pager | tail -n {n}")[1])


    def dns_and_dhcp_work():
        router.wait_until_succeeds(
            "dig +short +time=2 +tries=1 @127.0.0.1 localhost A | grep -qx 127.0.0.1", timeout=60
        )
        client.succeed("ip -4 addr flush dev eth1; ip link set eth1 up; rm -f /tmp/lease")
        client.wait_until_succeeds(f"{UDHCPC} -i eth1 -n -q -t 3 -T 2 -s {LEASE}", timeout=90)
        lease = client.succeed("cat /tmp/lease").strip()
        assert lease.startswith("192.168.1."), lease
        client.succeed("dig +short +time=2 +tries=2 @192.168.1.1 localhost A | grep -qx 127.0.0.1")


    start_all()
    router.wait_for_unit("multi-user.target")
    router.wait_for_unit("sensr-agent.service")
    router.wait_until_succeeds("systemctl is-active sensr-unbound.service sensr-kea-dhcp4.service", timeout=90)
    client.wait_for_unit("multi-user.target")

    # An installed box has a system profile and /etc/NIXOS; the test VM may not.
    router.succeed("nix-env -p /nix/var/nix/profiles/system --set /run/current-system")
    router.execute("test -e /etc/NIXOS || touch /etc/NIXOS")

    A = running()
    BOARD = sh("jq -r .image /etc/sensr/version.json")
    SPEC = {s: sh(f"readlink -f {A}/specialisation/{s}") for s in ["good", "bad-apply", "bad-dns"]}

    with subtest("generation A is healthy and knows its release"):
        dns_and_dhcp_work()
        router.succeed("sensr status --json | jq -e '.applied != null and .last_apply_error == null'")
        # The gate by hand, as the updater runs it (the test VM's WAN is
        # QEMU's user network: the baseline says which checks apply).
        print(router.succeed("sensr-update-health baseline | tee /tmp/baseline.json"))
        gate = router.succeed("sensr-update-health gate --baseline /tmp/baseline.json --timeout 30 --interval 2")
        print(gate)
        assert json.loads(gate)["result"] == "pass", gate
        publish(A, "v0.0.1")
        st = request("check")
        assert st["phase"] == "up-to-date", st
        assert release() == "v0.0.1"

    def rolled_back(spec, tag, check):
        publish(SPEC[spec], tag)
        st = request("check")
        assert st["phase"] == "update-available", st
        st = request("install")
        journal("sensr-update")
        assert st["phase"] == "rolled-back", st
        assert st["message"].startswith(f"Rolled back from {tag} to v0.0.1: "), st
        assert check in st["rollback"]["failed"], st
        assert st["rollback"]["from"] == tag and st["rollback"]["to"] == "v0.0.1", st
        assert st["rollback"]["healthy_after"] is True, st
        assert running() == A, (running(), A)
        assert sh("readlink -f /nix/var/nix/profiles/system") == A
        assert release() == "v0.0.1"
        assert sh("cat /etc/sensr-test/generation 2>/dev/null || echo A") == "A"
        router.succeed(f"jq -e --arg p {SPEC[spec]} 'any(.[]; .store_path == $p)' /var/lib/sensr/updates/bad-releases.json")
        dns_and_dhcp_work()
        router.succeed("sensr status --json | jq -e '.last_apply_error == null'")

    with subtest("the agent's boot apply is rejected: rolled back to A"):
        rolled_back("bad-apply", "v0.0.2", "agent-clean")

    with subtest("unbound does not start: rolled back to A"):
        rolled_back("bad-dns", "v0.0.3", "dns")

    with subtest("auto mode does not install a release that was rolled back"):
        request("auto-on")
        router.execute("systemctl start sensr-update-timer.service", timeout=900)
        st = status()
        print(json.dumps(st, indent=2))
        assert running() == A
        assert st["phase"] == "update-available", st
        assert "rolled back here before" in st["message"], st
        # The page keeps saying what happened.
        assert st["rollback"]["from"] == "v0.0.3", st
        request("auto-off")

    with subtest("a good release stays"):
        publish(SPEC["good"], "v0.0.4")
        st = request("install")
        journal("sensr-update")
        assert st["phase"] == "done", st
        assert st["rollback"] is None, st
        assert running() == SPEC["good"]
        assert sh("readlink -f /nix/var/nix/profiles/system") == SPEC["good"]
        assert sh("cat /etc/sensr-test/generation") == "good"
        assert release() == "v0.0.4"
        dns_and_dhcp_work()
        st = request("check")
        assert st["phase"] == "up-to-date", st

    with subtest("installing the running generation again switches nothing (T-0381)"):
        before = sh("readlink /nix/var/nix/profiles/system")
        st = request("install")
        assert st["phase"] == "up-to-date", st
        assert sh("readlink /nix/var/nix/profiles/system") == before
        assert running() == SPEC["good"]
  '';
}
