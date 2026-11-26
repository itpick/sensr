# Runtime guard end to end: sensr-guard on the router, driven through the
# config and guard APIs.
#
#   upstream  WAN DHCP server (as in the slice)
#   router    sensr, imported from home-router.xml (the guard is on by
#             default, with the built-in core pack), a BPF-LSM kernel
#   target    a LAN host with HTTP on 192.168.1.50:80
#
# Asserted:
#   (a) every program of the core pack is attached (/api/v1/guard/status,
#       and bpftool lists them);
#   (b) exec of /tmp/x is an "exec outside /nix/store" alert: the rule's hit
#       counter moves within 10 s, and the event row is in the database once
#       its de-duplication window (10 s) and the next batch (5 s) have passed;
#   (c) committing a Connect block rule for the target is held for confirm
#       (pending_confirm and confirm_reason in the commit reply), and while
#       it is pending curl from the router to the target fails (a blocked
#       event is recorded); then it is confirmed;
#   (d) never-block (RF1): with an Exec block rule on the nft binary, nft
#       from a root shell is refused, but a commit still succeeds: the
#       agent's own `nft -c` runs (sensr-agent.service, recorded as not
#       blocked) and its systemctl restarts sensr-guard;
#   (e) /boot/firmware/sensr/guard-off and a restart of sensr-guard: the
#       status says kill_switch and the curl goes through; removing it and
#       restarting blocks again;
#   (f) `bpftool prog load` from a shell is a `bpf` event; once the shipped
#       (disabled) rule core-bpf-block-others is enabled through
#       guard.pack_rules (a confirm-held commit), the load fails with EPERM;
#   (g) a core pack 9.0.0 installed in the state directory with a signature
#       from a key that is not in the image's key list is refused on reload:
#       the built-in core stays active, saying why;
#   (h) SIGKILL of sensr-guard: within 2 s the status says not running with
#       every rule inactive, and within 5 s it is back and enforcing;
#   (i) no failed units.
#
# timeScale stretches the timing assertions of (b) and (h) for runs without
# KVM (qemu under TCG loads the programs a hundred times slower); CI runs
# it at 1.
#
# parity: (none: OPNsense has no runtime guard)
{
  pkgs,
  sensrModules,
  timeScale ? 1,
}:
let
  inherit (pkgs) lib;
  net = import ./slice/net.nix;
  fixture = ../../crates/sensr-import-opnsense/tests/fixtures/corpus/home-router.xml;
  targetIp = "192.168.1.50";
  core = "${pkgs.sensr-guard-bpf}/share/sensr-guard/packs/core";

  # A trivial BPF program for bpftool to load (not a guard program).
  trivialBpf =
    pkgs.runCommand "guard-test-trivial-bpf"
      {
        nativeBuildInputs = [ pkgs.llvmPackages_19.clang-unwrapped ];
      }
      ''
        cat > t.c <<'EOF'
        __attribute__((section("socket"), used)) int sensr_test_prog(void *ctx) { return 0; }
        char _license[] __attribute__((section("license"), used)) = "GPL";
        EOF
        mkdir -p $out
        clang -O2 -target bpf -c t.c -o $out/trivial.bpf.o
      '';

  # The core pack as version 9.0.0, laid out as an install leaves it
  # (pack.tar.zst, pack.minisig and the unpacked files), but signed by a
  # throwaway key the image does not trust.
  badPack =
    pkgs.runCommand "guard-test-bad-pack"
      {
        nativeBuildInputs = with pkgs; [
          minisign
          jq
          gnutar
          zstd
        ];
      }
      ''
        export HOME=$TMPDIR
        mkdir -p work $out
        cp ${core}/core.bpf.o ${core}/rules.json work/
        jq '.version = "9.0.0"' ${core}/manifest.json > work/manifest.json
        tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 \
          -C work -cf - core.bpf.o manifest.json rules.json \
          | zstd -q -o $out/pack.tar.zst
        minisign -G -W -p key.pub -s key.sec
        minisign -S -s key.sec -m $out/pack.tar.zst -x $out/pack.minisig
        cp work/* $out/
      '';
in
pkgs.testers.runNixOSTest {
  name = "sensr-guard";

  nodes = {
    upstream = {
      virtualisation.interfaces.wan0.vlan = net.wan.vlan;
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      virtualisation.memorySize = 384;
      systemd.network.networks."10-wan0" = {
        matchConfig.Name = "wan0";
        address = [ "${net.wan.upstream}/${toString net.wan.prefix}" ];
        networkConfig.DHCPServer = true;
        dhcpServerConfig = {
          PoolOffset = 100;
          PoolSize = 101;
          EmitDNS = false;
          EmitRouter = true;
        };
      };
    };

    router = {
      imports = sensrModules ++ [ ../images/common.nix ];
      # the images' kernel (the pack's vmlinux.h); NixOS puts bpf in lsm=
      boot.kernelPackages = pkgs.linuxPackages_latest;
      virtualisation.interfaces = {
        igc0.vlan = net.wan.vlan;
        igc1.vlan = net.lan.vlan;
      };
      virtualisation.memorySize = 1536;
      virtualisation.cores = 2;
      services.sensr.seedDir = "/boot/sensr";
      services.sensr.applier = "slice";
      systemd.tmpfiles.rules = [
        "d /boot 0755 root root -"
        "d /boot/sensr 0755 root root -"
        "C /boot/sensr/config.xml - - - - ${fixture}"
      ];
      users.users.root.hashedPassword = lib.mkForce null;
      # There is no internet here: the scheduled update check (5 min after
      # boot) can only fail, which (i) would count; under TCG the test runs
      # past it.
      systemd.timers.sensr-update.enable = false;
      environment.systemPackages = with pkgs; [
        bpftools
        curl
        jq
      ];
    };

    target = {
      virtualisation.interfaces.eth1.vlan = net.lan.vlan;
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      virtualisation.memorySize = 384;
      systemd.network.networks."10-eth1" = {
        matchConfig.Name = "eth1";
        address = [ "${targetIp}/24" ];
      };
      systemd.services.http = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80 --bind 0.0.0.0";
          WorkingDirectory = "/var/empty";
        };
      };
    };
  };

  testScript = ''
    import json
    import shlex
    import time
    import urllib.parse

    API = "https://127.0.0.1"
    # bcrypt of "opnsense" (as in agent-api.nix), set as root's password for the API
    ROOT_HASH = "$2y$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS"
    TARGET = "${targetIp}"
    CURL_TARGET = f"curl -sf -o /dev/null --max-time 5 http://{TARGET}/"
    NFT = "${pkgs.nftables}/bin/nft"
    TRIVIAL = "${trivialBpf}/trivial.bpf.o"
    BAD_PACK = "${badPack}"
    PIN = "/sys/fs/bpf/sensr_guard_test"
    SCALE = ${toString timeScale}
    # owner rules and the pack-rule override (uuid keys)
    CONNECT_RULE = "6d0de000-0000-4000-8000-0000000000c1"
    NFT_RULE = "6d0de000-0000-4000-8000-0000000000c2"
    BPF_OVERRIDE = "6d0de000-0000-4000-8000-0000000000f1"

    def api(method, path, body=None):
        """(HTTP status, JSON body or None)."""
        data = ""
        if body is not None:
            data = f" -H 'Content-Type: application/json' -d {shlex.quote(json.dumps(body))}"
        code = router.succeed(
            f"curl -sk -u root:opnsense -o /tmp/api.json -w '%{{http_code}}' -X {method}{data} '{API}{path}'"
        ).strip()
        text = router.succeed("cat /tmp/api.json")
        return int(code), (json.loads(text) if text.strip() else None)

    def ok(method, path, body=None):
        code, out = api(method, path, body)
        assert 200 <= code < 300, f"{method} {path}: HTTP {code} {out}"
        return out

    def status():
        return ok("GET", "/api/v1/guard/status")

    def core_pack(s):
        packs = [p for p in s["packs"] if p["name"] == "core"]
        assert len(packs) == 1, s["packs"]
        return packs[0]

    def rule(s, rule_id):
        rows = [r for r in s["rules"] if r["id"] == rule_id]
        return rows[0] if rows else None

    def events(**query):
        q = urllib.parse.urlencode({"limit": 1000, **query})
        return ok("GET", f"/api/v1/guard/events?{q}")["rows"]

    def commit(description):
        return ok("POST", "/api/v1/config/commit", {"description": description})

    def guard_pid():
        return router.succeed("systemctl show -P MainPID sensr-guard.service").strip()

    def poll(what, cond, timeout, interval=0.5):
        """Seconds until cond() returned something truthy (which is returned too)."""
        t0 = time.monotonic()
        while True:
            got = cond()
            if got:
                return time.monotonic() - t0, got
            if time.monotonic() - t0 > timeout:
                raise AssertionError(f"{what}: not within {timeout} s")
            time.sleep(interval)

    def guard_debug():
        print(router.execute(
            "systemctl status sensr-guard --no-pager; journalctl -b -u sensr-guard -u sensr-agent --no-pager | tail -n 80;"
            f" curl -sk -u root:opnsense {API}/api/v1/guard/status | jq ."
        )[1])

    def wait_enforcing(extra="true", timeout=300):
        """Running, enforcing, core active with every program attached, and jq `extra`."""
        cond = (
            ".running and .enforcing"
            " and any(.packs[]; .name == \"core\" and .active and (.programs | length > 0) and all(.programs[]; .attached))"
            f" and ({extra})"
        )
        try:
            router.wait_until_succeeds(
                f"curl -skf -u root:opnsense {API}/api/v1/guard/status | jq -e {shlex.quote(cond)}",
                timeout=timeout,
            )
        except Exception:
            guard_debug()
            raise

    def active(rule_id):
        return f"any(.rules[]; .id == \"{rule_id}\" and .active)"

    start_all()
    target.wait_for_unit("http.service")
    target.wait_for_open_port(80)
    router.wait_for_unit("sensr-agent.service")
    router.wait_for_unit("sensr-api.service")
    router.wait_until_succeeds("ip -4 addr show dev igc1 | grep -q 'inet 192.168.1.1/24'", timeout=120)

    lsm = router.succeed("cat /sys/kernel/security/lsm").strip()
    assert "bpf" in lsm.split(","), f"BPF LSM not active: {lsm}"

    with subtest("API access"):
        users = json.loads(router.succeed("sensr config get system.users --json"))
        root_id = next(k for k, u in users.items() if u.get("name") == "root")
        # The fixture's root has a TOTP seed, so the import turns two-factor on
        # and Basic auth with the password alone is refused (401): off here.
        router.succeed(
            f"sensr config set system.users.{root_id}.password_hash {shlex.quote(ROOT_HASH)}"
            f" && sensr config set --json system.users.{root_id}.otp_enabled false"
            " && sensr config commit -m 'guard test: API password'"
        )
        router.wait_until_succeeds(f"curl -skf -u root:opnsense {API}/api/v1/status >/dev/null", timeout=60)

    with subtest("(a) every program is attached"):
        wait_enforcing()
        s = status()
        print(json.dumps(s, indent=1))
        core = core_pack(s)
        assert core["source"] == "builtin" and core["verified"], core
        programs = core["programs"]
        assert programs and all(p["attached"] for p in programs), programs
        assert not s["kill_switch"], s
        # the kernel agrees: one guard_* program per attached program
        listed = json.loads(router.succeed("bpftool -j prog show"))
        names = {p.get("name") for p in listed}
        # (BPF_OBJ_NAME_LEN cuts names to 15 bytes; bpftool shows the BTF name)
        missing = [p["name"] for p in programs if p["name"] not in names and p["name"][:15] not in names]
        assert not missing, f"not in bpftool prog show: {missing} ({sorted(n for n in names if n)})"
        builtin_version = core["version"]

    with subtest("(b) exec outside /nix/store is an alert"):
        router.succeed("printf '#!/bin/sh\\nexit 0\\n' > /tmp/x && chmod +x /tmp/x")
        hits0 = rule(status(), "core-exec-tmp")["hits"]
        router.succeed("/tmp/x")
        took, _ = poll(
            "core-exec-tmp hit",
            lambda: rule(status(), "core-exec-tmp")["hits"] > hits0,
            timeout=10 * SCALE,
        )
        print(f"core-exec-tmp hit after {took:.1f} s")
        # the row is written once its 10 s window closes, in the next 5 s batch
        took, rows = poll(
            "exec /tmp/x event",
            lambda: [e for e in events(hook="exec", q="/tmp/x") if e["target"] == "/tmp/x"],
            timeout=(10 + 5 + 2) * SCALE,
        )
        print(f"event row after {took:.1f} s: {rows}")
        e = rows[0]
        assert not e["blocked"] and e["action"] == "alert", e
        assert e["rule"] == "core-exec-tmp", e

    with subtest("(c) a Connect block rule is held for confirm and blocks"):
        router.succeed(CURL_TARGET)
        ok("PUT", f"/api/v1/config/doc/guard/rules/{CONNECT_RULE}", {
            "description": "guard test: no HTTP to the target",
            "hook": "connect",
            "target": {"net": {"cidr": f"{TARGET}/32", "ports": [80]}},
            "action": "block",
        })
        # for (d): nft may only be run by never-block units
        ok("PUT", f"/api/v1/config/doc/guard/rules/{NFT_RULE}", {
            "description": "guard test: nobody runs nft",
            "hook": "exec",
            "target": {"path_prefix": NFT},
            "action": "block",
        })
        out = commit("guard test: block rules")
        print(json.dumps(out, indent=1))
        assert out["pending_confirm"], out
        assert "confirm within" in (out["confirm_reason"] or ""), out
        wait_enforcing(f"{active(CONNECT_RULE)} and {active(NFT_RULE)}")
        rc, _ = router.execute(CURL_TARGET)
        assert rc != 0, "curl to the target went through the block rule"
        router.succeed("sensr status --json | jq -e '.pending_confirm != null'")
        _, rows = poll(
            "blocked connect event",
            lambda: [e for e in events(hook="connect", q=TARGET) if e["blocked"]],
            timeout=60,
        )
        print(rows)
        ok("POST", "/api/v1/config/confirm")
        router.succeed("sensr status --json | jq -e '.pending_confirm == null'")
        router.fail(CURL_TARGET)

    with subtest("(d) the agent's own nft and systemctl still run (never-block)"):
        rc, out = router.execute(f"{NFT} list tables 2>&1")
        print(out)
        assert rc != 0 and "not permitted" in out, (rc, out)
        pid0 = guard_pid()
        # a harmless change whose apply runs `nft -c` and restarts sensr-guard
        ok("PUT", "/api/v1/config/doc/guard/retention_days", 29)
        out = commit("guard test: retention 29 days")
        assert not out["pending_confirm"] and not out["confirm_reason"], out
        router.succeed("jq -e '.retention_days == 29' /run/sensr/guard/guard.json")
        router.wait_until_succeeds(f"test \"$(systemctl show -P MainPID sensr-guard.service)\" != {pid0}", timeout=60)
        wait_enforcing(active(NFT_RULE))
        _, rows = poll(
            "nft exec events",
            lambda: (lambda rs: rs if any(e["blocked"] for e in rs)
                     and any(not e["blocked"] and e["unit"] == "sensr-agent.service" for e in rs) else None)(
                [e for e in events(hook="exec", q=NFT) if e["target"] == NFT]
            ),
            timeout=60,
        )
        print(rows)
        assert all(e["unit"] != "sensr-agent.service" for e in rows if e["blocked"]), rows
        # done with it: nothing else is to be refused nft
        ok("DELETE", f"/api/v1/config/doc/guard/rules/{NFT_RULE}")
        out = commit("guard test: nft allowed again")
        assert not out["pending_confirm"], out
        wait_enforcing(f"all(.rules[]; .id != \"{NFT_RULE}\")")
        router.succeed(f"{NFT} list tables >/dev/null")

    with subtest("(e) the boot kill switch file lets everything through"):
        router.succeed(
            "mkdir -p /boot/firmware/sensr && touch /boot/firmware/sensr/guard-off"
            " && systemctl restart sensr-guard.service"
        )
        router.wait_until_succeeds(
            f"curl -skf -u root:opnsense {API}/api/v1/guard/status | jq -e '.running and .kill_switch'",
            timeout=300,
        )
        router.succeed(CURL_TARGET)
        router.succeed("rm /boot/firmware/sensr/guard-off && systemctl restart sensr-guard.service")
        wait_enforcing(f"(.kill_switch | not) and {active(CONNECT_RULE)}")
        router.fail(CURL_TARGET)

    with subtest("(f) a BPF program load is an event, and EPERM once blocked"):
        router.succeed(f"bpftool prog load {TRIVIAL} {PIN} type socket && rm {PIN}")
        _, rows = poll(
            "bpf event",
            lambda: [e for e in events(hook="bpf") if "bpftool" in e["exe"] and not e["blocked"]],
            timeout=(10 + 5 + 2) * SCALE,
        )
        print(rows)
        assert rows[0]["target"] == "prog_load", rows
        ok("PUT", f"/api/v1/config/doc/guard/pack_rules/{BPF_OVERRIDE}", {
            "pack": "core",
            "rule_id": "core-bpf-block-others",
            "enabled": True,
        })
        out = commit("guard test: only sensr-guard loads BPF")
        assert out["pending_confirm"] and out["confirm_reason"], out
        wait_enforcing(active("core-bpf-block-others"))
        ok("POST", "/api/v1/config/confirm")
        rc, out = router.execute(f"bpftool prog load {TRIVIAL} {PIN} type socket 2>&1")
        print(out)
        # libbpf says -EPERM (its probe load is refused first)
        assert rc != 0 and ("EPERM" in out or "not permitted" in out), (rc, out)
        router.fail(f"test -e {PIN}")
        poll(
            "blocked bpf event",
            lambda: [e for e in events(hook="bpf") if "bpftool" in e["exe"] and e["blocked"]],
            timeout=60,
        )
        ok("DELETE", f"/api/v1/config/doc/guard/pack_rules/{BPF_OVERRIDE}")
        out = commit("guard test: BPF loads allowed again")
        assert not out["pending_confirm"], out
        wait_enforcing("any(.rules[]; .id == \"core-bpf-block-others\" and (.active | not))")
        router.succeed(f"bpftool prog load {TRIVIAL} {PIN} type socket && rm {PIN}")

    with subtest("(g) a pack with an untrusted signature is refused; core stays active"):
        # As an install leaves it: version dir with the archive, its
        # signature and the unpacked files, and `current` pointing at it.
        router.succeed(
            "d=/var/lib/sensr-guard/packs/core && mkdir -p $d/9.0.0"
            f" && cp {BAD_PACK}/* $d/9.0.0/ && chmod 0644 $d/9.0.0/*"
            " && ln -sfn 9.0.0 $d/current"
        )
        ok("POST", "/api/v1/guard/reload")
        wait_enforcing()
        core = core_pack(status())
        print(core)
        assert core["active"] and core["source"] == "builtin", core
        assert core["version"] == builtin_version, core
        assert "9.0.0" in (core.get("reason") or "") and "not trusted" in core["reason"], core
        router.fail(CURL_TARGET)
        router.succeed("rm -rf /var/lib/sensr-guard/packs/core")
        ok("POST", "/api/v1/guard/reload")
        wait_enforcing(active(CONNECT_RULE))

    with subtest("(h) a killed sensr-guard: every rule inactive, back within 5 s"):
        pid0 = guard_pid()
        script = (
            "set -u\n"
            f"st() {{ curl -sk --max-time 2 -u root:opnsense {API}/api/v1/guard/status; }}\n"
            "now() { date +%s%3N; }\n"
            "t0=$(now); systemctl kill -s KILL sensr-guard.service; down=; up=\n"
            f"while [ $(( $(now) - t0 )) -lt {30000 * SCALE} ]; do\n"
            "  s=$(st || true)\n"
            "  if [ -z \"$down\" ] && printf '%s' \"$s\" | jq -e '(.running | not) and (.rules | length > 0) and all(.rules[]; .active | not)' >/dev/null 2>&1; then down=$(( $(now) - t0 )); fi\n"
            f"  if [ -n \"$down\" ] && printf '%s' \"$s\" | jq -e '.running and .enforcing and {active(CONNECT_RULE)}' >/dev/null 2>&1; then up=$(( $(now) - t0 )); break; fi\n"
            "done\n"
            "echo \"$down $up\"\n"
        )
        router.succeed(f"cat > /tmp/kill.sh <<'EOF'\n{script}EOF")
        out = router.succeed("bash /tmp/kill.sh").split()
        print(f"down after {out[0] if out else '?'} ms, back after {out[1] if len(out) > 1 else '?'} ms")
        assert len(out) == 2, f"down/up not both seen: {out}"
        down_ms, up_ms = int(out[0]), int(out[1])
        assert down_ms <= 2000 * SCALE, f"rules inactive only after {down_ms} ms"
        assert up_ms <= 5000 * SCALE, f"back only after {up_ms} ms"
        assert guard_pid() != pid0
        router.fail(CURL_TARGET)

    with subtest("(i) no failed units"):
        for m in (router, target, upstream):
            m.succeed("test -z \"$(systemctl list-units --failed --no-legend)\" || (systemctl list-units --failed; false)")
  '';
}
