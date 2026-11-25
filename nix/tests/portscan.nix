# Port scanner end to end (sensr-scan driven by sensr).
#
#   upstream  WAN DHCP server (as in the slice)
#   router    sensr, imported from home-router.xml with its LAN moved to
#             192.168.10.1/24
#   target    a LAN device: sshd, nginx on 80 (<title>Target</title>) and 443
#             (self-signed certificate for target.lan), unbound on 53/udp,
#             net-snmp with community "public" and sysDescr "vmtarget"
#
# Asserted:
#   (a) the target gets a DHCP lease and an automatic device scan of its MAC
#       completes without anyone asking for it;
#   (b) that scan found tcp 22 (OpenSSH), 80 (title Target), 443 (a
#       certificate for target.lan), udp 53 open and udp 161 (vmtarget);
#   (c) a scan of a public address is refused (409, reason "public");
#   (d) a scan of the LAN /24 completes, finds the target alive and maps
#       its scan to its MAC;
#   (e) sensr-scan runs as user sensr-scan with an empty capability
#       bounding set;
#   (f) no unit failed.
#
# The scans run at pace "fast": a full TCP sweep plus the UDP probes takes
# minutes at the default gentle pace.
#
# parity: (none: OPNsense has no port scanner VM test)
{
  pkgs,
  sensrModules,
}:
let
  inherit (pkgs) lib;
  net = import ./slice/net.nix;
  # The slice's fixture with the LAN (and everything addressed in it: the
  # Kea subnet, pool and reservations, aliases) on 192.168.10.0/24.
  fixture = pkgs.runCommand "home-router-lan10.xml" { } ''
    sed 's/192\.168\.1\./192.168.10./g' ${../../crates/sensr-import-opnsense/tests/fixtures/corpus/home-router.xml} > $out
  '';

  # target.lan's certificate, self-signed (test only).
  cert = pkgs.runCommand "target-lan-cert" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj /CN=target.lan -addext subjectAltName=DNS:target.lan \
      -keyout $out/key.pem -out $out/cert.pem
  '';
  page = pkgs.writeTextDir "index.html" ''
    <!doctype html>
    <html><head><title>Target</title></head><body>target</body></html>
  '';
in
pkgs.testers.runNixOSTest {
  name = "sensr-portscan";

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
      environment.systemPackages = with pkgs; [
        curl
        jq
        sqlite
      ];
    };

    target = {
      virtualisation.interfaces.eth1.vlan = net.lan.vlan;
      networking.useNetworkd = true;
      networking.useDHCP = false;
      # closed ports answer (RST, port unreachable) instead of timing out
      networking.firewall.enable = false;
      virtualisation.memorySize = 768;
      # The link stays down until the test script raises it: the automatic
      # scan starts as soon as the router sees the lease, so the services
      # have to be listening before that.
      systemd.network.networks."10-eth1" = {
        matchConfig.Name = "eth1";
        networkConfig.DHCP = "ipv4";
        linkConfig.ActivationPolicy = "manual";
      };
      systemd.network.wait-online.enable = false;
      # no rate limit on port unreachables: closed UDP ports read as closed
      boot.kernel.sysctl."net.ipv4.icmp_ratelimit" = 0;

      services.openssh.enable = true;

      services.nginx = {
        enable = true;
        virtualHosts."target.lan" = {
          # the scanner sends no SNI and no host name
          default = true;
          addSSL = true;
          sslCertificate = "${cert}/cert.pem";
          sslCertificateKey = "${cert}/key.pem";
          root = "${page}";
        };
      };

      services.unbound = {
        enable = true;
        settings.server = {
          interface = [ "0.0.0.0" ];
          access-control = [ "192.168.10.0/24 allow" ];
        };
      };

      services.snmpd = {
        enable = true;
        configText = ''
          rocommunity public
          sysDescr vmtarget
        '';
      };
    };
  };

  testScript = ''
    import json
    import shlex

    API = "https://127.0.0.1"
    # bcrypt of "opnsense" (as in agent-api.nix), set as root's password for the API
    ROOT_HASH = "$2y$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS"

    def get(path):
        return json.loads(router.succeed(f"curl -skf -u root:opnsense '{API}{path}'"))

    def post(path, body):
        """(HTTP status, JSON body) of a POST to the API."""
        out = router.succeed(
            f"curl -sk -u root:opnsense -o /tmp/post.json -w '%{{http_code}}'"
            f" -X POST -H 'Content-Type: application/json' -d {shlex.quote(json.dumps(body))}"
            f" '{API}{path}'"
        ).strip()
        return int(out), json.loads(router.succeed("cat /tmp/post.json") or "null")

    def port(scan, proto, n):
        rows = [p for p in scan["ports"] if p["proto"] == proto and p["port"] == n]
        assert rows, f"{proto}/{n} not in {[(p['proto'], p['port'], p['state']) for p in scan['ports']]}"
        return rows[0]

    # The target joins only once the scanner runs at pace fast, so its
    # automatic first-join scan is a fast one.
    upstream.start()
    router.start()
    router.wait_for_unit("sensr-agent.service")
    router.wait_for_unit("sensr-api.service")
    router.wait_until_succeeds("ip -4 addr show dev igc1 | grep -q 'inet 192.168.10.1/24'", timeout=120)

    with subtest("API access and the scanner at pace fast"):
        users = json.loads(router.succeed("sensr config get system.users --json"))
        root_id = next(k for k, u in users.items() if u.get("name") == "root")
        router.succeed(
            f"sensr config set system.users.{root_id}.password_hash {shlex.quote(ROOT_HASH)}"
            " && sensr config set --json portscan '{\"pace\": \"fast\"}'"
            " && sensr config commit -m 'portscan test: API password, pace fast'"
        )
        router.wait_until_succeeds("jq -e '.pace == \"fast\"' /run/sensr/portscan/portscan.json", timeout=60)
        print(router.succeed("cat /run/sensr/portscan/portscan.json"))
        router.wait_for_unit("sensr-scan.service")
        router.wait_until_succeeds("test -S /run/sensr-scan/scan.sock", timeout=60)
        router.wait_until_succeeds(f"curl -skf -u root:opnsense {API}/api/v1/portscan/status >/dev/null", timeout=60)

    target.start()
    for unit in ("sshd.service", "nginx.service", "unbound.service", "snmpd.service"):
        target.wait_for_unit(unit)
    target.wait_for_open_port(22)
    target.wait_for_open_port(80)
    target.wait_for_open_port(443)
    target.wait_for_open_port(53)
    target.succeed("ip link set eth1 up")

    with subtest("(a) the target gets a lease and is scanned automatically"):
        target.wait_until_succeeds("ip -4 addr show dev eth1 | grep -q 'inet 192.168.10.'", timeout=120)
        target_ip = json.loads(target.succeed("ip -j -4 addr show dev eth1"))[0]["addr_info"][0]["local"]
        mac = target.succeed("cat /sys/class/net/eth1/address").strip().lower()
        print(f"target {target_ip} {mac}")
        try:
            router.wait_until_succeeds(
                f"curl -skf -u root:opnsense {API}/api/v1/portscan/hosts/{mac}"
                " | jq -e '.latest.status == \"complete\"'",
                timeout=600,
            )
        except Exception:
            print(router.execute(
                f"curl -sk -u root:opnsense {API}/api/v1/portscan/status;"
                f" curl -sk -u root:opnsense '{API}/api/v1/portscan/jobs?kind=device';"
                " cat /proc/net/arp; journalctl -b --no-pager -u sensr-scan -u sensr-agent | tail -n 60"
            )[1])
            raise
        host = get(f"/api/v1/portscan/hosts/{mac}")
        scan = host["latest"]
        print(json.dumps(scan, indent=1))
        assert scan["address"] == target_ip, scan["address"]
        assert scan["mac"] == mac, scan["mac"]
        # nobody asked: the job is the agent's first-join scan
        auto = [j for j in get("/api/v1/portscan/jobs?kind=device") if j["mac"] == mac]
        assert auto and all(j["requested_by"] == "auto" for j in auto), auto

    with subtest("(b) the services are found and identified"):
        p = port(scan, "tcp", 22)
        assert p["state"] == "open" and p["ident"]["product"] == "OpenSSH", p
        p = port(scan, "tcp", 80)
        assert p["state"] == "open" and p["ident"]["title"] == "Target", p
        p = port(scan, "tcp", 443)
        assert p["state"] == "open" and "target.lan" in (p["ident"]["tls"] or {}).get("subject", ""), p
        p = port(scan, "udp", 53)
        assert p["state"] == "open", p
        p = port(scan, "udp", 161)
        assert p["state"] == "open" and p["ident"]["product"] == "vmtarget", p

    with subtest("(c) a public address is refused"):
        code, body = post("/api/v1/portscan/start", {"target": "1.1.1.1", "kind": "device"})
        assert code == 409, (code, body)
        assert body["reason"] == "public", body

    with subtest("(d) a range scan of the LAN finds the target under its MAC"):
        code, body = post("/api/v1/portscan/start", {"target": "192.168.10.0/24", "kind": "range"})
        assert code == 200, (code, body)
        job_id = body["job_id"]
        router.wait_until_succeeds(
            f"curl -skf -u root:opnsense {API}/api/v1/portscan/jobs/{job_id}"
            " | jq -e '.job.status == \"complete\"'",
            timeout=600,
        )
        out = get(f"/api/v1/portscan/jobs/{job_id}")
        print(json.dumps(out["job"], indent=1))
        assert out["job"]["hosts_alive"] >= 1, out["job"]
        mine = [s for s in out["scans"] if s["address"] == target_ip]
        assert len(mine) == 1 and mine[0]["mac"] == mac, out["scans"]

    with subtest("(e) sensr-scan runs as sensr-scan without capabilities"):
        pid = router.succeed("systemctl show -P MainPID sensr-scan.service").strip()
        assert pid != "0", "sensr-scan is not running"
        uid = router.succeed(f"awk '/^Uid:/ {{print $2}}' /proc/{pid}/status").strip()
        assert uid == router.succeed("id -u sensr-scan").strip(), uid
        router.succeed(f"stat -c %U /proc/{pid} | grep -qx sensr-scan")
        bounding = router.succeed("systemctl show -P CapabilityBoundingSet sensr-scan.service").strip()
        assert bounding == "", f"bounding set {bounding!r}"
        router.succeed(f"grep -q '^CapBnd:\\s*0000000000000000$' /proc/{pid}/status")
        router.succeed(f"grep -q '^CapEff:\\s*0000000000000000$' /proc/{pid}/status")

    with subtest("(f) no failed units"):
        for m in (router, target):
            m.succeed("test -z \"$(systemctl list-units --failed --no-legend)\" || (systemctl list-units --failed; false)")
  '';
}
