# Traffic insight end to end: known flows through the router are accounted
# per host, per service, per remote and per interface; then the CPU cost of
# accounting at line rate.
#
#   upstream  WAN DHCP server and the internet's router (as in the slice)
#   internet  HTTP (GET /big = 32 MiB, PUT anything), UDP sink, iperf3
#   router    sensr, imported from home-router.xml, insight on
#   lan       LAN client
#
# Asserted: after a 32 MiB download, an 8 MiB upload and 200 UDP datagrams
# of 1000 bytes, flows.db holds them for the LAN host, for tcp/80 and
# udp/5001, for the remote and for the LAN interface, at 1-minute, 1-hour and
# 1-day resolution. Measured (printed, not asserted beyond a sanity bound):
# sensr-insight's CPU while iperf3 runs at line rate, and the throughput
# with and without the accounting table.
#
# parity: (none: OPNsense has no Insight VM test)
{
  pkgs,
  sensrModules,
}:
let
  inherit (pkgs) lib;
  net = import ./slice/net.nix;
  fixture = ../../crates/sensr-import-opnsense/tests/fixtures/corpus/home-router.xml;

  server = pkgs.writers.writePython3 "insight-test-server" { flakeIgnore = [ "E501" ]; } ''
    import http.server


    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            n = 32 << 20
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            chunk = b"x" * 65536
            for _ in range(n // len(chunk)):
                self.wfile.write(chunk)

        def do_PUT(self):
            left = int(self.headers.get("Content-Length", "0"))
            while left > 0:
                left -= len(self.rfile.read(min(left, 65536)))
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass


    http.server.ThreadingHTTPServer(("", 80), H).serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "sensr-insight";

  nodes = {
    upstream = {
      virtualisation.interfaces = {
        wan0.vlan = net.wan.vlan;
        inet0.vlan = net.internet.vlan;
      };
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
      systemd.network.networks = {
        "10-wan0" = {
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
        "10-inet0" = {
          matchConfig.Name = "inet0";
          address = [ "${net.internet.upstream}/${toString net.internet.prefix}" ];
        };
      };
    };

    internet = {
      virtualisation.interfaces.inet0.vlan = net.internet.vlan;
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      systemd.network.networks."10-inet0" = {
        matchConfig.Name = "inet0";
        address = [ "${net.internet.host}/${toString net.internet.prefix}" ];
        routes = [ { Gateway = net.internet.upstream; } ];
      };
      systemd.services.insight-test-server = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = server;
      };
      systemd.services.iperf3 = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = "${pkgs.iperf3}/bin/iperf3 -s";
      };
      environment.systemPackages = [ pkgs.socat ];
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
        jq
        nftables
        sqlite
      ];
    };

    lan = {
      virtualisation.interfaces.eth1.vlan = net.lan.vlan;
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      virtualisation.memorySize = 512;
      systemd.network.networks."10-eth1" = {
        matchConfig.Name = "eth1";
        networkConfig.DHCP = "ipv4";
      };
      environment.systemPackages = with pkgs; [
        curl
        socat
        iperf3
      ];
    };
  };

  testScript = ''
    import json
    import time

    INTERNET = "${net.internet.host}"
    DB = "/var/lib/sensr-insight/flows.db"
    MIB = 1 << 20

    def q(sql):
        return router.succeed(f"sqlite3 -readonly -cmd '.timeout 5000' {DB} \"{sql}\"").strip()

    def total(res, kind, key, host="", col="down"):
        v = q(f"SELECT COALESCE(SUM({col}),0) FROM traffic WHERE res={res} AND kind='{kind}' AND key='{key}' AND host='{host}'")
        return int(v or 0)

    def insight_cpu():
        pid = router.succeed("systemctl show -p MainPID --value sensr-insight.service").strip()
        f = router.succeed(f"cat /proc/{pid}/stat").rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / 100.0

    def router_busy():
        f = [int(x) for x in router.succeed("head -1 /proc/stat").split()[1:]]
        return sum(f) - f[3] - f[4], sum(f)

    start_all()
    internet.wait_for_unit("insight-test-server.service")
    router.wait_for_unit("sensr-agent.service")
    router.wait_until_succeeds("ip -4 addr show dev igc0 | grep -q 'inet 11.0.0.'", timeout=120)
    lan.wait_until_succeeds("ip -4 addr show dev eth1 | grep -q 'inet 192.168.1.'", timeout=90)
    lan_ip = json.loads(lan.succeed("ip -j -4 addr show dev eth1"))[0]["addr_info"][0]["local"]
    lan.wait_until_succeeds(f"curl -sf --max-time 5 -o /dev/null http://{INTERNET}/", timeout=60)

    with subtest("insight on: the accounting table and the daemon run"):
        router.succeed(
            "sensr config set --json insight '{\"enabled\": true, \"sample_seconds\": 2}'"
            " && sensr config commit -m 'insight test'"
        )
        router.wait_for_unit("sensr-insight.service")
        router.wait_until_succeeds("nft list table inet sensr_flow | grep -q hu4", timeout=30)
        router.wait_until_succeeds(f"test -e {DB}", timeout=30)
        print(router.succeed("cat /run/sensr/insight/insight.json"))
        # the API's group can read the databases
        router.succeed(f"stat -c '%G %a' {DB} | grep -q '^sensr 640'")

    with subtest("known flows are accounted per host, service, remote and interface"):
        router.sleep(5)
        lan.succeed(f"curl -sf --max-time 60 -o /dev/null http://{INTERNET}/big")
        lan.succeed("head -c 8388608 /dev/zero > /tmp/up && curl -sf --max-time 60 -T /tmp/up http://" + INTERNET + "/up")
        lan.succeed(f"for i in $(seq 200); do head -c 1000 /dev/zero | socat -u - UDP:{INTERNET}:5001; done")
        # two samples later everything is written
        router.sleep(6)
        print(router.succeed(f"sqlite3 -readonly -cmd '.timeout 5000' {DB} 'SELECT res, kind, key, host, up, down FROM traffic WHERE res=60 ORDER BY up+down DESC LIMIT 12'"))
        for res in (60, 3600, 86400):
            down = total(res, "host", lan_ip)
            up = total(res, "host", lan_ip, col="up")
            assert 32 * MIB <= down < 34 * MIB, f"res {res}: host down {down}"
            assert 8 * MIB <= up < 10 * MIB, f"res {res}: host up {up}"
        assert 32 * MIB <= total(60, "app", "tcp/80", lan_ip) < 34 * MIB
        assert 8 * MIB <= total(60, "app", "tcp/80", lan_ip, col="up") < 10 * MIB
        udp = total(60, "app", "udp/5001", lan_ip, col="up")
        # payload + UDP and IP headers, per datagram
        assert 200 * 1028 <= udp <= 200 * 1100, f"udp/5001 {udp}"
        assert 32 * MIB <= total(60, "remote", INTERNET) < 34 * MIB
        # the LAN interface sent the download to the host
        lan_tx = total(60, "iface", "lan", col="up")
        assert lan_tx >= 32 * MIB, f"lan tx {lan_tx}"
        assert total(10, "iface", "lan", col="up") >= 32 * MIB

    with subtest("cost at line rate"):
        def run(label):
            c0, (b0, t0) = insight_cpu(), router_busy()
            w0 = time.time()
            out = json.loads(lan.succeed(f"iperf3 -c {INTERNET} -t 20 -P 4 -R -J"))
            wall = time.time() - w0
            c1, (b1, t1) = insight_cpu(), router_busy()
            mbit = out["end"]["sum_received"]["bits_per_second"] / 1e6
            busy = 100.0 * (b1 - b0) / (t1 - t0)
            core = (c1 - c0) / wall
            print(f"COST {label}: {mbit:.0f} Mbit/s, router busy {busy:.1f} %, sensr-insight {core:.4f} cores")
            return mbit, busy, core
        on = run("accounting on")
        router.succeed("nft delete table inet sensr_flow")
        off = run("accounting off")
        print(f"COST summary: throughput {on[0]:.0f} vs {off[0]:.0f} Mbit/s, router busy {on[1]:.1f} vs {off[1]:.1f} %, daemon {on[2]:.4f} cores")
        assert on[2] < 0.1, f"sensr-insight used {on[2]} cores"
  '';
}
