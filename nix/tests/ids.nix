# Intrusion detection and prevention end to end (Suricata driven by sensr).
#
#   upstream  WAN DHCP server and the internet's router (as in the slice)
#   internet  an HTTP host: /uid answers like a rooted box ("uid=0(root)…"),
#             /slow trickles for a minute, /big is 64 MiB, /rules/test.rules
#             is the ruleset (testmynids.org is parked; nothing leaves the
#             test's networks)
#   router    sensr, imported from home-router.xml (the slice's fixture)
#   lan       LAN client
#
# Asserted:
#   - rules come from the configured source through suricata-update;
#   - HOME_NET holds the WAN's DHCP address and follows a new one;
#   - detect mode alerts for the uid=0(root) response, including a rule that
#     needs the WAN address in HOME_NET (after NAT the WAN only sees public
#     addresses);
#   - the default suppression list silences STUN, a control rule still alerts;
#   - prevent mode (NFQUEUE) drops the probe, other traffic flows, and a TCP
#     connection open before the switch survives it (stream.midstream);
#   - fail-open: with Suricata stopped, forwarding goes on;
#   - switching IDS off removes the queue table.
#
# parity: (none: OPNsense has no IDS VM test)
{
  pkgs,
  sensrModules,
}:
let
  inherit (pkgs) lib;
  net = import ./slice/net.nix;
  fixture = ../../crates/sensr-import-opnsense/tests/fixtures/corpus/home-router.xml;

  # 2100498 is ET Open's rule, verbatim in what it matches; 9000001 only
  # matches with the WAN address in HOME_NET (the client side of the flow
  # on the WAN is the router's public address); 2016149 is ET INFO STUN
  # (suppressed by default) and 9000002 the same match, not suppressed.
  rules = pkgs.writeText "test.rules" ''
    alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7;)
    alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SENSR TEST root id to a home address"; flow:established,to_client; http.response_body; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:9000001; rev:1;)
    alert udp $HOME_NET any -> any 3478 (msg:"ET INFO Session Traversal Utilities for NAT (STUN Binding Request)"; content:"|00 01|"; depth:2; classtype:misc-activity; sid:2016149; rev:3;)
    alert udp $HOME_NET any -> any 3479 (msg:"SENSR TEST STUN-like control"; content:"|00 01|"; depth:2; classtype:misc-activity; sid:9000002; rev:1;)
  '';

  server = pkgs.writers.writePython3 "ids-test-server" { flakeIgnore = [ "E501" ]; } ''
    import http.server
    import time

    RULES = open("${rules}", "rb").read()


    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def body(self, b):
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/uid":
                self.body(b"uid=0(root) gid=0(root) groups=0(root)\n")
            elif self.path == "/rules/test.rules":
                self.body(RULES)
            elif self.path == "/big":
                n = 64 << 20
                self.send_response(200)
                self.send_header("Content-Length", str(n))
                self.end_headers()
                chunk = b"x" * 65536
                for _ in range(n // len(chunk)):
                    self.wfile.write(chunk)
            elif self.path == "/slow":
                self.send_response(200)
                self.send_header("Content-Length", "120")
                self.end_headers()
                for _ in range(120):
                    self.wfile.write(b".")
                    self.wfile.flush()
                    time.sleep(0.5)
            else:
                self.body(self.client_address[0].encode() + b"\n")

        def log_message(self, *a):
            pass


    http.server.ThreadingHTTPServer(("", 80), H).serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "sensr-ids";

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
      systemd.services.ids-test-server = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = server;
      };
      environment.systemPackages = [ pkgs.socat ];
    };

    router = {
      imports = sensrModules ++ [ ../images/common.nix ];
      virtualisation.interfaces = {
        igc0.vlan = net.wan.vlan;
        igc1.vlan = net.lan.vlan;
      };
      virtualisation.memorySize = 2048;
      virtualisation.cores = 4;
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
      virtualisation.memorySize = 384;
      systemd.network.networks."10-eth1" = {
        matchConfig.Name = "eth1";
        networkConfig.DHCP = "ipv4";
      };
      environment.systemPackages = with pkgs; [
        curl
        socat
      ];
    };
  };

  testScript = ''
    import json
    import time

    INTERNET = "${net.internet.host}"

    def ids_set(doc):
        router.succeed(f"sensr config set --json ids '{json.dumps(doc)}' && sensr config commit -m 'ids test'")

    def alerts(sid):
        rc, out = router.execute(
            f"jq -c 'select(.event_type==\"alert\" and .alert.signature_id=={sid})' /var/log/suricata/eve.json"
        )
        return [l for l in out.splitlines() if l.strip()]

    def stun(port):
        # a STUN binding request header, from the LAN client through NAT
        lan.succeed(f"printf '\\x00\\x01\\x00\\x00\\x21\\x12\\xa4\\x42abcdefghijkl' | socat -u - UDP:{INTERNET}:{port}")

    start_all()
    internet.wait_for_unit("ids-test-server.service")
    router.wait_for_unit("sensr-agent.service")
    router.wait_until_succeeds("ip -4 addr show dev igc0 | grep -q 'inet 11.0.0.'", timeout=120)
    wan_ip = json.loads(router.succeed("ip -j -4 addr show dev igc0"))[0]["addr_info"][0]["local"]
    lan.wait_until_succeeds("ip -4 addr show dev eth1 | grep -q 'inet 192.168.1.'", timeout=90)
    lan.wait_until_succeeds(f"curl -sf --max-time 5 http://{INTERNET}/", timeout=60)

    base = {
        "enabled": True,
        "interfaces": ["wan"],
        "sources": [{"type": "url", "url": f"http://{INTERNET}/rules/test.rules"}],
        "profile": "all",
    }

    with subtest("detect: rules download through suricata-update and load"):
        ids_set(base)
        router.wait_for_unit("sensr-suricata.service")
        router.wait_until_succeeds("test -s /var/lib/suricata/rules/test.rules", timeout=120)
        router.wait_until_succeeds("grep -q 2100498 /var/lib/suricata/rules/test.rules")
        # the update reloads Suricata; wait until the engine has the rules
        router.wait_until_succeeds(
            "suricatasc -c ruleset-stats /run/suricata/suricata-command.socket | jq -e '.message[0].rules_loaded >= 4'",
            timeout=120,
        )
        print(router.succeed("cat /run/sensr/suricata/vars.yaml"))

    with subtest("HOME_NET holds the WAN lease"):
        router.succeed(f"grep -q '{wan_ip}/32' /run/sensr/suricata/vars.yaml")

    with subtest("detect: the uid=0(root) response alerts, also the HOME_NET-dependent rule"):
        out = lan.succeed(f"curl -sf --max-time 5 http://{INTERNET}/uid")
        assert "uid=0(root)" in out, out
        router.wait_until_succeeds("grep -q '\"signature_id\":2100498' /var/log/suricata/eve.json", timeout=30)
        router.wait_until_succeeds("grep -q '\"signature_id\":9000001' /var/log/suricata/eve.json", timeout=30)
        a = json.loads(alerts(9000001)[0])
        assert a["dest_ip"] == wan_ip, a
        # sensr-insight stores them for the alerts view
        router.wait_for_unit("sensr-insight.service")
        router.wait_until_succeeds(
            "sqlite3 -readonly -cmd '.timeout 5000' /var/lib/sensr-insight/alerts.db"
            " 'SELECT COUNT(*) FROM alerts WHERE sid=2100498' | grep -qv '^0$'",
            timeout=30,
        )

    with subtest("suppressions: STUN is silent by default, the control alerts"):
        stun(3478)
        stun(3479)
        router.wait_until_succeeds("grep -q '\"signature_id\":9000002' /var/log/suricata/eve.json", timeout=30)
        assert alerts(2016149) == [], alerts(2016149)

    with subtest("HOME_NET follows a new WAN address"):
        router.succeed("ip addr add 11.0.0.250/24 dev igc0")
        router.wait_until_succeeds("grep -q '11.0.0.250/32' /run/sensr/suricata/vars.yaml", timeout=30)
        router.succeed("ip addr del 11.0.0.250/24 dev igc0")
        router.wait_until_succeeds("! grep -q '11.0.0.250/32' /run/sensr/suricata/vars.yaml", timeout=30)

    with subtest("prevent: the probe is dropped, an open connection survives the switch"):
        lan.succeed(f"(curl -sN --max-time 120 -o /tmp/slow http://{INTERNET}/slow; echo $? > /tmp/slow.rc) >/dev/null 2>&1 &")
        lan.wait_until_succeeds("test $(stat -c %s /tmp/slow) -ge 4", timeout=20)
        ids_set(dict(base, mode="prevent", rule_overrides=[{"sid": 2100498, "action": "drop"}]))
        router.wait_until_succeeds("nft list table inet sensr_ips", timeout=60)
        router.wait_until_succeeds(
            "grep -q '^2100498' /run/sensr/suricata/drop.conf && grep -q 'drop ip' /var/lib/suricata/rules/test.rules",
            timeout=120,
        )
        router.wait_until_succeeds(
            "suricatasc -c ruleset-stats /run/suricata/suricata-command.socket | jq -e '.message[0].rules_loaded >= 4'",
            timeout=120,
        )
        # blocked: the response carrying uid=0(root) never arrives. The rule
        # download and the reload it triggers run in the background, and
        # ruleset-stats reports the rule set the engine has, not the one it is
        # about to load: retry until the new drop rule is in effect.
        lan.wait_until_succeeds(
            f"! curl -s --max-time 8 http://{INTERNET}/uid | grep -q 'uid=0(root)'",
            timeout=60,
        )
        # other traffic flows, also in bulk
        assert lan.succeed(f"curl -sf --max-time 5 http://{INTERNET}/").strip() == wan_ip
        t0 = time.time()
        lan.succeed(f"curl -sf --max-time 60 -o /dev/null http://{INTERNET}/big")
        print(f"64 MiB through the IPS in {time.time() - t0:.1f} s")
        # the connection opened before the switch finished intact
        lan.wait_until_succeeds("test -s /tmp/slow.rc", timeout=90)
        assert lan.succeed("cat /tmp/slow.rc").strip() == "0", lan.succeed("cat /tmp/slow.rc")
        assert lan.succeed("stat -c %s /tmp/slow").strip() == "120"
        print(router.succeed("suricatasc -c dump-counters /run/suricata/suricata-command.socket | jq -c '.message.ips'"))

    with subtest("fail-open: forwarding goes on while Suricata is stopped"):
        router.succeed("systemctl stop sensr-suricata.service")
        assert lan.succeed(f"curl -sf --max-time 5 http://{INTERNET}/").strip() == wan_ip
        router.succeed("systemctl start sensr-suricata.service")

    with subtest("off: the queue table and the engine go away"):
        ids_set(dict(base, enabled=False))
        router.wait_until_fails("nft list table inet sensr_ips", timeout=60)
        router.wait_until_fails("systemctl is-active sensr-suricata.service", timeout=60)
        assert lan.succeed(f"curl -sf --max-time 5 http://{INTERNET}/uid")
  '';
}
