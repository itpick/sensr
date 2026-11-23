# The routing vertical slice (M-slice): sensr imports the synthetic
# home-router.xml and routes for a small network.
#
#   upstream  WAN DHCP server and the internet's router
#   internet  an "internet" HTTP host (echoes the client address), a
#             stratum-1 NTP server, and the WireGuard road-warrior peer "phone"
#   router    sensr (mode = "sensr") or the hand-written oracle of the same
#             config (mode = "reference", ./slice/reference-router.nix)
#   lan       DHCP client in the LAN pool
#   nas       LAN client with the NAS reservation (MAC 02:00:5e:10:00:0a)
#   iot       IoT VLAN 20 client with the thermostat reservation
#
# Assertions: DHCP leases (pool and static reservation), DNS through the
# router, NAT to the internet, the imported filter rules (block and allow),
# the port forward, a WireGuard peer, a LAN client setting its clock from the
# router's NTP server (which syncs from the "internet"), and commit-confirm
# rolling back an
# unconfirmed change. In sensr mode each part waits on its flag in
# nix/pending.nix; the reference mode always runs everything except
# commit-confirm, which is sensr's alone.
#
# parity: (none: the slice has no OPNsense test counterpart; it is the
# docs/research/03 §4.1 VM suite for the M-slice)
{
  pkgs,
  sensrModules,
  mode ? "sensr",
}:
let
  inherit (pkgs) lib;
  net = import ./slice/net.nix;
  pending = import ../pending.nix;
  reference = mode == "reference";
  py = b: if b then "True" else "False";
  fixture = ../../crates/sensr-import-opnsense/tests/fixtures/corpus/home-router.xml;

  # A tiny HTTP server answering every request with `reply`, or with the
  # client's address when `reply` is null.
  httpEcho =
    { port, reply ? null }:
    {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig.ExecStart = pkgs.writers.writePython3 "http-echo-${toString port}" { } ''
        import http.server


        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = ${if reply == null then "self.client_address[0]" else ''"${reply}"''}
                b = (body + "\n").encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)


        http.server.ThreadingHTTPServer(("", ${toString port}), H).serve_forever()
      '';
    };

  # What the internet's feed server serves: a blocklist for the URL table
  # alias and a DB-IP-format country database (gzip) for GeoIP.
  feeds = pkgs.runCommand "slice-feeds" { nativeBuildInputs = [ pkgs.gzip ]; } ''
    mkdir -p $out
    printf '# synthetic blocklist\n${net.internet.blocked}\n' > $out/blocklist.txt
    printf '${net.internet.geo},${net.internet.geo},ZZ\n198.51.100.0,198.51.100.255,QQ\n' | gzip -9n > $out/geo.csv.gz
  '';

  client =
    extra:
    lib.recursiveUpdate {
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      virtualisation.memorySize = 384;
      environment.systemPackages = with pkgs; [
        curl
        dig
      ];
    } extra;

  routerSensr = {
    imports = sensrModules ++ [ ../images/common.nix ];
    services.sensr.seedDir = "/boot/sensr";
    # Until import + apply work end to end, the agent only plans, so the
    # commit-confirm assertions still run against the store.
    services.sensr.applier = if pending.importApply then "preview" else "slice";
    # The seed folder as a fresh image has it after someone copied their
    # OPNsense backup onto the FAT partition (the agent imports it once,
    # before its boot apply).
    systemd.tmpfiles.rules = [
      "d /boot 0755 root root -"
      "d /boot/sensr 0755 root root -"
    ]
    ++ lib.optional (!pending.importApply) "C /boot/sensr/config.xml - - - - ${fixture}";
    users.users.root.hashedPassword = lib.mkForce null;
  };
in
pkgs.testers.runNixOSTest {
  name = "sensr-slice-${mode}";

  nodes = {
    upstream = {
      virtualisation.interfaces = {
        wan0 = {
          vlan = net.wan.vlan;
        };
        inet0 = {
          vlan = net.internet.vlan;
        };
      };
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
      systemd.network.networks = {
        "10-wan0" = {
          matchConfig.Name = "wan0";
          address = [
            "${net.wan.upstream}/${toString net.wan.prefix}"
            "${net.wan6.upstream}/${toString net.wan6.prefix}"
          ];
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
      # DHCPv6 with prefix delegation for the router's WAN
      services.kea.dhcp6 = {
        enable = true;
        settings = {
          interfaces-config.interfaces = [ "wan0" ];
          lease-database = {
            type = "memfile";
            persist = false;
          };
          subnet6 = [
            {
              id = 1;
              subnet = "${net.wan6.upstream}/${toString net.wan6.prefix}";
              interface = "wan0";
              pools = [ { pool = "2001:db8:ffff::100-2001:db8:ffff::1ff"; } ];
              pd-pools = [
                {
                  prefix = net.wan6.pdPool;
                  prefix-len = net.wan6.pdPoolLen;
                  delegated-len = net.wan6.delegatedLen;
                }
              ];
            }
          ];
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
        address = [
          "${net.internet.host}/${toString net.internet.prefix}"
          "${net.internet.blocked}/${toString net.internet.prefix}"
          "${net.internet.geo}/${toString net.internet.prefix}"
        ];
        routes = [ { Gateway = net.internet.upstream; } ];
      };
      systemd.services.http-echo = httpEcho { port = 80; };
      # A blocklist (HaGeZi's wildcard format) for the router to download.
      systemd.services.http-list = httpEcho {
        port = 8080;
        reply = "*.listed.example";
      };
      # An authoritative server for a domain the router forwards to (a
      # domain override): the slice has no root servers to recurse to.
      services.unbound = {
        enable = true;
        resolveLocalQueries = false;
        settings.server = {
          interface = [ net.internet.host ];
          access-control = [ "0.0.0.0/0 allow" ];
          local-zone = [ "\"internet.example.\" static" ];
          local-data = [ "\"www.internet.example. A ${net.internet.host}\"" ];
        };
      };
      # The internet's time: a stratum-1 server with no sources of its own.
      services.ntpd-rs = {
        enable = true;
        useNetworkingTimeServers = false;
        settings = {
          server = [ { listen = "[::]:123"; } ];
          synchronization.local-stratum = 1;
        };
      };
      systemd.services.feeds = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server --directory ${feeds} --bind ${net.internet.host} ${toString net.internet.listsPort}";
      };
      environment.systemPackages = with pkgs; [
        curl
        wireguard-tools
      ];
      environment.etc."slice/phone.key".text = net.wg.phonePrivate;
      environment.etc."slice/phone.psk".text = net.wg.phonePsk;
    };

    router =
      { ... }:
      {
        virtualisation.interfaces = {
          igc0 = {
            vlan = net.wan.vlan;
          };
          igc1 = {
            vlan = net.lan.vlan;
          };
        };
        virtualisation.memorySize = 1024;
        environment.systemPackages = with pkgs; [
          curl
          dig
          jq
          nftables
          wireguard-tools
        ];
        environment.etc."sensr-slice/home-router.xml".source = fixture;
      }
      // (if reference then { imports = [ ./slice/reference-router.nix ]; } else routerSensr);

    lan = client {
      virtualisation.interfaces.eth1.vlan = net.lan.vlan;
      # The router is the LAN's time server: a client that syncs from it
      # alone (ntpd-rs; the test instrumentation keeps timesyncd off).
      services.ntpd-rs = {
        enable = true;
        useNetworkingTimeServers = false;
        settings = {
          source = [
            {
              mode = "server";
              address = net.lan.router;
            }
          ];
          synchronization.minimum-agreeing-sources = 1;
        };
      };
      systemd.network.networks."10-eth1" = {
        matchConfig.Name = "eth1";
        networkConfig.DHCP = "ipv4";
        # What a Raspberry Pi OS client sends: evidence for the router's
        # host labels (the "Host labels" subtest).
        dhcpV4Config.VendorClassIdentifier = "dhcpcd-9.4.1:Linux-6.1.0:aarch64:Raspberry Pi";
      };
    };

    nas = client {
      virtualisation.interfaces.eth1.vlan = net.lan.vlan;
      systemd.network.networks."10-eth1" = {
        matchConfig.Name = "eth1";
        linkConfig.MACAddress = net.nas.mac;
        networkConfig.DHCP = "ipv4";
      };
      systemd.services.http-80 = httpEcho {
        port = 80;
        reply = "nas";
      };
      systemd.services.http-443 = httpEcho {
        port = 443;
        reply = "nas";
      };
    };

    iot = client {
      virtualisation.interfaces.eth1.vlan = net.lan.vlan;
      systemd.network.netdevs."10-iot" = {
        netdevConfig = {
          Kind = "vlan";
          Name = "iot";
          MACAddress = net.iot.mac;
        };
        vlanConfig.Id = net.iot.vlanId;
      };
      systemd.network.networks = {
        "10-eth1" = {
          matchConfig.Name = "eth1";
          vlan = [ "iot" ];
          networkConfig.LinkLocalAddressing = "no";
        };
        "20-iot" = {
          matchConfig.Name = "iot";
          networkConfig.DHCP = "ipv4";
        };
      };
    };
  };

  testScript = ''
    import json
    import time

    REFERENCE = ${py reference}
    PENDING = {
        "importApply": ${py (pending.importApply && !reference)},
        "commitConfirm": ${py (pending.commitConfirm || reference)},
        "configGet": ${py (pending.configGet && !reference)},
    }
    NAS = "${net.nas.ip}"
    IOT = "${net.iot.ip}"
    INTERNET = "${net.internet.host}"
    BLOCKED = "${net.internet.blocked}"
    GEO = "${net.internet.geo}"
    LISTS = f"http://{INTERNET}:${toString net.internet.listsPort}"

    def hostname_in(source):
        out = router.succeed(f"sensr config get system.hostname --json --source {source}")
        return json.loads(out)

    def pending(what):
        print(f"PENDING: {what} (nix/pending.nix)")

    def ipv4(machine, ifname):
        out = machine.succeed(f"ip -j -4 addr show dev {ifname}")
        addrs = [a["local"] for i in json.loads(out) for a in i.get("addr_info", [])]
        assert addrs, f"{machine.name}: no IPv4 on {ifname}"
        return addrs[0]

    def blocked(machine, cmd):
        # Dropped, not refused: curl exits 28 (timeout) when a rule drops
        # the SYN, 7 when something answers with a reset.
        rc, out = machine.execute(f"{cmd} --connect-timeout 3 -s -o /dev/null")
        assert rc == 28, f"{machine.name}: expected a drop for {cmd!r}, curl exited {rc}: {out!r}"

    start_all()
    upstream.wait_for_unit("systemd-networkd.service")
    internet.wait_for_unit("http-echo.service")

    if not REFERENCE:
        with subtest("sensr imports home-router.xml from the seed folder"):
            router.wait_for_unit("multi-user.target")
            if PENDING["importApply"]:
                pending("import + apply of home-router.xml; the network assertions below are skipped")
            else:
                # The agent imported /boot/sensr/config.xml at boot, onto
                # the factory revision, and applied it.
                router.wait_for_unit("sensr-agent.service")
                print(router.succeed("sensr config history"))
                print(router.succeed("cat /var/lib/sensr/import-report.txt"))
                # What the boot apply made of it (validation issues, the plan).
                print(router.execute("sensr apply --dry-run --source head 2>&1; sensr status 2>&1; journalctl -b -u sensr-agent --no-pager 2>&1 | tail -n 40")[1])
                assert json.loads(router.succeed("sensr config get system.hostname --json --source head")) == "gw-home"
                # The fixture's peer keys are placeholders; give "phone"
                # the test key pair's public half (nix/tests/slice/net.nix).
                router.succeed(
                    "sensr config set wireguard.peers.${net.wg.phoneUuid}.public_key ${net.wg.phonePublic}"
                    " && sensr config commit -m 'slice: test key for peer phone'"
                )
                # The fixture's time servers do not exist in a sealed test;
                # the "internet" has one.
                router.succeed(
                    # (the flags first: each set must leave a valid document)
                    "sensr config set ntp.servers '[]' --json"
                    " && sensr config set system.time_servers '[\"${net.internet.host}\"]' --json"
                    " && sensr config commit -m 'slice: the internet time server'"
                )
        if PENDING["configGet"]:
            pending("sensr config get")
        else:
            doc = json.loads(router.succeed("sensr config get --json"))
            assert isinstance(doc, dict), doc

    if REFERENCE or not PENDING["importApply"]:
        router.wait_for_unit("multi-user.target")
        router.wait_until_succeeds("ip -4 addr show dev igc0 | grep -q 'inet 11.0.0.'", timeout=120)
        wan_ip = ipv4(router, "igc0")
        print(f"router WAN address: {wan_ip}")

        with subtest("WAN: DHCP lease from the upstream"):
            assert wan_ip.startswith("11.0.0."), wan_ip
            router.succeed("ip -4 route show default | grep -q 'via ${net.wan.upstream}'")

        with subtest("LAN: DHCP lease from the pool"):
            lan.wait_until_succeeds("ip -4 addr show dev eth1 | grep -q 'inet 192.168.1.'", timeout=90)
            ip = ipv4(lan, "eth1")
            last = int(ip.split(".")[3])
            assert ${toString net.lan.poolFirst} <= last <= ${toString net.lan.poolLast}, ip
            lan.succeed("ip -4 route show default | grep -q 'via ${net.lan.router}'")

        if not REFERENCE:
            with subtest("Hosts inventory sees the LAN client's DHCP lease"):
                # Kea writes its lease file 0640 as its DynamicUser; the agent
                # needs CAP_DAC_READ_SEARCH to read it (else no host ever has
                # the "lease" source and the Hosts card offers no Make static).
                router.wait_until_succeeds(
                    "sensr runtime hosts | jq -e '[.hosts[] | select(.sources | index(\"lease\"))] | length > 0'",
                    timeout=60,
                )

        with subtest("LAN: static reservation for the NAS"):
            nas.wait_until_succeeds(f"ip -4 addr show dev eth1 | grep -q 'inet {NAS}/'", timeout=90)

        with subtest("IoT VLAN 20: static reservation for the thermostat"):
            iot.wait_until_succeeds(f"ip -4 addr show dev iot | grep -q 'inet {IOT}/'", timeout=90)

        with subtest("DNS resolves through the router (host overrides)"):
            out = lan.wait_until_succeeds("dig +short @${net.lan.router} nas.home.example A", timeout=30)
            assert out.strip() == NAS, out
            out = lan.succeed("dig +short @${net.lan.router} gw-home.home.example A")
            # OPNsense also registers the firewall's own name for every
            # interface address (unbound.inc unbound_add_host_entries), so
            # the LAN address is one of several answers.
            assert "${net.lan.router}" in out.split(), out
            # IoT may ask the firewall for DNS (rule seq 200).
            out = iot.succeed("dig +short +time=3 @${net.iot.router} cloud.home.example A")
            assert out.strip() == NAS, out

        if not REFERENCE:
            with subtest("DNS: split-horizon override, reservations and DHCP leases by name"):
                out = lan.succeed("dig +short @${net.lan.router} cluster.internal.home.example A")
                assert out.strip() == "192.168.1.20", out
                # Kea reservations, in their subnet's domain.
                out = lan.succeed("dig +short @${net.lan.router} logbox.home.example A")
                assert out.strip() == "192.168.1.20", out
                out = lan.succeed("dig +short @${net.lan.router} thermostat.iot.home.example A")
                assert out.strip() == IOT, out
                out = lan.succeed(f"dig +short @${net.lan.router} -x {IOT}")
                assert out.strip() == "thermostat.iot.home.example.", out
                # The LAN client's own lease, registered under the name it sent.
                lan_ip = ipv4(lan, "eth1")
                lan.wait_until_succeeds(
                    f"dig +short @${net.lan.router} lan.home.example A | grep -x {lan_ip}", timeout=60
                )
                out = lan.succeed(f"dig +short @${net.lan.router} -x {lan_ip}")
                assert out.strip() == "lan.home.example.", out

            with subtest("Host labels: the LAN client's DHCP request labels it"):
                # The passive sniffer (AF_PACKET) reads the client's DHCP
                # vendor class. The DISCOVER at boot may predate it, so the
                # client renews (a fresh REQUEST) until the label carries a
                # DHCP reason; the 30 s inventory poll creates the row.
                mac = lan.succeed("cat /sys/class/net/eth1/address").strip().lower()
                labelled = (
                    "sensr runtime hosts | jq -e"
                    f" '.hosts[] | select(.mac==\"{mac}\") | .label.reasons | any(startswith(\"DHCP\"))'"
                )
                deadline = time.monotonic() + 120
                while True:
                    lan.succeed("networkctl renew eth1")
                    if router.execute(labelled)[0] == 0:
                        break
                    if time.monotonic() > deadline:
                        print(router.succeed("sensr runtime hosts"))
                        print(router.execute("journalctl -b -u sensr-agent --no-pager | grep -i -E 'fingerprint|sniff' | tail -n 20")[1])
                        raise AssertionError(f"no DHCP reason on {mac}'s label")
                    time.sleep(10)
                host = [h for h in json.loads(router.succeed("sensr runtime hosts"))["hosts"] if h.get("mac") == mac][0]
                label = host["label"]
                print(json.dumps(label))
                # A QEMU (52:54:00) MAC that sends DHCP evidence is not taken
                # for a VM; the vendor class makes it a computer.
                assert label["by"] == "auto", label
                assert label["kind"] == "computer", label
                assert "DHCP vendor class: dhcpcd-9.4.1:Linux-6.1.0:aarch64:Raspberry Pi" in label["reasons"], label

            with subtest("DNS: a domain override forwards (names outside the network resolve)"):
                router.succeed(
                    "sensr config set dns.forwarding.servers.6c1d0c3e-0d7b-4c1e-9a51-1f0e4a9b2d77"
                    """ --json '{"domain": "internet.example", "address": "${net.internet.host}"}'"""
                    " && sensr config set dns.blocklists.14d4cffe-087b-45c1-b3a5-b06c07bf285e.urls"
                    """ --json '["http://${net.internet.host}:8080/list.txt"]'"""
                    " && sensr config commit -m 'slice: domain override and a reachable blocklist'"
                )
                # The commit reloads Unbound: a query may time out meanwhile.
                lan.wait_until_succeeds(
                    f"dig +short @${net.lan.router} www.internet.example A | grep -x {INTERNET}", timeout=60
                )

            with subtest("DNSBL: blocked names answer 0.0.0.0, allowed and local names resolve"):
                # Custom entries of the imported policy, and a name from the
                # list sensr downloaded and compiled.
                out = lan.wait_until_succeeds(
                    "dig +short @${net.lan.router} a.listed.example A | grep -x 0.0.0.0", timeout=300
                )
                print(router.succeed("cat /var/lib/sensr-dns/status.json; journalctl -b -u sensr-dnsbl --no-pager | tail -n 20"))
                for name in ["x.ads.example.net", "ads.example.net", "tracker.example.org"]:
                    out = lan.succeed(f"dig +short @${net.lan.router} {name} A")
                    assert out.strip() == "0.0.0.0", f"{name}: {out!r}"
                out = lan.succeed("dig +short @${net.lan.router} x.ads.example.net AAAA")
                assert out.strip() == "::", out
                # The allowlisted name inside the blocked subtree is not blocked.
                out = lan.succeed("dig +short @${net.lan.router} ok.ads.example.net A")
                assert out.strip() != "0.0.0.0", out
                # Exact entries block only the name itself.
                out = lan.succeed("dig +short @${net.lan.router} sub.tracker.example.org A")
                assert out.strip() != "0.0.0.0", out
                # Local and forwarded names are untouched.
                assert lan.succeed("dig +short @${net.lan.router} nas.home.example A").strip() == NAS
                assert lan.succeed("dig +short @${net.lan.router} www.internet.example A").strip() == INTERNET
                # IoT's own policy answers NXDOMAIN for its names; its clients
                # still get the global policy's.
                out = iot.succeed("dig +short +time=3 @${net.iot.router} x.ads.example.net A")
                assert out.strip() == "0.0.0.0", out

        with subtest("NAT: LAN reaches the internet as the router's WAN address"):
            seen = lan.wait_until_succeeds(f"curl -sf --max-time 5 http://{INTERNET}/", timeout=60).strip()
            assert seen == wan_ip, f"internet saw {seen}, expected the WAN address {wan_ip}"

        with subtest("firewall: IoT reaches the internet (seq 220)"):
            seen = iot.succeed(f"curl -sf --max-time 5 http://{INTERNET}/").strip()
            assert seen == wan_ip, seen

        with subtest("firewall: IoT is blocked from the LAN (seq 210)"):
            blocked(iot, f"curl http://{NAS}/")

        with subtest("firewall: LAN reaches the NAS"):
            assert lan.succeed(f"curl -sf --max-time 5 http://{NAS}/").strip() == "nas"

        with subtest("firewall: the WAN is closed by default"):
            blocked(internet, f"curl http://{wan_ip}:8080/")
            blocked(internet, f"curl http://{wan_ip}:80/")
            # sshd runs on the router, but never for the WAN.
            blocked(internet, f"curl telnet://{wan_ip}:22")

        with subtest("port forward: WAN 443 reaches the NAS"):
            out = internet.succeed(f"curl -sf --max-time 5 http://{wan_ip}:443/").strip()
            assert out == "nas", out

        with subtest("WireGuard: the phone peer connects and reaches the LAN (seq 300)"):
            internet.succeed(
                "ip link add wg0 type wireguard"
                " && wg set wg0 private-key /etc/slice/phone.key"
                f" peer ${net.wg.serverPublic} preshared-key /etc/slice/phone.psk"
                f" endpoint {wan_ip}:${toString net.wg.port}"
                " allowed-ips 10.10.10.0/24,192.168.1.0/24 persistent-keepalive 5"
                " && ip addr add ${net.wg.phoneAddress}/32 dev wg0"
                " && ip link set wg0 up"
                " && ip route add 10.10.10.0/24 dev wg0"
                " && ip route add 192.168.1.0/24 dev wg0"
            )
            # Through the tunnel to the LAN (rule seq 300); the first packet
            # triggers the handshake.
            out = internet.wait_until_succeeds(f"curl -sf --max-time 5 http://{NAS}/", timeout=30)
            assert out.strip() == "nas", out
            out = internet.succeed("wg show wg0 latest-handshakes")
            assert int(out.split()[1]) > 0, out
            # The tunnel is not a way onto the firewall itself: no rule
            # passes wg0 -> the firewall's own addresses.
            internet.fail("ping -c1 -W2 ${net.wg.serverAddress}")

    if REFERENCE or not PENDING["importApply"]:
        with subtest("NTP: a LAN client sets its clock from the router"):
            internet.wait_for_unit("ntpd-rs.service")
            # The router answers only once it is synchronised itself
            # (stratum 16 before), so the client's sync proves the chain.
            try:
                # Stratum 3: the client follows the router (2), which follows
                # the internet's server (1); unsynchronised is 16.
                lan.wait_until_succeeds("ntp-ctl status | grep -E 'Stratum:[[:space:]]+3([[:space:]]|$)' > /dev/null", timeout=300)
            finally:
                print(lan.execute("ntp-ctl status; journalctl -b -u ntpd-rs --no-pager | tail -n 20")[1])
                print(router.execute("for c in /run/sensr/ntp/ntp.toml /etc/ntpd-rs/ntp.toml; do [ -e $c ] && cat $c && ntp-ctl -c $c status; done; journalctl -b -u sensr-ntpd -u ntpd-rs --no-pager | tail -n 30")[1])
                print(internet.execute("ntp-ctl status; journalctl -b -u ntpd-rs --no-pager | tail -n 20")[1])
    def runtime(section):
        return json.loads(router.succeed(f"sensr runtime {section}"))

    def gateway(name):
        for g in runtime("gateways")["gateways"]:
            if g["name"] == name:
                return g
        raise AssertionError(f"no gateway {name}")

    def rule_packets(chain, label):
        out = json.loads(router.succeed(f"nft -j list chain inet sensr {chain}"))
        n = 0
        for item in out["nftables"]:
            r = item.get("rule")
            if r and r.get("comment") == label:
                for e in r["expr"]:
                    if "counter" in e and e["counter"]:
                        n += e["counter"]["packets"]
        return n

    if not REFERENCE and not PENDING["importApply"]:
        with subtest("URL table alias: the lan,opt1 blocklist wins over 'Allow LAN to any'"):
            # before the list is reachable the alias is empty: traffic passes
            assert lan.succeed(f"curl -sf --max-time 5 http://{BLOCKED}/").strip() == wan_ip
            router.succeed(
                f"sensr config set firewall.aliases.4b0d1c55-9e1a-4f7e-8a51-0c1f2f6f1b01.content.url {LISTS}/blocklist.txt"
                " && sensr config commit -m 'slice: local blocklist'"
            )
            router.wait_until_succeeds(f"nft list set inet sensr a_BLOCKLIST_4 | grep -q '{BLOCKED}'", timeout=90)
            blocked(lan, f"curl http://{BLOCKED}/")
            # everything else still passes
            assert lan.succeed(f"curl -sf --max-time 5 http://{INTERNET}/").strip() == wan_ip
            status = {a["name"]: a for a in runtime("aliases")}
            assert status["BLOCKLIST"]["entries"] == 1 and not status["BLOCKLIST"]["error"], status["BLOCKLIST"]
            # the disabled alias was never fetched and matches nothing
            assert status["PAUSED_FEED"]["entries"] == 0, status["PAUSED_FEED"]

        with subtest("URL table alias: a reload with the source down renders the last good list"):
            internet.succeed("systemctl stop feeds")
            router.succeed(
                "sensr config set firewall.aliases.4b0d1c55-9e1a-4f7e-8a51-0c1f2f6f1b01.content.refresh.hours 1 --json"
                " && sensr config commit -m 'slice: refresh hourly'"
            )
            router.sleep(15)
            router.succeed(f"nft list set inet sensr a_BLOCKLIST_4 | grep -q '{BLOCKED}'")
            blocked(lan, f"curl http://{BLOCKED}/")
            internet.succeed("systemctl start feeds")

        with subtest("GeoIP alias from a DB-IP-format database"):
            router.succeed(
                f"sensr config set firewall.feeds.geoip_url {LISTS}/geo.csv.gz"
                " && sensr config commit -m 'slice: local GeoIP database'"
            )
            router.wait_until_succeeds(f"nft list set inet sensr a_GEO_BLOCK_4 | grep -q '{GEO}'", timeout=90)
            before = rule_packets("in_wan", "8c3dc3ee-b23e-4170-af5a-5f23b2321d58")
            internet.execute(f"curl --interface {GEO} --connect-timeout 2 -s http://{wan_ip}:8080/")
            after = rule_packets("in_wan", "8c3dc3ee-b23e-4170-af5a-5f23b2321d58")
            assert after > before, f"GeoIP block rule did not match ({before} -> {after})"

        with subtest("gateway monitoring: WAN_DHCP online, then down, then back"):
            # the fixture's monitor address is not on the test network
            router.succeed(
                "sensr config delete gateways.gateways.9df1d26a-e824-425b-95df-aaf0fe534a17.monitor_address"
                " && sensr config commit -m 'slice: monitor the gateway itself'"
            )
            router.wait_until_succeeds(
                "sensr runtime gateways | jq -e '.gateways[] | select(.name==\"WAN_DHCP\") | .status==\"online\"'",
                timeout=120,
            )
            g = gateway("WAN_DHCP")
            assert g["next_hop"] == "${net.wan.upstream}" and g["latency_ms"] is not None, g
            assert g["active_default"], g
            upstream.succeed("sysctl -w net.ipv4.icmp_echo_ignore_all=1")
            router.wait_until_succeeds(
                "sensr runtime gateways | jq -e '.gateways[] | select(.name==\"WAN_DHCP\") | .status==\"down\"'",
                timeout=120,
            )
            upstream.succeed("sysctl -w net.ipv4.icmp_echo_ignore_all=0")
            router.wait_until_succeeds(
                "sensr runtime gateways | jq -e '.gateways[] | select(.name==\"WAN_DHCP\") | .status==\"online\"'",
                timeout=180,
            )

        with subtest("IPv6: a delegated prefix reaches the LAN client (PD, RA)"):
            try:
                router.wait_until_succeeds("ip -6 addr show dev igc1 scope global | grep -q 'inet6 2001:db8:100:'", timeout=120)
                print(router.succeed("networkctl status igc0 --json=short | jq -c .DHCPv6Client"))
            except Exception:
                print(router.execute("networkctl status igc0 --no-pager 2>&1; ip -6 addr; ip -6 route show table all; journalctl -b -u systemd-networkd --no-pager | grep -i -E 'dhcp6|igc0' | tail -40; nft list ruleset | grep -n -i -E '546|547|dhcpv6' | head")[1])
                print(upstream.execute("systemctl status kea-dhcp6-server --no-pager 2>&1 | head -20; journalctl -b -u kea-dhcp6-server --no-pager | tail -30; ip -6 addr show dev wan0")[1])
                raise
            lan.wait_until_succeeds("ip -6 addr show dev eth1 scope global | grep -q 'inet6 2001:db8:100:'", timeout=120)
            router.wait_until_succeeds("sensr runtime ipv6 | jq -e '.[0].state.current.prefix | startswith(\"2001:db8:100:\")'", timeout=60)
            pd = runtime("ipv6")
            print(json.dumps(pd, indent=1))
            assert pd and pd[0]["interface"] == "wan", pd
            assert pd[0]["state"]["current"]["prefix"].startswith("2001:db8:100:"), pd
            # persisted for the next boot
            router.succeed("test -s /var/lib/sensr/state/pd/wan.json")
            # the router's own address is advertised as the DNS server (RDNSS)
            rdnss = lan.succeed("networkctl status eth1 --json=short | jq -r '.DNS[]?.AddressString // empty' || true")
            print(f"LAN RDNSS: {rdnss}")

    with subtest("commit-confirm: an unconfirmed apply rolls back"):
        if PENDING["commitConfirm"]:
            pending("commit-confirm" + (" (sensr only)" if REFERENCE else ""))
        else:
            if PENDING["importApply"]:
                # Nothing imported: commit a known revision to come back to.
                router.succeed("sensr config set system.hostname gw-home")
                router.succeed("sensr config commit -m 'slice: baseline'")
            before = hostname_in("head")
            router.succeed("sensr config set system.hostname slice-unconfirmed")
            router.succeed("sensr config commit --confirm 15 -m 'slice: unconfirmed'")
            assert hostname_in("head") == "slice-unconfirmed"
            print(router.succeed("sensr status"))
            if not PENDING["importApply"]:
                router.wait_until_succeeds("hostname | grep -qx slice-unconfirmed", timeout=30)
            # No `sensr config confirm`: the agent goes back to the previous
            # revision on its own (as a new revision).
            router.wait_until_succeeds(
                f"sensr config get system.hostname --json --source head | grep -qx '\"{before}\"'",
                timeout=90,
            )
            print(router.succeed("sensr config history"))
            if not PENDING["importApply"]:
                router.wait_until_succeeds(f"hostname | grep -qx {before}", timeout=30)

    with subtest("commit-confirm: a confirmed commit stays"):
        if PENDING["commitConfirm"]:
            pending("commit-confirm" + (" (sensr only)" if REFERENCE else ""))
        else:
            router.succeed("sensr config set system.hostname slice-confirmed")
            router.succeed("sensr config commit --confirm 15 -m 'slice: confirmed'")
            router.succeed("sensr config confirm")
            router.sleep(25)
            assert hostname_in("head") == "slice-confirmed"
  '';
}
