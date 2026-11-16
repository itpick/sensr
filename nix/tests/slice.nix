# The routing vertical slice (M-slice): sensr imports the synthetic
# home-router.xml and routes for a small network.
#
#   upstream  WAN DHCP server and the internet's router
#   internet  an "internet" HTTP host (echoes the client address) and the
#             WireGuard road-warrior peer "phone"
#   router    sensr (mode = "sensr") or the hand-written oracle of the same
#             config (mode = "reference", ./slice/reference-router.nix)
#   lan       DHCP client in the LAN pool
#   nas       LAN client with the NAS reservation (MAC 02:00:5e:10:00:0a)
#   iot       IoT VLAN 20 client with the thermostat reservation
#
# Assertions: DHCP leases (pool and static reservation), DNS through the
# router, NAT to the internet, the imported filter rules (block and allow),
# the port forward, a WireGuard peer, and commit-confirm rolling back an
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
      systemd.services.http-echo = httpEcho { port = 80; };
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
          dig
          nftables
          wireguard-tools
        ];
        environment.etc."sensr-slice/home-router.xml".source = fixture;
      }
      // (if reference then { imports = [ ./slice/reference-router.nix ]; } else routerSensr);

    lan = client {
      virtualisation.interfaces.eth1.vlan = net.lan.vlan;
      systemd.network.networks."10-eth1" = {
        matchConfig.Name = "eth1";
        networkConfig.DHCP = "ipv4";
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

    REFERENCE = ${py reference}
    PENDING = {
        "importApply": ${py (pending.importApply && !reference)},
        "commitConfirm": ${py (pending.commitConfirm || reference)},
        "configGet": ${py (pending.configGet && !reference)},
    }
    NAS = "${net.nas.ip}"
    IOT = "${net.iot.ip}"
    INTERNET = "${net.internet.host}"

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
