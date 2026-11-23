# The house acceptance test: a home network shaped like a real one, with
# sensr as its router, checked end to end and reported as a scorecard.
#
#   upstream  the ISP: DHCPv4 with a reserved public address for the WAN's
#             (spoofed) MAC, DHCPv6 IA_NA + prefix delegation, RA; routes to
#             the "internet" and, optionally, NAT to the real one
#   internet  an HTTP host (echoes the client address, serves the URL-table
#             and DNSBL lists and an IDS trigger), the blocklisted sample
#             addresses, and a WireGuard road-warrior peer with a TEST key
#   router    sensr with three NICs (WAN, LAN, LAN2) whose MACs are the
#             parameters', seeded with a config.xml through the first-boot
#             seed folder
#   lan       a LAN client with a reservation MAC, serving HTTP
#   wifi      a LAN2 client that switches MACs (untrusted, trusted, printer)
#             and addresses
#
# The router's NICs are bound by sensr itself (the `ifnames` seed); with
# router.harness_names_nics the harness renames them instead.
#
# Everything house-specific comes from a parameter file and a seed folder.
# The defaults are synthetic (house/example.json, house/house.xml). A private
# run passes its own at run time, without putting anything into the nix store
# (house/run.sh: SENSR_HOUSE_PARAMS, SENSR_HOUSE_SEED and the NIC MACs are
# read by the VM start scripts and the test driver from the environment).
#
# Each check is PASS, FAIL or SKIP (missing a parameter or the real
# internet). The result table goes to the log and to house-results.json in
# the output directory (or SENSR_HOUSE_RESULTS). The test fails when a check
# listed in house/expect.json fails, or any check with strict = true; checks
# not yet expected are reported but do not fail CI (like nix/pending.nix,
# add a check to expect.json in the PR that makes it pass).
#
# parity: (none; docs/research/03 §4.1 VM suite, acceptance)
{
  pkgs,
  sensrModules,
  strict ? false,
  # Also: example devices on the LAN (DHCP + mDNS from network namespaces),
  # some traffic, two host modes, and screenshots of the dashboard from a
  # LAN client into $out/screenshots. The scorecard is printed, not
  # enforced; the test fails only without a dashboard screenshot.
  screenshots ? false,
}:
let
  inherit (pkgs) lib;
  example = builtins.fromJSON (builtins.readFile ./house/example.json);
  expect = builtins.fromJSON (builtins.readFile ./house/expect.json);

  # The default seed folder: the synthetic config and sensr's `ifnames` seed
  # (each imported device bound to its card's MAC).
  exampleSeed = pkgs.runCommand "sensr-house-example-seed" { } ''
    mkdir -p $out
    cp ${./house/house.xml} $out/config.xml
    cat > $out/ifnames <<EOF
    ${example.router.wan.mac} ${example.router.wan.device}
    ${example.router.lan.mac} ${example.router.lan.device}
    ${example.router.lan2.mac} ${example.router.lan2.device}
    EOF
  '';

  # VLANs of the test network.
  vlan = {
    wan = 1;
    lan = 2;
    internet = 3;
    lan2 = 4;
  };

  # A NIC whose MAC the start script takes from the environment (bash
  # expands it when the VM starts), on a fixed PCI address.
  envNic =
    {
      id,
      vlan,
      addr,
      var,
      mac,
    }:
    [
      "-device virtio-net-pci,netdev=${id},mac=\${${var}:-${mac}},addr=${addr}"
      ''-netdev vde,id=${id},sock="$QEMU_VDE_SOCKET_${toString vlan}"''
    ];

  # HTTP: "/" answers with the client's address; other paths are files
  # under /run/house-www (written by the test script from the parameters).
  httpServer = pkgs.writers.writePython3 "house-http" { } ''
    import http.server
    import os


    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            reply = os.environ.get("REPLY")
            if self.path == "/":
                body = reply or self.client_address[0]
                b = (body + "\n").encode()
            else:
                p = os.path.join("/run/house-www", self.path.lstrip("/"))
                try:
                    with open(p, "rb") as f:
                        b = f.read()
                except OSError:
                    self.send_response(404)
                    self.end_headers()
                    return
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass


    http.server.ThreadingHTTPServer(("", 80), H).serve_forever()
  '';
  http =
    reply:
    {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      environment = lib.optionalAttrs (reply != null) { REPLY = reply; };
      serviceConfig.ExecStart = httpServer;
    };

  client =
    extra:
    lib.recursiveUpdate {
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      virtualisation.memorySize = 512;
      # One-shot DHCP: busybox udhcpc and a script that sets what it got.
      environment.etc."house-udhcpc.sh" = {
        mode = "0755";
        text = ''
          #!/bin/sh
          case "$1" in
            deconfig) ip -4 addr flush dev "$interface" ;;
            bound|renew)
              ip -4 addr flush dev "$interface"
              ip addr add "$ip/$mask" dev "$interface"
              if [ -n "$router" ]; then ip route replace default via "''${router%% *}" dev "$interface"; fi
              ;;
          esac
        '';
      };
      environment.systemPackages = with pkgs; [
        curl
        dig
        chrony
        netcat-openbsd
        iputils
        openssl
      ];
      # The test script configures the client NIC itself (MAC, DHCP).
      systemd.network.networks."10-eth1" = {
        matchConfig.Name = "eth1";
        networkConfig = {
          LinkLocalAddressing = "ipv6";
          IPv6AcceptRA = true;
        };
        linkConfig.RequiredForOnline = "no";
      };
    } extra;

  # Headless Chromium for the screenshots (Playwright, the browsers from
  # the same nixpkgs as its driver).
  shotPython = pkgs.python3.withPackages (ps: [ ps.playwright ]);
  shotBrowsers = pkgs.playwright-driver.browsers-chromium;
  # Download loop for one example device: random rates around $2 KB/s.
  trafficLoop = pkgs.writeShellScript "house-traffic" ''
    export PATH=/run/current-system/sw/bin
    while :; do
      r=$(( $2 + RANDOM % $2 ))
      curl -s -o /dev/null --max-time $(( 4 + RANDOM % 8 )) --limit-rate "''${r}k" "$1"
      sleep $(( RANDOM % 4 ))
    done
  '';

  # The screenshots part of the test script (screenshots = true): after the
  # scorecard, so the checks see the house as usual.
  screenshotScript = ''
    # ------------------------------------------------------- screenshots
    # Example devices: namespace, MAC (a real maker's OUI), DHCP host name,
    # DHCP vendor class ("" sends none), mDNS (instance, TXT, services).
    DEVICES = [
        ("cam", "7c:78:b2:3a:11:01", "wyze-cam-v3", "", None),
        ("door", "9c:76:13:5d:22:02", "Ring-Doorbell", "", None),
        ("prn", "ec:9a:74:6c:33:03", "HP6C3303", "", ("HP OfficeJet Pro 9015", "ty=HP OfficeJet Pro 9015", ["_ipp._tcp", "_printer._tcp"])),
        ("pi", "dc:a6:32:02:8e:35", "rpi4-homeassistant", "", None),
        ("sonos", "5c:aa:fd:44:55:05", "Sonos-Kitchen", "", ("Kitchen", "", ["_sonos._tcp", "_spotify-connect._tcp"])),
        ("iphone", "2a:7e:9c:11:22:06", "Sams-iPhone", "", ("Sam's iPhone", "model=iPhone15,2", ["_companion-link._tcp"])),
        ("tv", "d8:eb:46:77:88:07", "Chromecast", "", ("Living Room TV", "md=Chromecast|fn=Living Room TV", ["_googlecast._tcp"])),
        ("plug", "04:83:08:c8:c9:08", "shellyplug-s-c8c908", "", None),
        ("galaxy", "8c:79:f5:12:34:09", "Galaxy-S24", "android-dhcp-14", None),
        ("pc", "f8:bc:12:ab:cd:10", "DESKTOP-AB12CD3", "MSFT 5.0", None),
        ("mac", "ac:bc:32:9e:01:11", "Annas-MacBook-Air", "", ("Anna's MacBook Air", "model=Mac14,2", ["_companion-link._tcp"])),
        ("switch", "98:b6:e9:4c:22:12", "Nintendo-Switch", "", None),
    ]
    # KB/s around which each device downloads from the "internet"
    TRAFFIC = {"tv": 300, "mac": 120, "pc": 200, "galaxy": 50, "sonos": 30, "switch": 80}
    MODES = {"cam": "isolated", "plug": "quarantine"}
    # bcrypt of "opnsense" (as in agent-api.nix): the seed's hash is synthetic
    ROOT_HASH = "$2y$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS"
    API = f"https://{LAN_IP}"
    UDHCPC = "${pkgs.busybox}/bin/udhcpc"
    IP = "${pkgs.iproute2}/bin/ip"
    dev_ip: dict[str, str] = {}


    def dev_dhcp(ns, name, vendor):
        desk.succeed(
            f"{IP} netns exec {ns} timeout 60 {UDHCPC} -i eth0 -f -q -n -t 10 -T 3"
            f" -x hostname:{q(name)} -V {q(vendor)} -s /etc/house-udhcpc.sh >&2"
        )
        out = json.loads(desk.succeed(f"{IP} -n {ns} -j -4 addr show dev eth0"))
        dev_ip[ns] = [a["local"] for i in out for a in i.get("addr_info", [])][0]


    def dev_mdns(ns, host, m):
        inst, txt, svcs = m
        desk.succeed(
            f"{IP} netns exec {ns} python3 ${./house/mdns.py} {dev_ip[ns]} {q(host)} {q(inst)} {q(txt)} "
            + " ".join(q(s) for s in svcs)
        )


    def hosts_now():
        return {h.get("mac"): h for h in json.loads(router.succeed("sensr runtime hosts"))["hosts"]}


    def label_of(h):
        return (h or {}).get("label") or {}


    users = json.loads(router.succeed("sensr config get system.users --json"))
    root_id = next(k for k, u in users.items() if u.get("name") == "root")
    router.succeed(
        f"sensr config set system.users.{root_id}.password_hash {q(ROOT_HASH)}"
        " && sensr config commit -m 'house: a known root password for the screenshots'"
    )

    desk.wait_for_unit("multi-user.target")
    print("desk:", client_dhcp(desk, None, hostname="admin-desk"))
    for ns, mac, name, vendor, m in DEVICES:
        desk.succeed(
            f"{IP} netns add {ns} && {IP} link add mv-{ns} link eth1 address {mac} type macvlan mode bridge"
            f" && {IP} link set mv-{ns} netns {ns} && {IP} -n {ns} link set lo up"
            f" && {IP} -n {ns} link set mv-{ns} name eth0 && {IP} -n {ns} link set eth0 up"
        )
        dev_dhcp(ns, name, vendor)
    print("example devices:", dev_ip)

    # Labelled once the inventory (30 s poll) has the leases and the sniffer
    # the DHCP and mDNS evidence; renew and re-announce until then.
    deadline = time.monotonic() + 420
    while True:
        for ns, mac, name, vendor, m in DEVICES:
            if m:
                dev_mdns(ns, name, m)
        time.sleep(20)
        hs = hosts_now()
        unlabelled = [d for d in DEVICES if label_of(hs.get(d[1])).get("kind") in (None, "unknown")]
        no_mdns = [d[0] for d in DEVICES if d[4] and not any(r.startswith("mDNS") for r in label_of(hs.get(d[1])).get("reasons", []))]
        no_dhcp = [d for d in DEVICES if d[3] and not any(r.startswith("DHCP") for r in label_of(hs.get(d[1])).get("reasons", []))]
        print(f"labels: {len(DEVICES) - len(unlabelled)}/{len(DEVICES)}; without mDNS {no_mdns}; without DHCP {[d[0] for d in no_dhcp]}")
        if not unlabelled and not no_mdns and not no_dhcp:
            break
        if time.monotonic() > deadline:
            print("WARNING: not every example device is labelled; screenshots anyway")
            print(router.execute("journalctl -b -u sensr-agent --no-pager | grep -i -E 'fingerprint|sniff|sensr-fp' | tail -n 20")[1])
            break
        for ns, mac, name, vendor, m in unlabelled + no_dhcp:
            desk.execute(f"{IP} netns exec {ns} timeout 30 {UDHCPC} -i eth0 -f -q -n -t 5 -T 2 -x hostname:{q(name)} -V {q(vendor)} -s /etc/house-udhcpc.sh >&2")
    for mac, h in sorted(hosts_now().items(), key=lambda kv: str(kv[1].get("ipv4"))):
        lab = label_of(h)
        print(f"HOST {str(h.get('name')):24} {mac} {str(h.get('ipv4')):15} {lab.get('maker')} / {lab.get('kind')} ({lab.get('confidence')}) {h.get('sources')} {lab.get('reasons')}")

    until(desk, f"curl -skf -u root:opnsense {API}/api/v1/status >/dev/null", timeout=60)
    for ns, mode in MODES.items():
        mac = next(d[1] for d in DEVICES if d[0] == ns)
        rc, out = desk.execute(
            f"curl -sk -u root:opnsense -X POST -H 'Content-Type: application/json'"
            f" -d {q(json.dumps({'mac': mac, 'mode': mode}))} {API}/api/v1/hosts/mode"
        )
        print(f"mode {ns} {mode}: rc {rc} {out}")

    # Some traffic for the graphs: downloads at changing rates.
    internet.succeed("dd if=/dev/urandom of=/run/house-www/big bs=1M count=64 status=none")
    for ns, kbs in TRAFFIC.items():
        desk.succeed(f"systemd-run --unit=traffic-{ns} {IP} netns exec {ns} ${trafficLoop} http://{INET}/big {kbs}")
    time.sleep(150)

    rc, out = desk.execute(
        "PLAYWRIGHT_BROWSERS_PATH=${shotBrowsers} FONTCONFIG_FILE=/etc/fonts/fonts.conf"
        f" timeout 900 python3 ${./house/shots.py} {API} /tmp/screenshots root opnsense Chromecast 2>&1",
        timeout=960,
    )
    print(out)
    print(desk.succeed("ls -la /tmp/screenshots"))
    desk.copy_from_vm("/tmp/screenshots")
    desk.succeed("test -s /tmp/screenshots/dashboard-1440-light.png")
    print(f"screenshots: {rc} failed")
  '';
in
pkgs.testers.runNixOSTest {
  name = if screenshots then "sensr-house-screenshots" else "sensr-house";

  nodes = {
    upstream = {
      virtualisation.interfaces = {
        wan0.vlan = vlan.wan;
        inet0.vlan = vlan.internet;
      };
      # The real internet, for a private run that wants it
      # (SENSR_HOUSE_REAL_INTERNET=1; never inside the build sandbox).
      virtualisation.qemu.options = [
        "\${SENSR_HOUSE_REAL_INTERNET:+-netdev user,id=uplink -device virtio-net-pci,netdev=uplink,mac=52:54:00:aa:00:01,addr=0x13}"
      ];
      virtualisation.memorySize = 768;
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      boot.kernel.sysctl = {
        "net.ipv4.ip_forward" = 1;
        "net.ipv6.conf.all.forwarding" = 1;
      };
      environment.systemPackages = with pkgs; [
        dnsmasq
        kea
        radvd
        nftables
        tcpdump
        jq
      ];
    };

    internet = {
      virtualisation.interfaces.inet0.vlan = vlan.internet;
      networking.useNetworkd = true;
      networking.useDHCP = false;
      networking.firewall.enable = false;
      systemd.services.house-http = http null // {
        preStart = "mkdir -p /run/house-www";
      };
      environment.systemPackages = with pkgs; [
        curl
        wireguard-tools
        dig
        netcat-openbsd
      ];
    };

    router =
      { config, ... }:
      {
      imports = sensrModules ++ [ ../images/common.nix ];
      services.sensr.seedDir = "/boot/sensr";
      services.sensr.applier = "slice";
      users.users.root.hashedPassword = lib.mkForce null;
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      # only the three house NICs (no QEMU user-mode NIC)
      virtualisation.qemu.networkingOptions = lib.mkForce [ ];
      virtualisation.qemu.options =
        envNic {
          id = "hwan";
          vlan = vlan.wan;
          addr = "0x10";
          var = "SENSR_HOUSE_MAC_WAN";
          mac = example.router.wan.mac;
        }
        ++ envNic {
          id = "hlan";
          vlan = vlan.lan;
          addr = "0x11";
          var = "SENSR_HOUSE_MAC_LAN";
          mac = example.router.lan.mac;
        }
        ++ envNic {
          id = "hlan2";
          vlan = vlan.lan2;
          addr = "0x12";
          var = "SENSR_HOUSE_MAC_LAN2";
          mac = example.router.lan2.mac;
        }
        ++ [
          "-virtfs local,path=\${SENSR_HOUSE_SEED:-${exampleSeed}},mount_tag=houseseed,security_model=none,readonly=on"
        ];
      environment.systemPackages = with pkgs; [
        dig
        nftables
        wireguard-tools
        tcpdump
        jq
      ];
      # The seed folder as a fresh install has it after someone copied the
      # backup onto it, and (until sensr names NICs from its `ifnames` seed)
      # the NICs named as the config expects, by MAC.
      systemd.services.house-seed = {
        description = "House test: seed folder and NIC names from the host";
        wantedBy = [ "multi-user.target" ];
        requiredBy = [ "sensr-agent.service" ];
        before = [
          "sensr-agent.service"
          "systemd-networkd.service"
          "network-pre.target"
        ];
        wants = [ "network-pre.target" ];
        after = [
          "local-fs.target"
          "systemd-udev-settle.service"
        ];
        unitConfig.DefaultDependencies = false;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        path = with pkgs; [
          coreutils
          util-linux
          iproute2
          kmod
          config.systemd.package
        ];
        script = ''
          set -eu
          modprobe 9pnet_virtio || true
          mkdir -p /run/house-seed /boot/sensr
          mount -t 9p -o trans=virtio,version=9p2000.L,ro houseseed /run/house-seed
          if [ ! -e /var/lib/sensr/seed-imported ] && [ -e /run/house-seed/config.xml ]; then
            install -m 0600 /run/house-seed/config.xml /boot/sensr/config.xml
          fi
          for f in ifnames authorized_keys seed.toml; do
            if [ -e "/run/house-seed/$f" ]; then install -m 0600 "/run/house-seed/$f" "/boot/sensr/$f"; fi
          done
          # strict (default) or partial: how the agent imports a config.xml
          # that does not validate
          if [ -e /run/house-seed/seed-import ]; then
            systemctl set-environment SENSR_SEED_IMPORT="$(cat /run/house-seed/seed-import)"
          fi
          if [ -e /run/house-seed/harness-ifnames ]; then
            udevadm settle
            while read -r mac name; do
              [ -n "$mac" ] || continue
              for d in /sys/class/net/*; do
                if [ "$(cat "$d/address")" = "$mac" ] && [ "''${d##*/}" != "$name" ]; then
                  ip link set "''${d##*/}" down
                  ip link set "''${d##*/}" name "$name"
                fi
              done
            done < /run/house-seed/harness-ifnames
          fi
        '';
      };
      };

    lan = client {
      virtualisation.interfaces.eth1.vlan = vlan.lan;
      systemd.services.house-http = http "lan";
    };

    wifi = client {
      virtualisation.interfaces.eth1.vlan = vlan.lan2;
    };
  }
  // lib.optionalAttrs screenshots {
    # The example devices (one network namespace each, a macvlan on eth1
    # with a real maker's MAC) and the browser.
    desk = client {
      virtualisation.interfaces.eth1.vlan = vlan.lan;
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      imports = [
        {
          environment.systemPackages = [
            shotPython
          ];
          fonts.fontconfig.enable = true;
          fonts.packages = with pkgs; [
            dejavu_fonts
            liberation_ttf
          ];
        }
      ];
    };
  };

  testScript = ''
    import ipaddress
    import json
    import os
    import shlex
    import time

    P = json.load(open(os.environ.get("SENSR_HOUSE_PARAMS", "${./house/example.json}")))
    EXPECT = set(json.loads(${builtins.toJSON (builtins.toJSON expect.pass)}))
    STRICT = ${if strict then "True" else "False"} or os.environ.get("SENSR_HOUSE_STRICT") == "1"
    SCREENSHOTS = ${if screenshots then "True" else "False"}
    REAL_INTERNET = os.environ.get("SENSR_HOUSE_REAL_INTERNET") == "1"
    R = P["router"]
    U = P["upstream"]
    I = P["internet"]
    C = P["clients"]
    LAN_IP = R["lan"]["ip"]
    LAN2_IP = R["lan2"]["ip"]
    results = {}


    def check(cid, fn, needs_internet=False):
        """One acceptance check: fn returns a detail string or raises."""
        if needs_internet and not REAL_INTERNET:
            results[cid] = ("SKIP", "needs the real internet (SENSR_HOUSE_REAL_INTERNET=1)")
            return
        t0 = time.monotonic()
        try:
            detail = fn()
            results[cid] = ("PASS", str(detail or ""))
        except Exception as e:  # noqa: BLE001 - every failure is a result
            results[cid] = ("FAIL", f"{type(e).__name__}: {e}"[:600])
        print(f"CHECK {results[cid][0]:4} {cid} ({time.monotonic() - t0:.0f}s) {results[cid][1]}")


    def skip(cid, why):
        results[cid] = ("SKIP", why)
        print(f"CHECK SKIP {cid} {why}")


    def q(s):
        return shlex.quote(str(s))


    def until(machine, cmd, timeout=60):
        return machine.wait_until_succeeds(cmd, timeout=timeout)


    def dropped(machine, url):
        # curl exits 28 (timeout) when a rule drops the SYN, 7 on a reset.
        rc, out = machine.execute(f"curl --connect-timeout 3 -s -o /dev/null {q(url)}")
        assert rc == 28, f"expected a drop for {url}, curl exited {rc}"
        return "dropped"


    def reaches(machine, url, want=None):
        out = machine.succeed(f"curl -sf --max-time 6 {q(url)}").strip()
        if want is not None:
            assert out == want, f"{url} answered {out!r}, want {want!r}"
        return out


    def dig(machine, name, server, rr="A"):
        return machine.succeed(f"dig +short +time=3 +tries=2 @{server} {q(name)} {rr}").split()


    def ipv4(machine, ifname):
        out = json.loads(machine.succeed(f"ip -j -4 addr show dev {ifname}"))
        return [a["local"] for i in out for a in i.get("addr_info", []) if not a["local"].startswith("169.254.")]


    def client_dhcp(machine, mac, hostname=None, static=None, prefix=None, gw=None):
        """Give the client NIC this MAC, then a DHCP lease (or a static address)."""
        machine.execute("pkill -x udhcpc; sleep 0.5")
        machine.succeed("ip -4 addr flush dev eth1")
        if mac:
            machine.succeed(f"ip link set eth1 down && ip link set eth1 address {mac} && ip link set eth1 up")
        if static:
            machine.succeed(f"ip addr add {static}/{prefix} dev eth1 && ip route replace default via {gw}")
            return static
        h = f"-x hostname:{q(hostname)}" if hostname else ""
        machine.succeed(
            f"timeout 90 ${pkgs.busybox}/bin/udhcpc -i eth1 -f -q -n -t 20 -T 3 {h} -s /etc/house-udhcpc.sh >&2"
        )
        got = ipv4(machine, "eth1")
        assert got, "no IPv4 lease"
        return got[0]


    # ---------------------------------------------------------------- network
    start_all()
    upstream.wait_for_unit("multi-user.target")
    internet.wait_for_unit("house-http.service")

    gw = U["gateway"]
    wan_net = ipaddress.ip_interface(f"{gw}/{U['prefix']}").network
    upstream.succeed(f"ip addr add {gw}/{U['prefix']} dev wan0 && ip link set wan0 up")
    upstream.succeed(f"ip addr add {I['upstream']}/{I['prefix']} dev inet0 && ip link set inet0 up")
    internet.succeed(f"ip addr add {I['ip']}/{I['prefix']} dev inet0 && ip link set inet0 up && ip route replace default via {I['upstream']}")
    for a in I.get("extra_addresses", []):
        internet.succeed(f"ip addr add {a}/32 dev lo")
        upstream.succeed(f"ip route replace {a}/32 via {I['ip']}")
    dns_opts = "--no-resolv"
    if REAL_INTERNET:
        upstream.succeed(
            "dev=$(grep -l 52:54:00:aa:00:01 /sys/class/net/*/address | cut -d/ -f5)"
            " && ip link set $dev up && ip addr add 10.0.2.15/24 dev $dev && ip route replace default via 10.0.2.2"
            " && nft add table ip nat && nft add chain ip nat post '{ type nat hook postrouting priority 100; }'"
            " && nft add rule ip nat post oifname $dev masquerade"
        )
        dns_opts = "--server=10.0.2.3"
    pool = U["pool"]
    upstream.succeed(
        "systemd-run --unit=house-dhcp4 dnsmasq -k --interface=wan0 --bind-interfaces"
        f" --dhcp-range={pool[0]},{pool[1]},{wan_net.netmask},1h --dhcp-host={U['spoof_mac']},{U['public_ip']}"
        f" --dhcp-option=option:router,{gw} --dhcp-option=option:dns-server,{gw} {dns_opts} --log-dhcp"
        " --dhcp-leasefile=/run/house-dnsmasq.leases --pid-file=/run/house-dnsmasq.pid"
    )
    v6 = U.get("v6")
    if v6:
        upstream.succeed(f"ip -6 addr add {v6['address']} dev wan0")
        na_net = ipaddress.ip_interface(v6["address"]).network
        kea = {
            "Dhcp6": {
                "interfaces-config": {"interfaces": ["wan0"]},
                "lease-database": {"type": "memfile", "persist": False},
                "subnet6": [{
                    "id": 1,
                    "subnet": str(na_net),
                    "interface": "wan0",
                    "pools": [{"pool": v6["na_pool"]}],
                    "pd-pools": [{
                        "prefix": v6["pd_prefix"],
                        "prefix-len": v6["pd_prefix_len"],
                        "delegated-len": v6["pd_delegated_len"],
                    }],
                }],
            }
        }
        upstream.succeed(f"mkdir -p /run/kea /var/lib/kea && echo {q(json.dumps(kea))} > /etc/house-kea6.json")
        upstream.succeed(
            "systemd-run --unit=house-dhcp6 --setenv=KEA_LOCKFILE_DIR=/run/kea --setenv=KEA_PIDFILE_DIR=/run/kea"
            " kea-dhcp6 -c /etc/house-kea6.json"
        )
        upstream.succeed(
            "printf 'interface wan0 {\\n AdvSendAdvert on;\\n AdvManagedFlag on;\\n AdvOtherConfigFlag on;\\n"
            f" prefix {na_net} {{ AdvAutonomous off; }};\\n}};\\n' > /etc/house-radvd.conf"
            " && systemd-run --unit=house-radvd radvd -n -C /etc/house-radvd.conf -p /run/house-radvd.pid"
        )
    www = {"blocklist.txt": "\n".join(I.get("blocklist", [])) + "\n",
           "dnsbl.txt": "\n".join(I.get("dnsbl", [])) + "\n",
           "ids": "uid=0(root) gid=0(root) groups=0(root)\n"}
    for name, body in www.items():
        internet.succeed(f"mkdir -p /run/house-www && printf %s {q(body)} > /run/house-www/{name}")

    # ----------------------------------------------------------------- router
    router.wait_for_unit("sensr-agent.service", timeout=300)
    router.wait_for_unit("multi-user.target", timeout=300)
    print(router.execute("systemctl status house-seed --no-pager 2>&1; journalctl -b -u house-seed -u sensr-agent --no-pager 2>&1 | tail -n 60; ip -br link; ls -la /boot/sensr /run/house-seed /var/lib/sensr 2>&1")[1])
    report = router.succeed("cat /var/lib/sensr/import-report.txt 2>/dev/null || cat /boot/sensr/import-report.txt 2>/dev/null || true")
    print(router.succeed("sensr config history"))


    def import_clean():
        assert report, "no import report: the seed was not imported"
        for line in report.splitlines():
            if line.startswith("## unmapped, unexpected"):
                n = int(line.split("(")[1].rstrip(")"))
                assert n == 0, f"{n} unexpected unmapped nodes (see the import report in the log)"
        return "no unexpected unmapped nodes"


    check("import.clean", import_clean)

    def import_seed():
        assert report, "no import report"
        assert "## rejected" not in report, "the seed import was rejected (strict); see the report"
        lines = report.splitlines()
        dropped, inside = [], False
        for line in lines:
            if line.startswith("## "):
                inside = line.startswith("## dropped")
            elif inside and line.strip():
                dropped.append(line.strip())
        print("seed import dropped:", dropped)
        return f"imported; {len(dropped)} dropped" + (": " + "; ".join(dropped)[:300] if dropped else "")


    check("import.seed", import_seed)

    def overlay():
        for path, value in P.get("overlay", []):
            if isinstance(value, str):
                router.succeed(f"sensr config set {q(path)} {q(value)}")
            else:
                router.succeed(f"sensr config set --json {q(path)} {q(json.dumps(value))}")
        if P.get("overlay"):
            router.succeed("sensr config commit -m 'house: overlay'")
        return f"{len(P.get('overlay', []))} settings"


    check("config.overlay", overlay)

    wg = P.get("wireguard")
    test_pub = None
    if wg:
        test_pub = internet.succeed("umask 077; wg genkey > /run/wg.key && wg pubkey < /run/wg.key").strip()

        def wg_test_key():
            router.succeed(
                f"sensr config set wireguard.peers.{wg['peer_uuid']}.public_key {test_pub}"
                " && sensr config commit -m 'house: TEST key for the road-warrior peer'"
            )
            return "test key set"

        check("wireguard.test_key", wg_test_key)

    wan = R["wan"]["device"]

    def wan_lease():
        until(router, f"ip -4 addr show dev {wan} | grep -q 'inet {U['public_ip']}/'", timeout=180)
        router.succeed(f"ip -4 route show default | grep -q 'via {gw}'")
        return U["public_ip"]


    check("wan.lease", wan_lease)

    def wan_mac():
        mac = router.succeed(f"cat /sys/class/net/{wan}/address").strip()
        assert mac == U["spoof_mac"].lower(), f"WAN MAC {mac}, want {U['spoof_mac']}"
        return mac


    check("wan.mac_spoof", wan_mac)

    def hostname():
        h = router.succeed("hostname").strip()
        assert h == R["hostname"], f"{h!r}, want {R['hostname']!r}"
        return h


    check("system.hostname", hostname)

    # ------------------------------------------------------------------ DHCP
    lc = C["lan"]

    def lan_reservation():
        ip = client_dhcp(lan, lc["mac"], hostname=lc.get("name"))
        assert ip == lc["ip"], f"got {ip}, want {lc['ip']}"
        lan.succeed(f"ip -4 route show default | grep -q 'via {LAN_IP}'")
        return ip


    check("dhcp.lan.reservation", lan_reservation)

    def lan2_dynamic():
        ip = client_dhcp(wifi, C["lan2_untrusted"]["mac"], hostname="wifitest")
        assert ipaddress.ip_address(ip) in ipaddress.ip_interface(f"{LAN2_IP}/{R['lan2']['prefix']}").network, ip
        wifi.succeed(f"ip -4 route show default | grep -q 'via {LAN2_IP}'")
        return ip


    check("dhcp.lan2.dynamic", lan2_dynamic)
    wifi_ip = (ipv4(wifi, "eth1") or ["?"])[0]

    # ------------------------------------------------------------------- DNS
    D = P.get("dns", {})
    for n in D.get("names", []):
        def dns_name(n=n):
            out = until(lan, f"dig +short +time=2 +tries=3 @{LAN_IP} {q(n['name'])} A | grep -v '^;;'", timeout=60).split()
            assert n["want"] in out, f"{n['name']} -> {out}"
            return " ".join(out)
        check(f"dns.name:{n['name']}", dns_name)
    for p in D.get("ptr", []):
        def dns_ptr(p=p):
            out = lan.succeed(f"dig +short +time=3 @{LAN_IP} -x {p['ip']}").split()
            assert p["want"] in out, f"{p['ip']} -> {out}"
            return " ".join(out)
        check(f"dns.ptr:{p['ip']}", dns_ptr)

    def dns_lease():
        out = until(lan, f"dig +short +time=2 +tries=3 @{LAN_IP} wifitest.{R['domain']} A | grep -v '^;;'", timeout=60).split()
        assert wifi_ip in out, f"wifitest -> {out}, want {wifi_ip}"
        return wifi_ip


    check("dns.dhcp_lease_registered", dns_lease)

    if D.get("recursive"):
        def dns_recursive():
            out = dig(lan, D["recursive"], LAN_IP)
            assert out, "no answer"
            return " ".join(out)
        check("dns.recursive", dns_recursive, needs_internet=True)
    for b in D.get("blocked", []):
        def dnsbl(b=b):
            until(lan, f"dig +short +time=3 @{LAN_IP} {q(b)} A | grep -qx 0.0.0.0", timeout=120)
            return f"{b} -> 0.0.0.0"
        check(f"dns.dnsbl:{b}", dnsbl, needs_internet=not b.endswith(".test"))

    # -------------------------------------------------------------- firewall
    INET = I["ip"]
    PUB = U["public_ip"]

    def nat():
        seen = until(lan, f"curl -sf --max-time 5 http://{INET}/", timeout=60).strip()
        assert seen == PUB, f"internet saw {seen}, want {PUB}"
        return seen


    check("nat.outbound", nat)
    F = P.get("firewall", {})
    for b in F.get("blocked_destinations", []):
        def blocked_dest(b=b):
            internet.succeed(f"ip -4 addr show dev lo | grep -q 'inet {b['ip']}/'")
            return dropped(lan, f"http://{b['ip']}/") + f" (alias {b['alias']}, LAN; before 'allow LAN to any')"
        check(f"firewall.outbound_block:{b['alias']}", blocked_dest, needs_internet=False)
        def blocked_dest2(b=b):
            return dropped(wifi, f"http://{b['ip']}/") + f" (alias {b['alias']}, LAN2)"
        check(f"firewall.outbound_block_lan2:{b['alias']}", blocked_dest2)
    check("firewall.lan2_internet", lambda: reaches(wifi, f"http://{INET}/", PUB))
    check("firewall.lan2_untrusted_to_lan_blocked", lambda: dropped(wifi, f"http://{lc['ip']}/"))
    def lan2_dns():
        out = dig(wifi, R["hostname"] + "." + R["domain"], LAN2_IP)
        assert out, "no answer"
        return " ".join(out)


    check("firewall.lan2_dns_to_router", lan2_dns)
    check("firewall.lan2_ping_router", lambda: wifi.succeed(f"ping -c1 -W3 {LAN2_IP}") and "ok")
    check("firewall.lan_to_lan2", lambda: lan.succeed(f"ping -c1 -W3 {wifi_ip}") and "ok")

    def ntp():
        wifi.succeed(f"chronyd -Q -t 10 'server {LAN2_IP} iburst maxsamples 1'")
        return "router answers NTP"


    check("ntp.served_on_lan2", ntp)

    def ssh_ports():
        lan.succeed(f"nc -z -w3 {LAN_IP} 22")
        wifi.succeed(f"nc -z -w3 {LAN2_IP} 22")
        rc, _ = wifi.execute(f"nc -z -w3 {LAN_IP} 22")
        assert rc != 0, "LAN2 (untrusted) reached SSH on the LAN address"
        return "LAN and LAN2 addresses open; LAN address closed to untrusted LAN2"


    check("ssh.listen_and_filter", ssh_ports)

    def ui_tls():
        code = until(lan, f"curl -sk -o /dev/null -w '%{{http_code}}' https://{LAN_IP}:{P.get('ui', {}).get('https_port', 443)}/ | grep -E '^(200|30[0-9])$'", timeout=60).strip()
        cert = lan.succeed(f"echo | openssl s_client -connect {LAN_IP}:443 2>/dev/null | openssl x509 -noout -subject -enddate 2>/dev/null || true")
        return f"HTTP {code}; {cert.strip()}"


    check("ui.tls_lan", ui_tls)

    if "lan2_trusted" in C:
        def trusted():
            client_dhcp(wifi, C["lan2_trusted"]["mac"], hostname="trusted")
            return reaches(wifi, f"http://{lc['ip']}/", "lan")
        check("firewall.lan2_trusted_mac_to_lan", trusted)
    if "lan2_printer" in C:
        def printer():
            ip = client_dhcp(wifi, C["lan2_printer"]["mac"], hostname="printer")
            assert ip == C["lan2_printer"]["ip"], f"printer got {ip}"
            reaches(wifi, f"http://{INET}/", PUB)
            dropped(wifi, f"http://{lc['ip']}/")
            return f"{ip}: reservation, internet allowed, LAN blocked"
        check("dhcp+firewall.printer", printer)
    if "lan2_static_allowed" in C:
        def laptop():
            client_dhcp(wifi, C["lan2_untrusted"]["mac"], static=C["lan2_static_allowed"]["ip"], prefix=R["lan2"]["prefix"], gw=LAN2_IP)
            return reaches(wifi, f"http://{lc['ip']}/", "lan")
        check("firewall.lan2_allowed_address_to_lan", laptop)

    def wan_closed():
        internet.fail(f"ping -c2 -W2 {PUB}")
        for port in F.get("wan_closed_tcp", [22]):
            rc, _ = internet.execute(f"nc -z -w3 {PUB} {port}")
            assert rc != 0, f"WAN TCP {port} is open"
        return "ping and " + ",".join(map(str, F.get("wan_closed_tcp", [22]))) + " closed"


    check("firewall.wan_inbound_closed", wan_closed)

    # ------------------------------------------------------------- WireGuard
    if wg:
        def wireguard():
            spub = router.succeed("wg show all public-key | awk '{print $2}' | head -n1").strip()
            lan_net = str(ipaddress.ip_interface(f"{LAN_IP}/{R['lan']['prefix']}").network)
            internet.succeed(
                "ip link add wg0 type wireguard && wg set wg0 private-key /run/wg.key"
                f" peer {spub} endpoint {PUB}:{wg['port']} allowed-ips {wg['tunnel_net']},{lan_net} persistent-keepalive 5"
                f" && ip addr add {wg['peer_address']}/32 dev wg0 && ip link set wg0 up"
                f" && ip route add {wg['tunnel_net']} dev wg0 && ip route add {lan_net} dev wg0"
            )
            until(internet, f"curl -sf --max-time 5 http://{lc['ip']}/ | grep -qx lan", timeout=45)
            hs = internet.succeed("wg show wg0 latest-handshakes").split()
            assert int(hs[1]) > 0, hs
            dns = internet.succeed(f"dig +short +time=3 @{LAN_IP} {q(R['hostname'] + '.' + R['domain'])}").split()
            return f"handshake; LAN host via the tunnel; DNS {dns}"
        check("wireguard.handshake_and_lan", wireguard)

    # ------------------------------------------------------------------ IPv6
    if v6:
        lan_dev = R["lan"]["device"]

        def v6_wan():
            until(router, f"ip -6 addr show dev {wan} scope global | grep -q inet6", timeout=120)
            return router.succeed(f"ip -6 -br addr show dev {wan} scope global").strip()
        check("ipv6.wan_dhcp6", v6_wan)

        def v6_pd():
            pd = ipaddress.ip_network(f"{v6['pd_prefix']}/{v6['pd_prefix_len']}")
            out = until(router, f"ip -6 -br addr show dev {lan_dev} scope global | grep inet6 || ip -6 -br addr show dev {lan_dev} scope global", timeout=120)
            addrs = [ipaddress.ip_interface(a) for a in out.split()[2:]]
            assert any(a.ip in pd for a in addrs), f"LAN has {out.strip()}, nothing from {pd}"
            # the upstream routes the delegated prefixes to the router
            ll = router.succeed(f"ip -6 -br addr show dev {wan} scope link").split()[2].split("/")[0]
            upstream.succeed(f"ip -6 route replace {pd} via {ll} dev wan0")
            return out.strip()
        check("ipv6.prefix_delegation_to_lan", v6_pd)

        def v6_client():
            out = until(lan, "ip -6 -br addr show dev eth1 scope global | grep -q inet6 && ip -6 -br addr show dev eth1 scope global", timeout=90)
            up = str(ipaddress.ip_interface(v6["address"]).ip)
            until(lan, f"ping -6 -c1 -W3 {up}", timeout=30)
            return out.strip() + f"; reaches {up}"
        check("ipv6.ra_slaac_client_reaches_upstream", v6_client)

    # ------------------------------------------------------------ IDS, insight
    ids = P.get("ids")
    if ids:
        def ids_alert():
            lan.succeed(f"curl -s --max-time 5 http://{INET}/ids >/dev/null")
            out = until(router, "grep -h '\"event_type\":\"alert\"' /var/log/suricata/eve.json /var/lib/sensr/ids/eve.json 2>/dev/null | tail -n 3", timeout=60)
            return out.strip()[:300]
        check("ids.alert_on_wan", ids_alert)

    def insight():
        rc, out = router.execute("sensr insight hosts --json 2>&1")
        assert rc == 0, f"exit {rc}: {out[:200]}"
        assert lc["ip"] in out, f"LAN client {lc['ip']} not in the insight data"
        return "LAN client has traffic data"


    check("insight.hosts", insight)

    def units():
        f = router.succeed("systemctl --failed --no-legend --plain | awk '{print $1}'").split()
        assert not f, f"failed units: {f}"
        return "none failed"


    check("system.no_failed_units", units)

    # --------------------------------------------------------- commit-confirm
    def commit_confirm():
        before = json.loads(router.succeed("sensr config get system.hostname --json --source head"))
        router.succeed("sensr config set system.hostname house-unconfirmed")
        router.succeed("sensr config commit --confirm 15 -m 'house: unconfirmed'")
        until(router, "hostname | grep -qx house-unconfirmed", timeout=30)
        until(router, f"sensr config get system.hostname --json --source head | grep -qx {q(json.dumps(before))}", timeout=90)
        until(router, f"hostname | grep -qx {q(before)}", timeout=30)
        return f"rolled back to {before}"


    check("commit_confirm.rollback", commit_confirm)

    ${lib.optionalString screenshots screenshotScript}
    # ---------------------------------------------------------------- report
    print("=== sensr import report ===")
    print(report)
    print("=== house acceptance ===")
    for cid, (st, detail) in sorted(results.items()):
        mark = "*" if cid in EXPECT else " "
        print(f"{st:4} {mark} {cid}  {detail}")
    counts = {s: sum(1 for v in results.values() if v[0] == s) for s in ("PASS", "FAIL", "SKIP")}
    print(f"=== {counts['PASS']} pass, {counts['FAIL']} fail, {counts['SKIP']} skip (* = expected to pass, house/expect.json)")
    dest = os.environ.get("SENSR_HOUSE_RESULTS") or os.path.join(os.environ.get("out", "."), "house-results.json")
    try:
        with open(dest, "w") as fh:
            json.dump({"results": results, "counts": counts}, fh, indent=1)
    except OSError as e:
        print(f"could not write {dest}: {e}")
    bad = [c for c, (s, _) in results.items() if s == "FAIL" and (STRICT or c in EXPECT)]
    missing = [c for c in EXPECT if c not in results]
    if SCREENSHOTS:
        print(f"scorecard not enforced with screenshots: failed {bad}; expected but not run {missing}")
    else:
        assert not bad and not missing, f"failed: {bad}; expected but not run: {missing}"
  '';
}
