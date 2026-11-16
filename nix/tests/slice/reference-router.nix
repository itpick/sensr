# The slice's oracle: home-router.xml (crates/sensr-import-opnsense/tests/
# fixtures/corpus/) written out by hand as plain NixOS, i.e. what sensr must
# produce after importing that file. checks.slice-reference runs the slice's
# assertions against this router, which proves the assertions themselves
# before sensr's appliers exist; checks.slice runs the same assertions
# against sensr.
#
# Only what the assertions observe is modelled: interfaces and VLANs, WAN
# DHCP, the MVC and legacy filter rules, port forward, outbound NAT,
# Kea subnets and reservations, Unbound host overrides, WireGuard.
# Not modelled: IPv6 / prefix delegation, the URL-table and GeoIP alias
# contents (both are empty sets here: no feed in a sealed test), the DoT and
# domain-forward upstreams, syslog.
{ lib, pkgs, ... }:
let
  net = import ./net.nix;
  # RFC1918_NETS alias and OPNsense's blockpriv / blockbogons (bogons.sample).
  rfc1918 = "192.168.0.0/16";
  private = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10";
  bogons = "0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4";
in
{
  networking.hostName = "gw-home";
  networking.domain = "home.example";
  networking.useNetworkd = true;
  networking.useDHCP = false;
  networking.firewall.enable = false;
  boot.kernel.sysctl."net.ipv4.ip_forward" = 1;

  systemd.network = {
    netdevs = {
      "20-vlan01" = {
        netdevConfig = {
          Kind = "vlan";
          Name = "vlan01";
        };
        vlanConfig.Id = 20;
      };
      "20-vlan02" = {
        netdevConfig = {
          Kind = "vlan";
          Name = "vlan02";
        };
        vlanConfig.Id = 30;
      };
      "30-wg0" = {
        netdevConfig = {
          Kind = "wireguard";
          Name = "wg0";
        };
        wireguardConfig = {
          PrivateKeyFile = "/etc/slice/wg-server.key";
          ListenPort = net.wg.port;
        };
        wireguardPeers = [
          {
            PublicKey = net.wg.phonePublic;
            PresharedKeyFile = "/etc/slice/wg-phone.psk";
            AllowedIPs = [ "${net.wg.phoneAddress}/32" ];
            PersistentKeepalive = 25;
          }
        ];
      };
    };
    networks = {
      "10-igc0" = {
        matchConfig.Name = "igc0";
        networkConfig.DHCP = "ipv4";
        dhcpV4Config.UseDNS = false;
      };
      "10-igc1" = {
        matchConfig.Name = "igc1";
        address = [ "${net.lan.router}/24" ];
        vlan = [
          "vlan01"
          "vlan02"
        ];
      };
      "20-vlan01" = {
        matchConfig.Name = "vlan01";
        address = [ "${net.iot.router}/24" ];
      };
      "20-vlan02" = {
        matchConfig.Name = "vlan02";
        address = [ "192.168.30.1/24" ];
      };
      "30-wg0" = {
        matchConfig.Name = "wg0";
        address = [ "${net.wg.serverAddress}/24" ];
      };
    };
  };
  environment.etc."slice/wg-server.key" = {
    text = net.wg.serverPrivate;
    mode = "0400";
    user = "systemd-network";
  };
  environment.etc."slice/wg-phone.psk" = {
    text = net.wg.phonePsk;
    mode = "0400";
    user = "systemd-network";
  };

  networking.nftables = {
    enable = true;
    # Interface names exist only at runtime.
    checkRuleset = false;
    ruleset = ''
      table inet filter {
        set rfc1918_nets { type ipv4_addr; flags interval; elements = { ${rfc1918} } }
        set private { type ipv4_addr; flags interval; elements = { ${private} } }
        set bogons { type ipv4_addr; flags interval; elements = { ${bogons} } }
        # Alias contents a sealed test cannot fetch: GEO_BLOCK (geoip ZZ)
        # and DROP_FEED (urltable).
        set geo_block { type ipv4_addr; flags interval; }
        set drop_feed { type ipv4_addr; flags interval; }

        # OPNsense evaluates its rules on the interface a packet comes in on,
        # for traffic to the firewall and through it alike; first match wins
        # (quick), default block.
        chain rules {
          # WAN: system rules for blockpriv / blockbogons, then user rules.
          iifname "igc0" ip saddr @private drop
          iifname "igc0" ip saddr @bogons drop
          iifname "igc0" ip saddr @geo_block drop                         # seq 5
          iifname "igc0" udp dport ${toString net.wg.port} fib daddr type local accept  # seq 10
          # Port forward HTTPS -> NAS, "pass" = auto-registered filter rule.
          iifname "igc0" ct status dnat ip daddr ${net.nas.ip} tcp dport 443 accept
          # LAN
          iifname "igc1" ip saddr 192.168.1.0/24 accept                   # seq 100
          # IoT (opt1)
          iifname "vlan01" ip saddr 192.168.20.0/24 ip daddr ${net.iot.router} meta l4proto { tcp, udp } th dport 53 accept  # 200
          iifname "vlan01" ip saddr 192.168.20.0/24 ip daddr 192.168.1.0/24 drop   # 210
          iifname "vlan01" ip saddr 192.168.20.0/24 ip daddr @drop_feed drop      # 215
          iifname "vlan01" ip saddr 192.168.20.0/24 accept                         # 220
          # Guest (opt2), legacy rules in their order.
          iifname "vlan02" ip saddr 192.168.30.0/24 ip daddr @rfc1918_nets drop
          iifname "vlan02" ip saddr 192.168.30.0/24 ip daddr 192.168.30.1 meta l4proto { tcp, udp } th dport 53 accept
          iifname "vlan02" ip saddr 192.168.30.0/24 accept
          # WireGuard (opt3)
          iifname "wg0" ip saddr 10.10.10.0/24 ip daddr 192.168.1.0/24 accept   # 300
          iifname "wg0" ip saddr 10.10.10.0/24 ip daddr ${net.nas.ip} tcp dport 80 accept  # 310
        }

        chain input {
          type filter hook input priority filter; policy drop;
          ct state established,related accept
          ct state invalid drop
          iif "lo" accept
          # Kea's fwrules=1: DHCP to the firewall on its interfaces.
          iifname { "igc1", "vlan01", "vlan02" } udp dport 67 accept
          # WAN DHCP client.
          iifname "igc0" udp sport 67 udp dport 68 accept
          jump rules
        }

        chain forward {
          type filter hook forward priority filter; policy drop;
          ct state established,related accept
          ct state invalid drop
          jump rules
        }
      }

      table ip nat {
        chain prerouting {
          type nat hook prerouting priority dstnat;
          # "HTTPS to NAS reverse proxy": wanip:443 -> NAS_HOST:443
          iifname "igc0" tcp dport 443 fib daddr type local dnat to ${net.nas.ip}:443
        }
        chain postrouting {
          type nat hook postrouting priority srcnat;
          # Hybrid outbound NAT: the automatic rules for every internal
          # network, plus the manual road-warrior rule (10.10.10.0/24).
          oifname "igc0" ip saddr { 192.168.1.0/24, 192.168.20.0/24, 192.168.30.0/24, 10.10.10.0/24 } masquerade
        }
      }
    '';
  };

  # ntpd: the "internet" time server (the fixture's are replaced in the
  # test), served on lan,opt1,opt2's addresses and loopback.
  services.ntpd-rs = {
    enable = true;
    useNetworkingTimeServers = false;
    settings = {
      source = [
        {
          mode = "server";
          address = net.internet.host;
        }
      ];
      server = map (a: { listen = "${a}:123"; }) [
        "127.0.0.1"
        net.lan.router
        net.iot.router
        "192.168.30.1"
      ];
      synchronization.minimum-agreeing-sources = 1;
    };
  };

  services.kea.dhcp4 = {
    enable = true;
    settings = {
      interfaces-config.interfaces = [
        "igc1"
        "vlan01"
        "vlan02"
      ];
      valid-lifetime = 4000;
      lease-database = {
        type = "memfile";
        persist = true;
        name = "/var/lib/kea/dhcp4.leases";
      };
      subnet4 = [
        {
          id = 1;
          subnet = "192.168.1.0/24";
          interface = "igc1";
          pools = [ { pool = "192.168.1.100 - 192.168.1.199"; } ];
          option-data = [
            { name = "routers"; data = "192.168.1.1"; }
            { name = "domain-name-servers"; data = "192.168.1.1"; }
            { name = "domain-name"; data = "home.example"; }
          ];
          reservations = [
            { hw-address = net.nas.mac; ip-address = net.nas.ip; hostname = "nas"; }
            { hw-address = "02:00:5e:10:00:14"; ip-address = "192.168.1.20"; hostname = "logbox"; }
          ];
        }
        {
          id = 2;
          subnet = "192.168.20.0/24";
          interface = "vlan01";
          pools = [ { pool = "192.168.20.100 - 192.168.20.250"; } ];
          option-data = [
            { name = "routers"; data = "192.168.20.1"; }
            { name = "domain-name-servers"; data = "192.168.20.1"; }
            { name = "domain-name"; data = "iot.home.example"; }
          ];
          reservations = [
            { hw-address = net.iot.mac; ip-address = net.iot.ip; hostname = "thermostat"; }
          ];
        }
        {
          id = 3;
          subnet = "192.168.30.0/24";
          interface = "vlan02";
          pools = [ { pool = "192.168.30.50 - 192.168.30.200"; } ];
          option-data = [
            { name = "routers"; data = "192.168.30.1"; }
            { name = "domain-name-servers"; data = "192.168.30.1"; }
            { name = "domain-name"; data = "guest.home.example"; }
          ];
        }
      ];
    };
  };

  services.unbound = {
    enable = true;
    resolveLocalQueries = false;
    settings.server = {
      interface = [
        "127.0.0.1"
        net.lan.router
        net.iot.router
        "192.168.30.1"
        net.wg.serverAddress
      ];
      # OPNsense's automatic ACL: the networks of the internal interfaces.
      access-control = [
        "127.0.0.0/8 allow"
        "192.168.1.0/24 allow"
        "192.168.20.0/24 allow"
        "192.168.30.0/24 allow"
        "10.10.10.0/24 allow"
      ];
      # Interfaces come up after unbound in a test VM.
      ip-freebind = true;
      local-zone = [ ''"home.example." transparent'' ];
      local-data = [
        ''"nas.home.example. A ${net.nas.ip}"''
        ''"cloud.home.example. A ${net.nas.ip}"''
        ''"gw-home.home.example. A ${net.lan.router}"''
      ];
      local-data-ptr = [
        ''"${net.nas.ip} nas.home.example"''
        ''"${net.lan.router} gw-home.home.example"''
      ];
    };
  };
}
