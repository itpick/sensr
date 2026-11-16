# NixOS minimal router: nftables (same generated policy as the other routers),
# masquerade, unbound + kea on LAN (OPNsense ships unbound + a DHCP server),
# and the Rust prototype as the "management API" stand-in.
{ config, lib, pkgs, protoFor, ... }:
let
  proto = protoFor pkgs;
  gen = ../generated;
in
{
  networking.hostName = "sensrbench-nixr";
  systemd.network.links = {
    "10-lan0" = { matchConfig.MACAddress = "52:54:00:5b:01:01"; linkConfig.Name = "lan0"; };
    "10-wan0" = { matchConfig.MACAddress = "52:54:00:5b:01:02"; linkConfig.Name = "wan0"; };
  };
  systemd.network.networks = {
    "20-lan0" = { matchConfig.Name = "lan0"; address = [ "192.168.1.1/24" ]; };
    "20-wan0" = {
      matchConfig.Name = "wan0";
      address = [ "10.99.0.1/24" ];
      routes = [ { Gateway = "10.99.0.254"; } ];
    };
  };
  boot.kernel.sysctl."net.ipv4.ip_forward" = 1;

  networking.nftables = {
    enable = true;
    checkRuleset = false; # interface names only exist at runtime
    rulesetFile = "${gen}/nft/small.nft";
  };

  services.unbound = {
    enable = true;
    settings.server = {
      interface = [ "127.0.0.1" "192.168.1.1" ];
      access-control = [ "192.168.1.0/24 allow" ];
    };
  };
  services.kea.dhcp4 = {
    enable = true;
    settings = {
      interfaces-config.interfaces = [ "lan0" ];
      lease-database = { type = "memfile"; persist = true; name = "/var/lib/kea/dhcp4.leases"; };
      subnet4 = [ {
        id = 1;
        subnet = "192.168.1.0/24";
        pools = [ { pool = "192.168.1.150 - 192.168.1.199"; } ];
        option-data = [ { name = "routers"; data = "192.168.1.1"; } { name = "domain-name-servers"; data = "192.168.1.1"; } ];
      } ];
    };
  };

  environment.etc."sensrbench".source = gen;
  environment.systemPackages = [ proto pkgs.nftables pkgs.iputils pkgs.procps pkgs.ethtool ];
  systemd.services.sensr-proto = {
    description = "sensr control-plane prototype (benchmark stand-in)";
    wantedBy = [ "multi-user.target" ];
    after = [ "nftables.service" ];
    path = [ pkgs.nftables ];
    serviceConfig.ExecStart = "${proto}/bin/sensr-proto serve --policy /etc/sensrbench/opn/small.json --port 8080";
    serviceConfig.Restart = "always";
  };
}
