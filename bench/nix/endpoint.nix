# One image for both traffic endpoints; the role is picked by NIC MAC address.
{ pkgs, ... }:
{
  networking.hostName = "sensrbench-endpoint";
  systemd.network.networks = {
    "10-client" = {
      matchConfig.MACAddress = "52:54:00:5b:00:10";
      address = [ "192.168.1.100/24" ];
      routes = [ { Gateway = "192.168.1.1"; } ];
    };
    "10-server" = {
      matchConfig.MACAddress = "52:54:00:5b:00:20";
      address = [ "10.99.0.10/24" ];
      routes = [ { Gateway = "10.99.0.1"; } ];
    };
  };
  environment.systemPackages = with pkgs; [ iperf3 wrk iputils procps ];
  systemd.services.iperf3 = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig.ExecStart = "${pkgs.iperf3}/bin/iperf3 -s";
    serviceConfig.Restart = "always";
  };
  services.nginx = {
    enable = true;
    virtualHosts.default = {
      default = true;
      locations."/".return = "200 'ok'";
    };
  };
  boot.kernel.sysctl."net.ipv4.ip_local_port_range" = "10000 65000";
}
