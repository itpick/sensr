# The boot-time benchmark's endpoints, one image, the role picked by MAC
# (like bench/nix/endpoint.nix):
#   52:54:00:5e:00:20  wanhost  11.0.0.1/24 on the router's WAN: DHCP server
#                      (the router's WAN lease) and the ping target
#   52:54:00:5e:00:10  client   192.168.1.100/24 on the router's LAN, gateway
#                      192.168.1.1; probes the router and prints
#                      "SENSRBENCH <milestone>" on its serial console the
#                      first time each succeeds
{ lib, pkgs, modulesPath, ... }:
let
  probe = pkgs.writeShellScript "sensrbench-probe" ''
    say() { echo "SENSRBENCH $1" > /dev/ttyS0; }
    # The harness passes the SSH key through QEMU's fw_cfg.
    key=/run/bench-key
    cp /sys/firmware/qemu_fw_cfg/by_name/opt/sensrbench/key/raw $key 2>/dev/null && chmod 600 $key
    say ready
    (until ${pkgs.iputils}/bin/ping -n -c1 -W1 11.0.0.1 >/dev/null 2>&1; do sleep 0.05; done; say fwd) &
    (until ${pkgs.openssh}/bin/ssh -i $key -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 root@192.168.1.1 true 2>/dev/null; do sleep 0.2; done; say ssh) &
    (until [ "$(${pkgs.curl}/bin/curl -s -o /dev/null -w '%{http_code}' --max-time 1 http://192.168.1.1:443/api/v1/session)" != 000 ]; do sleep 0.1; done; say api) &
    wait
  '';
in
{
  imports = [
    "${modulesPath}/profiles/minimal.nix"
    "${modulesPath}/profiles/qemu-guest.nix"
    "${modulesPath}/virtualisation/disk-image.nix"
  ];
  image.format = "qcow2";
  image.efiSupport = false;
  image.baseName = "sensr-bench-endpoint";
  system.stateVersion = "26.11";
  boot.kernelParams = [ "console=ttyS0,115200" ];
  boot.loader.timeout = 0;
  boot.kernelModules = [ "qemu_fw_cfg" ];
  networking.hostName = "sensrbench-endpoint";
  networking.useNetworkd = true;
  networking.useDHCP = false;
  networking.firewall.enable = false;
  documentation.enable = false;
  users.allowNoPasswordLogin = true;
  systemd.network.networks = {
    "10-client" = {
      matchConfig.MACAddress = "52:54:00:5e:00:10";
      address = [ "192.168.1.100/24" ];
      routes = [ { Gateway = "192.168.1.1"; } ];
    };
    "10-wanhost" = {
      matchConfig.MACAddress = "52:54:00:5e:00:20";
      address = [ "11.0.0.1/24" ];
      networkConfig.DHCPServer = true;
      dhcpServerConfig = {
        PoolOffset = 100;
        PoolSize = 100;
        EmitRouter = true;
        EmitDNS = false;
      };
    };
  };
  systemd.services.sensrbench-probe = {
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-networkd.service" ];
    serviceConfig.ExecStart = probe;
  };
}
