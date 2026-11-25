# checks.x86_64-linux.guard-load: sensr-guard's loader (aya) loads the core
# pack on a real BPF-LSM kernel, attaches every program and applies compiled
# rules. The assertions are nix/tests/guard-load.sh, which also runs by hand
# on other kernels (aarch64 included); it drives guard-load-probe:
#
#   - every program reports attached, and bpftool lists them;
#   - a block rule on 192.0.2.1/32 port 80: curl to it fails with EPERM,
#     curl to the server works, the hit and the event are counted;
#   - the rule moving to another slot keeps its hits by rule id;
#   - with the kill switch on, the same curl goes through (still reported);
#   - when the probe exits (dropping Loaded), no guard program is left.
#
#   guard   the loader, with the BPF LSM (the pack's kernel)
#   server  HTTP on its own address and on 192.0.2.1
{ pkgs }:
let
  pack = "${pkgs.sensr-guard-bpf}/share/sensr-guard/packs/core";
  # The probe: sensr-guard with the daemon feature (pkgs.sensr builds the
  # workspace without it).
  probe = pkgs.sensr.passthru.craneLib.buildPackage {
    pname = "guard-load-probe";
    inherit (pkgs.sensr) version;
    src = pkgs.sensr.passthru.src;
    strictDeps = true;
    cargoExtraArgs = "--locked -p sensr-guard --features daemon --bin guard-load-probe";
    doCheck = false;
  };
  blocked = "192.0.2.1";
in
pkgs.testers.runNixOSTest {
  name = "sensr-guard-load";

  nodes = {
    server =
      { ... }:
      {
        # one kernel for both nodes (less to build)
        boot.kernelPackages = pkgs.linuxPackages_latest;
        networking.firewall.enable = false;
        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = blocked;
            prefixLength = 32;
          }
        ];
        systemd.services.http = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          serviceConfig = {
            ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80 --bind 0.0.0.0";
            WorkingDirectory = "/var/empty";
          };
        };
      };

    guard =
      { nodes, ... }:
      {
        # The kernel the pack's vmlinux.h comes from (the images' kernel).
        boot.kernelPackages = pkgs.linuxPackages_latest;
        # NixOS puts bpf in security.lsm (lsm=) by default; the test
        # script checks that it is active.
        virtualisation.memorySize = 1024;
        networking.firewall.enable = false;
        networking.interfaces.eth1.ipv4.routes = [
          {
            address = blocked;
            prefixLength = 32;
            via = nodes.server.networking.primaryIPAddress;
          }
        ];
        environment.systemPackages = [
          probe
          pkgs.bpftools
          pkgs.curl
        ];
      };
  };

  testScript = ''
    start_all()
    server.wait_for_unit("http.service")
    server.wait_for_open_port(80)
    guard.wait_for_unit("multi-user.target")

    lsm = guard.succeed("cat /sys/kernel/security/lsm")
    assert "bpf" in lsm.split(","), f"BPF LSM not active: {lsm}"
    print(guard.succeed("uname -r"))

    print(guard.succeed(
        "bash ${./guard-load.sh} ${probe}/bin/guard-load-probe ${pack} http://server/ 12"
    ))
  '';
}
