{
  description = "sensr benchmark VMs: NixOS minimal router (nftables) and iperf3 endpoints";

  # pinned to the nixtop system revision (NixOS 26.11.20261008.e7439b6)
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/e7439b6b14ad3cc35d05608ebca9bce01a25f5f8";

  outputs = { self, nixpkgs }:
    let
      mk = system: modules: nixpkgs.lib.nixosSystem { inherit system; modules = modules; };
      # aarch64 (Pi track, no native builder): same source, cross-compiled static musl binary
      protoPrebuilt = pkgs: pkgs.runCommand "sensr-proto-0.1.0" { } ''
        install -Dm755 ${./prototype/prebuilt/sensr-proto-aarch64} $out/bin/sensr-proto
      '';
      protoFor = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "sensr-proto";
        version = "0.1.0";
        src = ./prototype;
        cargoLock.lockFile = ./prototype/Cargo.lock;
        doCheck = false;
      };
    in {
      nixosConfigurations = {
        router = mk "x86_64-linux" [ ./nix/common.nix ./nix/router.nix { _module.args.protoFor = protoFor; } ];
        endpoint = mk "x86_64-linux" [ ./nix/common.nix ./nix/endpoint.nix ];
        router-aarch64 = mk "aarch64-linux" [ ./nix/common.nix ./nix/router.nix ./nix/aarch64.nix { _module.args.protoFor = protoPrebuilt; } ];
      };
      packages.x86_64-linux = {
        router = self.nixosConfigurations.router.config.system.build.qcow2;
        endpoint = self.nixosConfigurations.endpoint.config.system.build.qcow2;
        proto = protoFor nixpkgs.legacyPackages.x86_64-linux;
      };
      packages.aarch64-linux.router = self.nixosConfigurations.router-aarch64.config.system.build.qcow2;
    };
}
