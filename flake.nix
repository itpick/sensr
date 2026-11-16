{
  description = "sensr: a Rust firewall/router OS on NixOS";

  inputs = {
    # Unstable until NixOS 26.11 branches, then the release branch (docs/research/06 §2.1).
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      linuxSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };
      forAll = f: lib.genAttrs systems (system: f (pkgsFor system));
      forLinux = f: lib.genAttrs linuxSystems (system: f (pkgsFor system));

      gitRev = self.rev or self.dirtyRev or "unknown";

      # Every sensr system: the module, the overlay, and the build metadata
      # that goes into /etc/sensr/version.json.
      sensrModules = [
        self.nixosModules.default
        { services.sensr.build.gitRev = gitRev; }
      ];

      # In nixosTests pkgs is fixed (and already has the overlay), so tests
      # take the module without the nixpkgs.overlays line.
      testModules = [
        self.nixosModules.sensr
        { services.sensr.build.gitRev = gitRev; }
      ];

      mkSystem =
        system: modules:
        lib.nixosSystem {
          inherit system;
          modules = sensrModules ++ modules;
        };
    in
    {
      overlays.default = lib.composeManyExtensions [
        rust-overlay.overlays.default
        (import ./nix/overlays {
          inherit crane;
          src = ./.;
        })
      ];

      # nixosModules.sensr is the bare module (pkgs must carry pkgs.sensr);
      # nixosModules.default adds the overlay that provides it.
      nixosModules.sensr = ./nix/modules/sensr.nix;
      nixosModules.default = {
        imports = [ self.nixosModules.sensr ];
        nixpkgs.overlays = [ self.overlays.default ];
      };

      nixosConfigurations = {
        qcow = mkSystem "x86_64-linux" [ ./nix/images/qcow.nix ];
        qcow-aarch64 = mkSystem "aarch64-linux" [ ./nix/images/qcow.nix ];
      };

      # nix build .#images.qcow (docs/PLAN.md §6)
      images = {
        qcow = self.nixosConfigurations.qcow.config.system.build.image;
        qcow-aarch64 = self.nixosConfigurations.qcow-aarch64.config.system.build.image;
      };

      packages = forAll (pkgs: {
        default = pkgs.sensr;
        sensr = pkgs.sensr;
      });

      checks = forLinux (
        pkgs:
        {
          sensr = pkgs.sensr;
        }
        // lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
          boot-first-run = import ./nix/tests/boot-first-run.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          qcow-boot = import ./nix/tests/qcow-boot.nix {
            inherit pkgs;
            image = self.images.qcow;
          };
        }
      );

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages =
            [ (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml) ]
            ++ (with pkgs; [
              cargo-deny
              cargo-audit
              cargo-nextest
              cargo-outdated
              cargo-leptos
              binaryen
              qemu
              zstd
            ])
            ++ lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.nftables;
        };
      });

      formatter = forAll (pkgs: pkgs.nixfmt);
    };
}
