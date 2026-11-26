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
        pi4 = mkSystem "aarch64-linux" [ ./nix/images/pi4.nix ];
        pi5 = mkSystem "aarch64-linux" [ ./nix/images/pi5.nix ];
        iso = mkSystem "x86_64-linux" [ ./nix/images/iso.nix ];
      };

      # nix build .#images.qcow (docs/PLAN.md §6)
      images = {
        qcow = self.nixosConfigurations.qcow.config.system.build.image;
        qcow-aarch64 = self.nixosConfigurations.qcow-aarch64.config.system.build.image;
        # Raspberry Pi 4 SD/USB image (aarch64-linux)
        pi4 = self.nixosConfigurations.pi4.config.system.build.sdImage;
        # Raspberry Pi 5 SD/USB/NVMe image (aarch64-linux; boot-tested with
        # nix/tests/pi5-qemu.sh)
        pi5 = self.nixosConfigurations.pi5.config.system.build.sdImage;
        # x86_64 live installer USB image (UEFI, BIOS via the ISO's GRUB)
        iso = self.nixosConfigurations.iso.config.system.build.isoImage;
      };

      # Boot-time benchmark images (nix/bench/boot-times.py): the qcow
      # router with the factory config or home-router.xml seeded, and the
      # endpoints.
      bench.x86_64-linux = {
        router-factory = (mkSystem "x86_64-linux" [ (import ./nix/bench/router.nix { variant = "factory"; }) ]).config.system.build.image;
        router-home = (mkSystem "x86_64-linux" [ (import ./nix/bench/router.nix { variant = "home"; }) ]).config.system.build.image;
        endpoint = (lib.nixosSystem { system = "x86_64-linux"; modules = [ ./nix/bench/endpoint.nix ]; }).config.system.build.image;
      };

      # Dashboard screenshots from the house test, with example devices on
      # the LAN (.github/workflows/vm-screenshots.yml; $out/screenshots).
      # Not a check, so `nix flake check` does not run it.
      screenshots.x86_64-linux.house = import ./nix/tests/house.nix {
        pkgs = pkgsFor "x86_64-linux";
        sensrModules = testModules;
        screenshots = true;
      };

      packages = forAll (
        pkgs:
        {
          default = pkgs.sensr;
          sensr = pkgs.sensr;
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          sensr-guard-bpf = pkgs.sensr-guard-bpf;
        }
      );

      checks = forLinux (
        pkgs:
        {
          sensr = pkgs.sensr;
          # The runtime guard's core pack: objects, sections, never-block
          # list (both arches; aarch64 runs in CI's nix-aarch64 job).
          guard-bpf-build = import ./nix/tests/guard-bpf-build.nix { inherit pkgs; };
        }
        // lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
          boot-first-run = import ./nix/tests/boot-first-run.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          # The routing vertical slice: against sensr, and against the
          # hand-written oracle of the same config (proves the assertions).
          slice = import ./nix/tests/slice.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          slice-reference = import ./nix/tests/slice.nix {
            inherit pkgs;
            sensrModules = testModules;
            mode = "reference";
          };
          insight = import ./nix/tests/insight.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          portscan = import ./nix/tests/portscan.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          ids = import ./nix/tests/ids.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          # The house acceptance scorecard (synthetic defaults; private runs
          # go through nix/tests/house/run.sh).
          house = import ./nix/tests/house.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          # The runtime guard's loader on a BPF-LSM kernel (the same checks
          # run by hand on aarch64 with nix/tests/guard-load.sh).
          guard-load = import ./nix/tests/guard-load.nix { inherit pkgs; };
          # The runtime guard end to end on the router: alerts, blocks held
          # for confirm, never-block, kill switch, refused pack, restart.
          guard = import ./nix/tests/guard.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          agent-api = import ./nix/tests/agent-api.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          ifnames = import ./nix/tests/ifnames.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          # the seed on a by-label FAT mount, as on a Pi: no boot may wait
          # for it before udev's coldplug
          ifnames-fat = import ./nix/tests/ifnames-fat.nix {
            inherit pkgs;
            sensrModules = testModules;
          };
          pi5-trial-install = import ./nix/tests/pi5-trial-install.nix {
            inherit pkgs;
            trialInstall = pkgs.writeShellApplication {
              name = "sensr-pi5-trial-install";
              runtimeInputs = with pkgs; [
                coreutils
                util-linux
                gnused
                gnugrep
                findutils
                zstd
                xz
                parted
                systemd
                e2fsprogs
              ];
              text = builtins.readFile ./nix/pi5/trial-install.sh;
            };
            trialHealth = pkgs.writeShellApplication {
              name = "sensr-trial-health";
              runtimeInputs = with pkgs; [
                coreutils
                gnugrep
                gnused
                iproute2
                dig
                curl
                inetutils
                util-linux
                systemd
              ];
              bashOptions = [ ];
              text =
                builtins.replaceStrings [ "@seedDir@" ] [ "/tmp/seed" ]
                  (builtins.readFile ./nix/pi5/trial-health.sh);
            };
          };
          # every way a trial boot can end, ending back on the previous OS
          trial-revert = import ./nix/tests/trial-revert.nix {
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
