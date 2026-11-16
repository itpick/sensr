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

  outputs = { self, nixpkgs, rust-overlay, crane, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
        in f { inherit pkgs toolchain craneLib; });
    in {
      packages = forAll ({ craneLib, ... }: {
        default = craneLib.buildPackage {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
        };
      });

      devShells = forAll ({ pkgs, toolchain, ... }: {
        default = pkgs.mkShell {
          packages = [ toolchain ] ++ (with pkgs; [
            cargo-deny cargo-audit cargo-nextest cargo-outdated cargo-leptos binaryen
            nftables qemu zstd
          ]);
        };
      });

      # NixOS modules, images (x86_64 ISO, Pi 4/5, qcow2) and nixosTest suites
      # land in nix/ per docs/PLAN.md phase 0.
    };
}
