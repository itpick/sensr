# pkgs.sensr: the whole Cargo workspace built with crane, one derivation that
# carries every binary (sensr-agent, sensr-api, sensr, sensr-insight,
# sensr-scan). The dependency-only derivation (cargoArtifacts) is cached
# separately, so a change to sensr's own code does not rebuild the crates.io
# graph.
#
# The toolchain is the one rust-toolchain.toml pins, so Nix and cargo always
# build with the same compiler. Needs rust-overlay's overlay applied first
# (flake.nix composes them).
{ crane, src }:
final: prev:
let
  inherit (final) lib;
  toolchainToml = builtins.fromTOML (builtins.readFile (src + "/rust-toolchain.toml"));
  channel = toolchainToml.toolchain.channel;
  # The minimal profile: rust-toolchain.toml also lists the wasm and aarch64
  # std targets for developers, which a native package build does not need.
  toolchain = final.rust-bin.stable.${channel}.minimal.override {
    extensions = [ "clippy" ];
    # sensr-ui's islands are a wasm bundle, built below with the same compiler.
    targets = [ "wasm32-unknown-unknown" ];
  };
  craneLib = (crane.mkLib final).overrideToolchain (_: toolchain);

  # Everything cargo can see: manifests, sources and test data under crates/.
  # docs/, nix/ and reference/ stay out, so editing them does not rebuild Rust.
  workspaceSrc = lib.fileset.toSource {
    root = src;
    fileset = lib.fileset.unions (
      [
        (src + "/Cargo.toml")
        (src + "/Cargo.lock")
        (src + "/crates")
      ]
      ++ lib.optional (builtins.pathExists (src + "/.cargo")) (src + "/.cargo")
      ++ lib.optional (builtins.pathExists (src + "/clippy.toml")) (src + "/clippy.toml")
    );
  };

  workspaceToml = builtins.fromTOML (builtins.readFile (src + "/Cargo.toml"));

  commonArgs = {
    src = workspaceSrc;
    pname = "sensr";
    version = workspaceToml.workspace.package.version;
    strictDeps = true;
    # xtask is developer tooling and never ships in an image. The daemons'
    # binaries need their crates' `daemon` features (the crates' default is
    # the light shared part the agent and apply link against; sensr-guard's
    # daemon is the aya loader, Linux only); in commonArgs so the
    # dependency-only build caches the daemons' crates too.
    cargoExtraArgs = "--locked --workspace --features sensr-scan/daemon"
      + lib.optionalString (builtins.pathExists (src + "/crates/xtask")) " --exclude xtask"
      + lib.optionalString final.stdenv.hostPlatform.isLinux " --features sensr-guard/daemon";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
{
  # Kea without what an appliance never runs: kea-shell (Python, 137 MiB of
  # closure), the message compiler and headers. The config report in
  # libkea-cfgrpt also names the build tools; those references go too.
  # Copied, not rebuilt: the result keeps the name kea-<version>, so its
  # store path has the same length and the old path can be rewritten in
  # place, binaries included.
  sensr-kea = final.runCommand "kea-${prev.kea.version}"
    {
      nativeBuildInputs = [ final.removeReferencesTo ];
      inherit (prev.kea) meta;
      passthru.version = prev.kea.version;
      disallowedReferences = [ prev.kea final.python3 ];
    }
    ''
      cp -a ${prev.kea}/. $out
      chmod -R u+w $out
      rm -rf $out/bin/kea-shell $out/bin/kea-msg-compiler $out/include
      find $out -type f -exec sed -i "s|${prev.kea}|$out|g" {} +
      find $out -type f -exec remove-references-to \
        -t ${final.python3} -t ${final.bison} -t ${final.flex} -t ${final.gnum4} {} +
    '';

  # The runtime guard's built-in core pack (BPF objects, manifest, default
  # rules), built against the kernel the images boot.
  sensr-guard-bpf = final.callPackage ../packages/sensr-guard-bpf.nix {
    src = src + "/bpf/guard";
    # The pack's own version (bpf/guard/VERSION, bumped with every change
    # to the programs or default rules; CI checks it): a router installs a
    # signed pack only when it is newer than what it runs.
    version = lib.fileContents (src + "/bpf/guard/VERSION");
    kernel = final.linuxPackages_latest.kernel;
  };

  # The public keys sensr-guard verifies signed packs against: every *.pub
  # in nix/pi5/guard-keys (none yet: only the built-in packs run).
  sensr-guard-keys = final.runCommand "sensr-guard-keys" { } ''
    mkdir -p $out/share/sensr-guard/keys
    for f in ${src + "/nix/pi5/guard-keys"}/*.pub; do
      if [ -f "$f" ]; then
        cp "$f" $out/share/sensr-guard/keys/
      fi
    done
  '';

  sensr = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      nativeBuildInputs = [ final.wasm-bindgen-cli ];
      # cargo test runs in CI's rust job (and in checks.cargo-test); some
      # tests drive nft and other daemons, which the package sandbox lacks.
      doCheck = false;
      # The CLI is `sensr` (docs/PLAN.md §2.1); until the sensr-cli crate
      # names its binary that, provide the name here so units and docs can
      # rely on it.
      postInstall = ''
        # the loader's test tool (nix/tests/guard-load.nix builds its own)
        rm -f $out/bin/guard-load-probe
        if [ ! -e $out/bin/sensr ] && [ -e $out/bin/sensr-cli ]; then
          ln -s sensr-cli $out/bin/sensr
        fi
        # services.sensr.api.uiRoot: `cargo leptos build` output, done here by
        # hand so the image does not need cargo-leptos in its build closure.
        # The wasm bundle is the islands' hydrate build; the CSS is the one
        # plain stylesheet cargo-leptos would install from style-file.
        mkdir -p $out/share/sensr/ui/pkg
        cp crates/sensr-ui/public/favicon.svg $out/share/sensr/ui/
        cp crates/sensr-ui/style/main.css $out/share/sensr/ui/pkg/sensr-ui.css
        cargo build --locked --release --target wasm32-unknown-unknown \
          -p sensr-ui --lib --no-default-features --features hydrate
        wasm-bindgen --target web --out-name sensr-ui \
          --out-dir $out/share/sensr/ui/pkg \
          target/wasm32-unknown-unknown/release/sensr_ui.wasm
      '';
      passthru = {
        inherit craneLib cargoArtifacts toolchain;
        src = workspaceSrc;
      };
      meta = {
        description = "sensr: a Rust firewall/router OS on NixOS";
        homepage = "https://github.com/itpick/sensr";
        license = with lib.licenses; [ mit asl20 ];
        mainProgram = "sensr";
      };
    }
  );
}
