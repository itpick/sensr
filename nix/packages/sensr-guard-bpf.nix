# pkgs.sensr-guard-bpf: the runtime guard's built-in `core` pack — the C BPF
# programs in bpf/guard compiled for this system's kernel, plus the pack
# manifest and default rules:
#
#   $out/share/sensr-guard/packs/core/{manifest.json,rules.json,*.bpf.o}
#
# vmlinux.h comes from the BTF of the kernel the images boot (pi4/pi5 use
# linuxPackages_latest), so the programs see that kernel's types; they are
# CO-RE, so field offsets are relocated again at load time anyway.
#
# Nothing here loads the programs: the build sandbox has no kernel to load
# them into. Loading and attaching is tested in a VM (sensr-guard's loader).
{
  lib,
  stdenvNoCC,
  llvmPackages_19,
  libbpf,
  bpftools,
  linuxPackages_latest,
  kernel ? linuxPackages_latest.kernel,
  # The pack version (sensr's version).
  version ? "0.0.0",
  # bpf/guard
  src,
}:
let
  # The unwrapped clang: the cc-wrapper adds host flags (hardening,
  # -march, ...) that break `-target bpf`.
  clang = llvmPackages_19.clang-unwrapped;
  targetArch =
    if stdenvNoCC.hostPlatform.isx86_64 then
      "x86"
    else if stdenvNoCC.hostPlatform.isAarch64 then
      "arm64"
    else
      throw "sensr-guard-bpf: no BPF target arch for ${stdenvNoCC.hostPlatform.system}";

  # One object per program group; the section names inside are the hooks.
  programs = [
    "exec"
    "connect"
    "listen"
    "file"
    "creds"
    "module"
    "bpf"
  ];

  manifest = builtins.toJSON {
    name = "core";
    inherit version;
    min_sensr = "0.0.0";
    programs = map (p: "${p}.bpf.o") programs;
    rules = "rules.json";
  };
in
stdenvNoCC.mkDerivation {
  pname = "sensr-guard-bpf";
  inherit version src;

  nativeBuildInputs = [
    clang
    llvmPackages_19.llvm # llvm-strip
    bpftools
  ];

  # BPF objects are not host binaries: no stripping, no patching.
  dontStrip = true;
  dontPatchELF = true;
  dontFixup = true;

  passthru = {
    inherit kernel programs targetArch;
  };

  buildPhase = ''
    runHook preBuild
    vmlinux=${kernel.dev}/vmlinux
    if [ ! -f "$vmlinux" ]; then
      vmlinux=$(find ${kernel.dev} -name vmlinux -type f | head -n1)
    fi
    echo "vmlinux.h from $vmlinux"
    bpftool btf dump file "$vmlinux" format c > vmlinux.h
    for p in ${lib.concatStringsSep " " programs}; do
      # -g emits BTF (needed for CO-RE); the DWARF is stripped below.
      clang -g -O2 -target bpf -D__TARGET_ARCH_${targetArch} \
        -Wall -Wno-missing-declarations \
        -I. -I${lib.getDev libbpf}/include \
        -c $p.bpf.c -o $p.bpf.o
      llvm-strip -g $p.bpf.o
    done
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    dir=$out/share/sensr-guard/packs/core
    mkdir -p $dir
    cp *.bpf.o $dir/
    cp rules.json $dir/rules.json
    echo ${lib.escapeShellArg manifest} > $dir/manifest.json
    runHook postInstall
  '';

  meta = {
    description = "sensr runtime guard: the core pack's BPF LSM programs";
    license = lib.licenses.gpl2Only;
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
