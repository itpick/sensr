# pkgs.sensr-guard-bpf: the runtime guard's built-in `core` pack — the C BPF
# programs in bpf/guard compiled for this system's kernel, plus the pack
# manifest and default rules:
#
#   $out/share/sensr-guard/packs/core/{manifest.json,rules.json,core.bpf.o}
#
# Each program group is compiled on its own and then linked into the one
# object core.bpf.o (`bpftool gen object`), so every program shares one
# instance of each map (task_exe, hits, the ring buffer, ...). The maps are
# weak in common.h, which lets the linker merge the identical definitions.
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

  # One source per program group; the section names inside are the hooks.
  # They are linked into `object`, the pack's only object.
  object = "core.bpf.o";
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
    programs = [ object ];
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
    inherit kernel programs object targetArch;
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
    bpftool gen object ${object} ${lib.concatMapStringsSep " " (p: "${p}.bpf.o") programs}

    # libbpf >= 1.8 writes the linked .BTF with a 32-byte header (the new,
    # here empty, layout section). aya 0.16 keeps hdr_len = 32 but writes a
    # 24-byte header when it loads the BTF, so the kernel reads the first
    # type as the layout and refuses the BTF ("Section overlap found").
    # With no layout data the 24-byte header means the same: drop the two
    # empty fields. type_off and str_off count from the header's end, so
    # they stay. checks.guard-bpf-build asserts hdr_len = 24.
    #
    # Upstream (aya-rs/aya; no issue found as of 2026-11-25, to be filed):
    # aya-obj 0.6.0 src/btf/btf.rs: `Btf::parse` honours `hdr_len` when it
    # locates the types and strings, but `Btf::to_bytes` serialises only
    # `size_of::<btf_header>()` (24) bytes of header, copied from the parsed
    # header, so hdr_len stays 32. The output has 8 fewer header bytes than
    # it claims, and BPF_BTF_LOAD fails with EINVAL. Fix there: write
    # hdr_len = 24 when the extra header fields are zero, or keep the
    # original header bytes. Once fixed, this step can go.
    #
    # od -t u4 reads host-order words. The BTF is the BPF target's byte
    # order, and the host is that target (x86_64 or aarch64, both little
    # endian; common.h refuses big-endian BPF targets), so they agree.
    llvm-objcopy --dump-section .BTF=btf ${object} copy.o
    hdr_len=$(od -A n -t u4 -j 4 -N 4 btf | tr -d ' ')
    if [ "$hdr_len" = 32 ]; then
      layout_len=$(od -A n -t u4 -j 28 -N 4 btf | tr -d ' ')
      [ "$layout_len" = 0 ] || { echo "BTF layout section not empty ($layout_len)"; exit 1; }
      { head -c 4 btf; printf '\x18\x00\x00\x00'; head -c 24 btf | tail -c 16; tail -c +33 btf; } > btf24
      llvm-objcopy --update-section .BTF=btf24 ${object}
    elif [ "$hdr_len" != 24 ]; then
      echo "unexpected BTF hdr_len $hdr_len"; exit 1
    fi
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    dir=$out/share/sensr-guard/packs/core
    mkdir -p $dir
    cp ${object} $dir/
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
