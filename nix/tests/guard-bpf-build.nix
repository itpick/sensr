# checks.<system>.guard-bpf-build: the core pack builds, its one linked
# object carries every expected program section and exactly one copy of each
# map (so the programs share them), the manifest and default rules are
# valid JSON, and the never-block list behaves (a host C test of the same
# neverblock.h the programs include).
#
# The object is only inspected, never loaded: there is no kernel in the
# build sandbox (so no `bpftool prog loadall`, and bpftool is not even an
# input here). Loading and attaching is the loader's VM test
# (nix/tests/guard-load.nix).
{ pkgs, guardBpf ? pkgs.sensr-guard-bpf }:
let
  inherit (pkgs) lib;
  pack = "${guardBpf}/share/sensr-guard/packs/core";
  packVersion = lib.fileContents ../../bpf/guard/VERSION;
  # the sections (programs) the linked object must carry, by source
  sections = {
    exec = [
      "lsm.s/bprm_check_security"
      "lsm.s/bprm_committed_creds"
      "lsm/task_alloc"
      "iter/task"
    ];
    connect = [ "lsm/socket_connect" ];
    listen = [ "lsm/socket_bind" "lsm/socket_listen" ];
    file = [ "lsm.s/file_open" "lsm.s/path_unlink" "lsm.s/path_rename" ];
    creds = [ "lsm/task_fix_setuid" ];
    module = [ "lsm.s/kernel_read_file" "lsm/kernel_load_data" ];
    bpf = [ "lsm/bpf" ];
  };
  allSections = lib.concatLists (lib.attrValues sections) ++ [ ".maps" "license" ".BTF" ];
  # the contract's maps (bpf/guard/README.md) plus the internal scratch maps
  maps = [
    "rules_meta" "exe_prefix_lpm" "path_prefix_lpm" "net4_lpm" "net6_lpm"
    "port_rules" "unit_rules" "uid_rules" "hits" "config" "events"
    "ringbuf_dropped" "task_exe" "scratch" "seed_buf"
  ];
in
pkgs.runCommand "guard-bpf-build"
  {
    nativeBuildInputs = [
      pkgs.llvmPackages_19.llvm # llvm-objdump
      pkgs.jq
      pkgs.stdenv.cc
    ];
  }
  ''
    set -euo pipefail

    # the never-block list (bpf/guard/neverblock.h), on the host
    cc -std=c11 -Wall -Wextra -Werror -I${guardBpf.src} \
      -o neverblock_test ${guardBpf.src}/neverblock_test.c
    ./neverblock_test

    # one object: core.bpf.o
    o=${pack}/${guardBpf.object}
    [ -f "$o" ] || { echo "missing $o"; exit 1; }
    n=$(ls ${pack}/*.bpf.o | wc -l)
    [ "$n" -eq 1 ] || { echo "expected 1 object, found $n"; ls ${pack}; exit 1; }

    # every expected section (exact name: the section column of -h)
    llvm-objdump -h "$o" > sections
    for s in ${lib.concatStringsSep " " allSections}; do
      if ! awk -v s="$s" '$2 == s { found = 1 } END { exit !found }' sections; then
        echo "${guardBpf.object}: no section $s"; cat sections; exit 1
      fi
    done
    echo "${guardBpf.object}: ${lib.concatStringsSep " " allSections}"

    # each map exactly once, in .maps: the programs share it
    llvm-objdump -t "$o" > symbols
    for m in ${lib.concatStringsSep " " maps}; do
      c=$(awk -v m="$m" '$NF == m && /[[:space:]]\.maps[[:space:]]/ { c++ } END { print c + 0 }' symbols)
      [ "$c" -eq 1 ] || { echo "map $m: $c definitions in .maps"; grep -w "$m" symbols; exit 1; }
    done
    echo "maps shared: ${lib.concatStringsSep " " maps}"

    # a 24-byte BTF header (the derivation's note on aya)
    llvm-objcopy --dump-section .BTF=btf "$o" copy.o
    hdr_len=$(od -A n -t u4 -j 4 -N 4 btf | tr -d ' ')
    [ "$hdr_len" = 24 ] || { echo "BTF hdr_len $hdr_len, want 24"; exit 1; }

    # the manifest names exactly that object
    # its version is bpf/guard/VERSION
    jq -e '.name == "core" and .min_sensr == "0.0.0" and .version == "${packVersion}"' \
      ${pack}/manifest.json
    jq -e '.programs == ["${guardBpf.object}"]' ${pack}/manifest.json

    # the default rules: alert everywhere except the shipped-disabled block
    jq -e 'type == "array" and length > 0
      and all(.[]; (.id | startswith("core-")) and (.hook | type == "string"))
      and all(.[]; .action == "alert" or (.id == "core-bpf-block-others" and .enabled == false))' \
      ${pack}/rules.json

    mkdir -p $out
    cp ${pack}/manifest.json $out/
  ''
