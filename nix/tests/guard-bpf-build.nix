# checks.<system>.guard-bpf-build: the core pack builds, every object is
# there with the expected LSM sections, the manifest and default rules are
# valid JSON, and the never-block list behaves (a host C test of the same
# neverblock.h the programs include).
#
# The objects are only inspected, never loaded: there is no kernel in the
# build sandbox (so no `bpftool prog loadall`, and bpftool is not even an
# input here). Loading and attaching is the loader's VM test.
{ pkgs, guardBpf ? pkgs.sensr-guard-bpf }:
let
  pack = "${guardBpf}/share/sensr-guard/packs/core";
  # object -> the section (program) names it must carry
  sections = {
    exec = [ "lsm.s/bprm_check_security" "lsm/task_alloc" ];
    connect = [ "lsm/socket_connect" ];
    listen = [ "lsm/socket_bind" "lsm/socket_listen" ];
    file = [ "lsm.s/file_open" "lsm.s/path_unlink" "lsm.s/path_rename" ];
    creds = [ "lsm/task_fix_setuid" ];
    module = [ "lsm.s/kernel_read_file" "lsm/kernel_load_data" ];
    bpf = [ "lsm/bpf" ];
  };
  checkObject =
    obj: secs:
    ''
      o=${pack}/${obj}.bpf.o
      [ -f "$o" ] || { echo "missing $o"; exit 1; }
      llvm-objdump -h "$o" > ${obj}.sections
      for s in ${pkgs.lib.concatStringsSep " " secs} .maps license .BTF; do
        # exact name: the section column of `llvm-objdump -h`
        if ! awk -v s="$s" '$2 == s { found = 1 } END { exit !found }' ${obj}.sections; then
          echo "${obj}.bpf.o: no section $s"; cat ${obj}.sections; exit 1
        fi
      done
      echo "${obj}.bpf.o: ${pkgs.lib.concatStringsSep " " secs}"
    '';
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

    # every object, with every expected section
    ${pkgs.lib.concatStrings (pkgs.lib.mapAttrsToList checkObject sections)}
    n=$(ls ${pack}/*.bpf.o | wc -l)
    [ "$n" -eq ${toString (builtins.length (builtins.attrNames sections))} ] \
      || { echo "expected ${toString (builtins.length (builtins.attrNames sections))} objects, found $n"; exit 1; }

    # the manifest names exactly those objects
    jq -e '.name == "core" and .min_sensr == "0.0.0" and (.version | type == "string")' \
      ${pack}/manifest.json
    jq -e --argjson want '${builtins.toJSON (map (o: "${o}.bpf.o") (builtins.attrNames sections))}' \
      '(.programs | sort) == ($want | sort)' ${pack}/manifest.json

    # the default rules: alert everywhere except the shipped-disabled block
    jq -e 'type == "array" and length > 0
      and all(.[]; (.id | startswith("core-")) and (.hook | type == "string"))
      and all(.[]; .action == "alert" or (.id == "core-bpf-block-others" and .enabled == false))' \
      ${pack}/rules.json

    mkdir -p $out
    cp ${pack}/manifest.json $out/
  ''
