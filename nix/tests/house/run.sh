#!/usr/bin/env bash
# Run the house acceptance test against a private house, outside the build
# sandbox, so nothing private enters the nix store:
#
#   nix/tests/house/run.sh PARAMS.json SEED_DIR [OUT_DIR]
#
# PARAMS.json  the house parameters (format: nix/tests/house/example.json)
# SEED_DIR     what the router's seed folder gets: config.xml (an OPNsense
#              backup), and optionally ifnames, authorized_keys, seed.toml;
#              this script adds harness-ifnames when the parameters say the
#              harness names the NICs
# OUT_DIR      results and logs (default: ./house-out); house-results.json
#
# Environment: SENSR_HOUSE_REAL_INTERNET=1 gives the upstream a NAT to the
# real internet (recursion, real blocklists, IDS rule downloads);
# SENSR_HOUSE_STRICT=1 fails on any failed check. The VMs' disks live in a
# temporary directory under OUT_DIR (XDG_RUNTIME_DIR and TMPDIR point there)
# and are removed afterwards; delete OUT_DIR yourself when its results hold
# private data.
set -euo pipefail
here=$(cd "$(dirname "$0")/../../.." && pwd)
params=$(realpath "$1") seed=$(realpath "$2") out=$(realpath -m "${3:-./house-out}")
umask 077
mkdir -p "$out"
for t in jq nix; do command -v $t >/dev/null || { echo "needs $t" >&2; exit 1; }; done

# The seed share: the caller's files plus the NIC names, in a private copy.
share=$(mktemp -d "$out/seed.XXXXXX")
tmp=$(mktemp -d "$out/vm.XXXXXX")
trap 'rm -rf "$share" "$tmp"' EXIT
cp -r "$seed"/. "$share"/
if [ "$(jq -r '.router.harness_names_nics // true' "$params")" = true ]; then
  jq -r '.router | [.wan, .lan, .lan2][] | "\(.mac) \(.device)"' "$params" > "$share/harness-ifnames"
fi

driver=$(nix build --no-link --print-out-paths "path:$here#checks.x86_64-linux.house.driver")
export SENSR_HOUSE_PARAMS=$params SENSR_HOUSE_SEED=$share SENSR_HOUSE_RESULTS=$out/house-results.json
SENSR_HOUSE_MAC_WAN=$(jq -r .router.wan.mac "$params")
SENSR_HOUSE_MAC_LAN=$(jq -r .router.lan.mac "$params")
SENSR_HOUSE_MAC_LAN2=$(jq -r .router.lan2.mac "$params")
export SENSR_HOUSE_MAC_WAN SENSR_HOUSE_MAC_LAN SENSR_HOUSE_MAC_LAN2
cd "$tmp"
# The driver keeps VM disks in XDG_RUNTIME_DIR (else TMPDIR): keep them in
# $tmp, which the trap removes; the router's disk holds the seeded config.
PYTHONUNBUFFERED=1 XDG_RUNTIME_DIR=$tmp TMPDIR=$tmp "$driver/bin/nixos-test-driver" --output_directory "$out" 2>&1 | tee "$out/house.log"
