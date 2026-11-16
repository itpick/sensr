#!/usr/bin/env bash
# Syntax- and kernel-checks every nft JSON golden with `nft -c -j -f`.
#
# Usage: scripts/nft-check-goldens.sh [golden-dir]
#   NFT=/path/to/nft      nft binary (default: nft on PATH)
#   NFT_WRAP="sudo"       privilege wrapper; "unshare -rn" works unprivileged
#                         where user namespaces are allowed
set -euo pipefail
dir=${1:-crates/sensr-rules/tests/golden}
nft=${NFT:-nft}
read -r -a wrap <<<"${NFT_WRAP:-}"
fail=0
shopt -s nullglob
files=("$dir"/*.nft.json)
if [ ${#files[@]} -eq 0 ]; then
  echo "no goldens in $dir" >&2
  exit 1
fi
for f in "${files[@]}"; do
  if "${wrap[@]}" "$nft" -c -j -f "$f"; then
    echo "ok   $f"
  else
    echo "FAIL $f" >&2
    fail=1
  fi
done
exit $fail
