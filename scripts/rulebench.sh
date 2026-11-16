#!/usr/bin/env bash
# Render + apply benchmark for sensr-rules (07-performance-evaluation shape).
#
#   scripts/rulebench.sh <rulebench-binary> [out-dir]
#
# For 50 / 1,000 / 10,000 user rules: the example's normalise + render times
# and peak RSS, then `nft -j -f` of the result into a fresh unprivileged
# network namespace (median of 5), with nft, ip and GNU time on PATH.
set -euo pipefail
bin=$1
out=${2:-rulebench-out}
mkdir -p "$out"
for spec in "50:36:200" "1000:950:10000" "10000:9950:10000"; do
  IFS=: read -r label extra block <<<"$spec"
  json="$out/rules-$label.json"
  "$bin" "$extra" "$block" 5 "$json" "$out/update-$label.json" >"$out/render-$label.jsonl" 2>"$out/update-render-$label.json"
  render=$(sort -t, -k5 "$out/render-$label.jsonl" | sed -n 3p)
  apply_ms=$(unshare -rn bash -c '
    ip link add wan0 type dummy; ip link add lan0 type dummy
    for i in 1 2 3 4 5; do
      s=$(date +%s%N); nft -j -f "$0"; e=$(date +%s%N); echo $(( (e - s) / 1000 ))
    done' "$json" | sort -n | sed -n 3p)
  # alias refresh: replace the blocklist set in place (median of 5)
  update_us=$(unshare -rn bash -c '
    ip link add wan0 type dummy; ip link add lan0 type dummy
    nft -j -f "$0"
    for i in 1 2 3 4 5; do
      s=$(date +%s%N); nft -j -f "$1"; e=$(date +%s%N); echo $(( (e - s) / 1000 ))
    done' "$json" "$out/update-$label.json" | sort -n | sed -n 3p)
  echo "{\"rules\":$label,\"apply_us\":$apply_ms,\"set_update_us\":$update_us,\"set_update_render\":$(cat "$out/update-render-$label.json"),\"render\":$render}"
done
