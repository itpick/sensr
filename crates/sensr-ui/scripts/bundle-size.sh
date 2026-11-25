#!/usr/bin/env bash
# Fails if the island bundle (wasm + JS glue, brotli -q 11) exceeds the budget in
# docs/PLAN.md §4 (< 400 KB, raised to 440 KB below). Run after `cargo leptos build --release`
# from the workspace root.
# Prints a Markdown table so CI can append it to the job summary.
set -euo pipefail

pkg="${1:-target/site/pkg}"
# 430: global search (2026-11-23)
# 440: port scanner (2026-11-25): the Hosts card's ports line and Scan now, and the
#      Port Scanner settings form and never-scanned grid in the form and grid islands
budget_kb="${SENSR_UI_BUNDLE_BUDGET_KB:-440}"

br() { brotli -q 11 -c "$1" | wc -c | tr -d ' '; }
gz() { gzip -9 -c "$1" | wc -c | tr -d ' '; }
raw() { wc -c <"$1" | tr -d ' '; }

total=0
echo "| file | raw | gzip | brotli |"
echo "|---|---:|---:|---:|"
for f in "$pkg/sensr-ui.wasm" "$pkg/sensr-ui.js" "$pkg/sensr-ui.css"; do
  [ -f "$f" ] || { echo "missing $f (run cargo leptos build --release)" >&2; exit 2; }
  b=$(br "$f")
  case "$f" in *.wasm|*.js) total=$((total + b)) ;; esac
  printf "| %s | %d KB | %d KB | %d KB |\n" "$(basename "$f")" $(( $(raw "$f") / 1024 )) $(( $(gz "$f") / 1024 )) $((b / 1024))
done
echo
echo "Island bundle (wasm + js, brotli): $((total / 1024)) KB of ${budget_kb} KB budget"
if [ $((total / 1024)) -ge "$budget_kb" ]; then
  echo "::error::sensr-ui island bundle is $((total / 1024)) KB brotli, budget ${budget_kb} KB" >&2
  exit 1
fi
