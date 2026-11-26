#!/usr/bin/env bash
# A change to the guard's core pack (bpf/guard: programs, headers, default
# rules) must bump bpf/guard/VERSION, or routers would never install the
# changed pack: they take a signed pack only when it is newer than theirs.
# README.md and the host-side tests are not part of the pack.
#
#   check-guard-pack-version.sh <base ref>   (e.g. origin/main)
set -euo pipefail
base=$(git merge-base "${1:?base ref}" HEAD)
changed=$(git diff --name-only "$base" HEAD -- bpf/guard \
  | grep -v -E '^bpf/guard/(README\.md|VERSION|live_test\.py|.*_test\.c)$' || true)
if [ -z "$changed" ]; then
  echo "bpf/guard: no pack changes"
  exit 0
fi
old=$(git show "$base:bpf/guard/VERSION" 2>/dev/null || echo 0.0.0)
new=$(cat bpf/guard/VERSION)
echo "pack files changed:"
while read -r f; do echo "  $f"; done <<<"$changed"
echo "VERSION: $old -> $new"
if [ "$old" = "$new" ] || [ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -n1)" != "$new" ]; then
  echo "::error file=bpf/guard/VERSION::bpf/guard changed but VERSION was not raised (still $old)"
  exit 1
fi
