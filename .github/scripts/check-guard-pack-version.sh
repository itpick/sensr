#!/usr/bin/env bash
# A change to the guard's core pack (bpf/guard: programs, headers, default
# rules) must raise bpf/guard/VERSION (semver), or routers would never
# install the changed pack: they take a signed pack only when it is newer
# than theirs. README.md and the host-side tests are not part of the pack.
#
#   check-guard-pack-version.sh <base commit or ref>
#
# Pull requests pass the base branch (the merge base with it is compared);
# pushes pass the commit before the push.
set -euo pipefail
base_ref=${1:?base commit or ref}
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

new=$(tr -d '[:space:]' < bpf/guard/VERSION)
if ! [[ $new =~ $semver ]]; then
  echo "::error file=bpf/guard/VERSION::'$new' is not a semver version (MAJOR.MINOR.PATCH)"
  exit 1
fi
read -r n1 n2 n3 <<<"${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"

# a new branch (no previous commit): nothing to compare
if [[ $base_ref =~ ^0+$ ]] || ! git rev-parse -q --verify "$base_ref^{commit}" >/dev/null; then
  echo "no base commit to compare with; VERSION $new is valid"
  exit 0
fi
base=$(git merge-base "$base_ref" HEAD)
changed=$(git diff --name-only "$base" HEAD -- bpf/guard \
  | grep -v -E '^bpf/guard/(README\.md|VERSION|live_test\.py|.*_test\.c)$' || true)
if [ -z "$changed" ]; then
  echo "bpf/guard: no pack changes (VERSION $new)"
  exit 0
fi
old=$(git show "$base:bpf/guard/VERSION" 2>/dev/null | tr -d '[:space:]' || true)
old=${old:-0.0.0}
if ! [[ $old =~ $semver ]]; then
  echo "the base VERSION '$old' is not semver; any valid VERSION is accepted"
  exit 0
fi
read -r o1 o2 o3 <<<"${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"
echo "pack files changed:"
while read -r f; do echo "  $f"; done <<<"$changed"
echo "VERSION: $old -> $new"
newer=false
if ((n1 != o1)); then ((n1 > o1)) && newer=true
elif ((n2 != o2)); then ((n2 > o2)) && newer=true
elif ((n3 > o3)); then newer=true
fi
if [ "$newer" != true ]; then
  echo "::error file=bpf/guard/VERSION::bpf/guard changed but VERSION was not raised ($old -> $new)"
  exit 1
fi
