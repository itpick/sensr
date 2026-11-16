#!/usr/bin/env bash
# Fetch the OPNsense sources sensr is rewritten from into reference/opnsense/.
# They are read-only reference: we reimplement behaviour, we never copy code into crates/.
#   scripts/fetch-reference.sh          clone or update, then check out the commits pinned in reference/REFS
#   scripts/fetch-reference.sh --latest update to each repo's latest default-branch commit and rewrite REFS
#   scripts/fetch-reference.sh --issues also re-download all opnsense/core and opnsense/plugins issues (needs gh)
set -euo pipefail
cd "$(dirname "$0")/.."
REPOS="core plugins docs tools changelog update ports"
DEST=reference/opnsense
REFS=reference/REFS
latest=0 issues=0
for a in "$@"; do case $a in --latest) latest=1 ;; --issues) issues=1 ;; *) echo "unknown arg $a" >&2; exit 2 ;; esac; done
mkdir -p "$DEST"

for r in $REPOS; do
  if [ -d "$DEST/$r/.git" ]; then
    git -C "$DEST/$r" fetch -q --tags origin
  else
    git clone -q "https://github.com/opnsense/$r.git" "$DEST/$r"
  fi
  if [ $latest = 0 ] && pin=$(awk -v r="$r" '$1==r {print $2}' "$REFS" 2>/dev/null) && [ -n "$pin" ]; then
    git -C "$DEST/$r" checkout -q "$pin"
  else
    git -C "$DEST/$r" checkout -q "origin/HEAD"
  fi
  echo "$r $(git -C "$DEST/$r" rev-parse HEAD) $(git -C "$DEST/$r" describe --tags --always 2>/dev/null)"
done

if [ $latest = 1 ] || [ ! -f "$REFS" ]; then
  { echo "# repo commit describe — pinned OPNsense reference sources (scripts/fetch-reference.sh --latest to bump)"
    for r in $REPOS; do echo "$r $(git -C "$DEST/$r" rev-parse HEAD) $(git -C "$DEST/$r" describe --tags --always 2>/dev/null)"; done
  } >"$REFS"
fi

if [ $issues = 1 ]; then
  mkdir -p reference/opnsense-issues
  for r in core plugins; do
    gh api --paginate "repos/opnsense/$r/issues?state=all&per_page=100" \
      --jq '.[] | select(.pull_request|not) | {n:.number,t:.title,s:.state,r:.state_reason,l:[.labels[].name],c:.comments,rx:.reactions.total_count,at:.created_at[:10],b:((.body // "")[:1200])}' \
      >"reference/opnsense-issues/$r.jsonl"
    echo "issues $r: $(wc -l <"reference/opnsense-issues/$r.jsonl")"
  done
fi
