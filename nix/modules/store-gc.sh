# sensr-store-gc: drop old system generations, then collect garbage.
#
#   sensr-store-gc [--locked]
#
# Every in-app update imports a whole system closure, so without this the
# store only grows (ISS-C-023). It keeps:
#   - the generation the system profile points at (the one the next boot
#     of the profile would use) and the running system;
#   - the system the machine booted from (/run/booted-system), which may be
#     older than the running one after a switch without a reboot;
#   - every toplevel the boot partition's slots name (current/, next/,
#     previous/ under @bootDir@): the firmware boots those without asking
#     Nix, so they get a GC root of their own and are never collected;
#   - the newest @keep@ other generations, for rollback.
# Older generations are deleted by explicit number, never "+N", so which
# ones survive does not depend on how many protected generations there are.
#
# --locked: the caller (the updater) already holds the update lock. Without
# it the lock is taken here, so a GC never runs while a closure is being
# imported and before it is rooted.
set -euo pipefail

profile=/nix/var/nix/profiles/system
keep=@keep@
boot_dir=@bootDir@
state_dir=@stateDir@
run_dir=@runDir@
root_dir=/nix/var/nix/gcroots/sensr-boot

if [ "${1:-}" != --locked ]; then
  mkdir -p "$state_dir"
  exec 9>"$state_dir/lock"
  flock 9
fi

free_bytes() { df -B1 --output=avail /nix | tail -n1 | tr -d ' '; }

before=$(free_bytes)
declare -A protect=()

protect_path() { # a path (symlink or store path) to protect
  local p
  p=$(readlink -f "$1" 2>/dev/null) || return 0
  [ -n "$p" ] && [ -e "$p" ] && protect["$p"]=1
  return 0
}

protect_path /run/current-system
protect_path /run/booted-system
protect_path "$profile"

# A GC root per boot slot. A slot whose system is already gone from the
# store (or has no slot) loses its root; nothing can be done for it.
mkdir -p "$root_dir"
for slot in current next previous; do
  link="$root_dir/$slot"
  sys=""
  if [ -r "$boot_dir/$slot/system" ]; then
    sys=$(head -n1 "$boot_dir/$slot/system")
  fi
  if [ -n "$sys" ] && [ -e "$sys" ]; then
    ln -sfn "$sys" "$link.new"
    mv -T "$link.new" "$link"
    protect["$sys"]=1
    echo "boot slot $slot: $sys (rooted)"
  else
    rm -f "$link"
    if [ -n "$sys" ]; then
      echo "boot slot $slot names $sys, which is not in the store" >&2
    fi
  fi
done

# Generation numbers, newest first.
mapfile -t gens < <(
  for l in "$profile"-*-link; do
    [ -L "$l" ] || continue
    n=${l#"$profile"-}
    n=${n%-link}
    case $n in '' | *[!0-9]*) continue ;; esac
    echo "$n"
  done | sort -rn
)

kept=()
doomed=()
others=0
for n in "${gens[@]}"; do
  target=$(readlink -f "$profile-$n-link" 2>/dev/null || true)
  if [ -n "$target" ] && [ -n "${protect[$target]:-}" ]; then
    kept+=("$n")
  elif [ "$others" -lt "$keep" ]; then
    others=$((others + 1))
    kept+=("$n")
  else
    doomed+=("$n")
  fi
done

if [ "${#doomed[@]}" -gt 0 ]; then
  echo "deleting system generations: ${doomed[*]} (keeping: ${kept[*]:-none})"
  nix-env -p "$profile" --delete-generations "${doomed[@]}"
else
  echo "no system generations to delete (keeping: ${kept[*]:-none})"
fi

nix-store --gc

after=$(free_bytes)
freed=$((after - before))
[ "$freed" -ge 0 ] || freed=0
echo "freed $((freed / 1048576)) MiB; $((after / 1048576)) MiB free on /nix"

mkdir -p "$state_dir" "$run_dir"
jq -n \
  --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson freed "$freed" \
  --argjson free "$after" \
  --argjson deleted "$(printf '%s\n' "${doomed[@]:-}" | jq -R 'select(. != "") | tonumber' | jq -s .)" \
  --argjson kept "$(printf '%s\n' "${kept[@]:-}" | jq -R 'select(. != "") | tonumber' | jq -s .)" \
  '{at: $at, freed_bytes: $freed, free_bytes: $free, deleted_generations: $deleted, kept_generations: $kept}' \
  > "$state_dir/gc.json.tmp"
mv "$state_dir/gc.json.tmp" "$state_dir/gc.json"
cp "$state_dir/gc.json" "$run_dir/gc.json.tmp"
chmod 0644 "$run_dir/gc.json.tmp"
mv "$run_dir/gc.json.tmp" "$run_dir/gc.json"
