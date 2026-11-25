# Runtime guard: the `core` pack's BPF programs

C BPF LSM programs, compiled by `nix/packages/sensr-guard-bpf.nix` (clang
`-target bpf`, `vmlinux.h` from the image kernel's BTF) into

```
$out/share/sensr-guard/packs/core/{manifest.json,rules.json,core.bpf.o}
```

Each source below compiles to its own object, and the build links them
all into `core.bpf.o` with `bpftool gen object`. The manifest's `programs`
lists that one object.

`common.h` is the map contract; `crates/sensr-guard` mirrors its structs
with `#[repr(C)]`. This file is the same contract in prose. The rule
compiler and the loader must follow it exactly. Change both sides together.

## Objects and programs

| Source object | Section | Hook |
|---|---|---|
| exec.bpf.o | `lsm.s/bprm_check_security` | `exec`. It also caches the new exe in `task_exe`. |
| | `lsm/task_alloc` | No hook. It copies the parent's `task_exe` to each new task. |
| connect.bpf.o | `lsm/socket_connect` | `connect` (IPv4 and IPv6) |
| listen.bpf.o | `lsm/socket_bind` | `listen` for non-stream inet sockets bound to a non-zero port (UDP) |
| | `lsm/socket_listen` | `listen` for TCP, with the bound address |
| file.bpf.o | `lsm.s/file_open` | `file_write` (opens with `FMODE_WRITE`) |
| | `lsm.s/path_unlink` | `file_write` |
| | `lsm.s/path_rename` | `file_write`. It checks both paths; the stronger match wins. |
| creds.bpf.o | `lsm/task_fix_setuid` | `setuid`, only when uid or euid changes. The target is the new euid. |
| module.bpf.o | `lsm.s/kernel_read_file` | `module` (`READING_MODULE`, `READING_MODULE_COMPRESSED`). The target is the module file. |
| | `lsm/kernel_load_data` | `module` (`LOADING_MODULE`). There is no path. |
| bpf.bpf.o | `lsm/bpf` | `bpf` (`BPF_PROG_LOAD`, `BPF_LINK_CREATE`). It skips `config.guard_tgid` entirely: no event, no block. |

The path hooks (`path_unlink`, `path_rename`) and `kernel_read_file` are
sleepable (`lsm.s/`), so they can use the `bpf_d_path` helper. That is the
pattern the spike proved; it needs no kfuncs. Built against 7.3.4's BTF,
every program passed the verifier on a live 7.2 aarch64 kernel, and each
one blocked and reported as described below.

**Shared maps.** Every source object declares the same maps, as weak
symbols (`GUARD_SHARED` in common.h). The link merges them, so
`core.bpf.o` holds one instance of each map, and every program uses it.
The loader loads that one object and creates each map once, with no
pinning. `task_exe` in particular must be shared: exec fills it and the
others read it. `scratch` is also merged, and it is internal: the loader
creates it but never reads or writes it.

`guard_pick` is a global (non-static) function. Each source names its
copy `guard_pick_<GUARD_OBJ>`, so the link keeps every copy with its own
symbol. A weak copy would leave code with no symbol behind, which aya
refuses to load.

C struct tags carry a `guard_` prefix (`struct guard_event`,
`struct guard_rule_set`, ...), because the kernel's own types in
`vmlinux.h` already use names like `scratch` and `config`. The map names
are the unprefixed ones below.

## Hook and action numbers

`hook`: exec 0, connect 1, listen 2, file_write 3, setuid 4, module 5, bpf 6.
This is the declaration order of `sensr_guard::rule::Hook`.
`action`: alert 0, block 1.

## Maps

All values are little-endian host structs. Addresses are in network
order. Ports are host order.

| Map | Type | Key | Value | Max |
|---|---|---|---|---|
| `rules_meta` | ARRAY | `u32 slot` | `struct guard_rule_meta { u32 id; u8 hook; u8 action; u8 enabled; }` (8 B) | 1024 |
| `exe_prefix_lpm` | LPM_TRIE | `struct guard_path_key { u32 prefixlen; char path[256]; }` (260 B) | `struct guard_rule_set` | 4096 |
| `path_prefix_lpm` | LPM_TRIE | `struct guard_path_key` | `struct guard_rule_set` | 4096 |
| `net4_lpm` | LPM_TRIE | `{ u32 prefixlen; u8 addr[4]; }` | `struct guard_rule_set` | 2048 |
| `net6_lpm` | LPM_TRIE | `{ u32 prefixlen; u8 addr[16]; }` | `struct guard_rule_set` | 2048 |
| `port_rules` | HASH | `{ u32 port; }` | `struct guard_rule_set` | 4096 |
| `unit_rules` | HASH | `{ char name[64]; }`, the leaf cgroup name, zero-padded | `struct guard_rule_set` | 1025 |
| `uid_rules` | HASH | `{ u32 uid; }` | `struct guard_rule_set` | 1025 |
| `hits` | PERCPU_ARRAY | `u32 slot` | `u64` | 1024 |
| `config` | ARRAY | `u32 0` | `struct guard_config { u8 kill_switch; u32 guard_tgid; }` (8 B, `guard_tgid` at offset 4) | 1 |
| `events` | RINGBUF | | `struct guard_event` records | 1 MiB |
| `ringbuf_dropped` | PERCPU_ARRAY | `u32 0` | `u64`: events the ring buffer had no room for (sum the CPUs) | 1 |
| `task_exe` | TASK_STORAGE | (task) | `struct guard_path_key`: the exe path and `prefixlen = 8 * (strlen + 1)` | |

The LPM maps use `BPF_F_NO_PREALLOC`, as LPM tries require.

### `struct guard_rule_set { u64 bits[16]; }` (128 B)

This is a set of rule **slots** 0..1023. Slot `s` is bit `s % 64` of
`bits[s / 64]`. The slot is the index into `rules_meta` and `hits`, and it
is what `event.rule_id` reports. `rule_meta.id` must equal the slot; it
exists only for the contract. Userspace keeps the mapping from rule-id
strings to slots.

### `struct guard_event` (624 B)

| Field | Offset | |
|---|---|---|
| `u64 ts` | 0 | CLOCK_BOOTTIME ns (`bpf_ktime_get_boot_ns`) |
| `u32 pid, ppid, uid` | 8, 12, 16 | pid = tgid, in the root pid namespace; uid = the current uid |
| `u32 rule_id` | 20 | slot |
| `u8 hook, action, blocked` | 24, 25, 26 | `action` is the rule's action; `blocked` says whether the operation was denied |
| `char exe[256]` | 27 | cached exe of the task ("" if unknown) |
| `char target[256]` | 283 | path; for setuid the uid in decimal; for bpf `prog_load` / `link_create`; "" for net hooks |
| `u8 addr[16]` | 539 | network order; IPv4 is in `addr[0..4]` |
| `u16 port` | 556 | host order |
| `u8 family` | 558 | 2 (AF_INET), 10 (AF_INET6), or 0 |
| `char unit[64]` | 559 | leaf cgroup name (the systemd unit) |

Strings are NUL-terminated within their field (a path longer than 255
bytes is cut to its first 255). Bytes after the NUL are unspecified.
An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is reported as
`family = 2` with the IPv4 address in `addr[0..4]`.

## How a program matches (the compiler must produce exactly this)

Each rule is a slot. Each program looks up one `rule_set` per
**dimension** it consults, ANDs them, and then walks the result:

| Hook | Dimensions consulted |
|---|---|
| exec | exe, unit, path (the program being started) |
| file_write | exe, unit, path (the file) |
| module (file) | exe, unit, path (the module file) |
| module (data) | exe, unit, path with an empty key, so the wildcard only |
| connect, listen | exe, unit, net4 or net6 (by family), port |
| setuid | exe, unit, uid |
| bpf | exe, unit |

- **exe**: `exe_prefix_lpm` looked up with the task's `task_exe` value
  (`prefixlen = 8 * (strlen + 1)`, so the NUL takes part). If the exe is
  unknown, the lookup uses `prefixlen = 0`, which reaches only the
  wildcard entry. For exec, "the task" is the caller of exec, so the
  process match applies to the program that starts another.
- **unit**: `unit_rules[leaf name] | unit_rules[all-zero name]`.
- **path**: `path_prefix_lpm` looked up with the subject path, also with
  `prefixlen = 8 * (strlen + 1)`.
- **long paths**: `bpf_d_path` runs into a PATH_MAX buffer. A path longer
  than 255 bytes becomes a key of its first 255 bytes with no NUL
  (`prefixlen = 8 * 255`). So it matches prefix entries, never exact ones.
  The same cut applies to `task_exe` and to the event's `exe`/`target`.
- **net**: `net4_lpm` with `prefixlen = 32`, or `net6_lpm` with
  `prefixlen = 128`. An IPv4-mapped IPv6 address is looked up in
  `net4_lpm` as its IPv4 address. So an IPv4 rule also covers
  `::ffff:a.b.c.d` on an AF_INET6 socket, and the compiler need not add
  mapped entries to `net6_lpm`.
  A v6 CIDR in a rule matches native IPv6 only: `::/0` does not cover IPv4
  or mapped addresses, which only IPv4 rules (or an explicit
  `::ffff:a.b.c.d/>=96` rule, compiled into `net4_lpm`) cover. To match
  everything, use `Target::Any`.
- **port**: `port_rules[port] | port_rules[0x10000]`.
- **uid**: `uid_rules[new euid] | uid_rules[0xffffffff]`.

If a lookup finds nothing, the set is empty and nothing matches, so the
program returns early.

### Wildcards ("any" in a dimension)

| Dimension | Wildcard key |
|---|---|
| exe, path | the LPM entry with `prefixlen = 0` |
| net4, net6 | the LPM entry with `prefixlen = 0` |
| unit | the all-zero 64-byte name |
| port | `0x10000` (`GUARD_PORT_ANY`) |
| uid | `0xffffffff` (`GUARD_UID_ANY`) |

A rule must appear in **every dimension its hook consults**. It goes at
its own key when the rule constrains that dimension, and at the wildcard
key when it doesn't:

- a rule with no `exe_prefix` goes in the exe wildcard;
- a rule with no `unit` goes in the unit wildcard;
- `Target::Any` goes in the wildcard of each target dimension of its hook
  (path; net4 + net6 + port; or uid);
- `Target::Net { cidr, ports: [] }` goes at its CIDR in net4 or net6, and in
  the port wildcard;
- `Target::Net { cidr, ports }` goes at its CIDR, and at each port.

A rule that is missing from a dimension never matches for that hook.
Putting rules in dimensions their hook does not consult is harmless,
because slots are filtered by hook at the end. Leaving them out keeps the
walk short.

### LPM values are cumulative

An LPM lookup returns only the **longest** matching entry. So the value
stored at each prefix must be the union of its own rules and the rules of
**every shorter entry that covers it**, the `prefixlen = 0` wildcard
included. Example: with `/nix/` → {1} and the wildcard → {2}, the entry
for `/nix/store/` holds {1, 2, and its own}.

### Path prefixes

A rule on `/nix/store` must match `/nix/store` and `/nix/store/x`, but not
`/nix/storefoo`. It compiles to two keys:

- the prefix entry `"/nix/store/"`, with `prefixlen = 8 * 11` (no NUL);
- the exact entry `"/nix/store\0"`, with `prefixlen = 8 * 11` (the NUL
  included).

`/nix/store/` means the same as `/nix/store`. Prefix `/` is the root
directory: `"/"` (prefixlen 8) matches every absolute path. The same rule
applies to `exe_prefix_lpm`.

### Picking the rule

After the AND, the program walks the set bits in slot order, bounded at
1024. It skips slots whose `rules_meta` entry is disabled or belongs to
another hook. The **first block rule** wins. If there is none, the
**first alert rule** wins. If no slot survives, the program does nothing.

On a match:

- the program increments `hits[slot]` and emits one `event`;
- it returns `-EPERM` only if all of these hold:
  - the action is block;
  - `config[0]` exists and `kill_switch == 0`;
  - the task's leaf cgroup name is not in `neverblock.h`.

With no `config` entry, nothing blocks (fail open).

`path_rename` picks a rule for the old path and for the new path, each with
the walk above. The stronger one is used: block beats alert, and on a tie
the old path wins. Only one event is emitted, with that side's path as the
target. So moving a file into a blocked directory is blocked even when the
source directory only has an alert rule.

Every program first passes through a verdict that an earlier LSM already
returned (`ret != 0`), without looking at any rules.

If the ring buffer is full, the event is lost and `ringbuf_dropped[0]`
(this CPU's slot) is incremented. The hit and the verdict are unaffected.

## Filtering left to userspace

- **"A kernel module loads after boot completed"** (`core-module-load`).
  The programs report every module load. sensr-guard ignores module events
  until `boot-complete.target` is reached.

## Known limits

- **Not hooked**: `path_link`, `path_truncate`, `path_mkdir`, `path_mknod`
  and `path_symlink`, and `chmod`/`chown`. A hard link, a truncate through
  `truncate(2)`, or a new directory under a protected path is not seen.
  Opening a file for writing, with `O_TRUNC` or `O_CREAT`, is seen.
- **listen on an unbound socket**: `socket_listen` reads the port before
  the kernel autobinds, so `listen()` without `bind()` is seen as port 0.
  Only port-wildcard rules then match.
- **setuid**: `task_fix_setuid` covers uid and euid changes (setuid,
  setreuid, setresuid, setfsuid). Gaining privileges through file
  capabilities, or `setgid`, is not covered. The target is the new euid.
- **Scripts**: the exe cache is set at `bprm_check_security`. A script
  runs that hook twice, once for the script and once for its interpreter.
  The interpreter's pass sees the script as the calling exe, and the cache
  ends up holding the interpreter.
- **Per-task working memory**: each task that hits a hook gets a `scratch`
  entry of about 6 KiB (TASK_STORAGE, freed when the task exits).
- **Paths longer than PATH_MAX** (4096): `bpf_d_path` fails, so nothing
  matches. At exec, the cache is then set to "unknown", not the old exe.

## Never-block (neverblock.h)

These leaf cgroup names are exempt from blocks, never from alerts:
`init.scope`, `sensr-agent.service`, `sensr-guard.service`,
`sensr-api.service`, `sshd.service`, `systemd-networkd.service`,
`systemd-resolved.service`, `systemd-journald.service`,
`sensr-kea-dhcp4.service`, `sensr-unbound.service`, `nix-daemon.service`,
`sensr-nic-recover.service`, and the prefixes `sensr-update`, `sensr-pi5-`,
`sensr-bootlog`, `sensr-trial-`.

The list is compiled in. No map or rule can change it. `neverblock_test.c`
is its host test, which `checks.<system>.guard-bpf-build` runs.

## The exe cache

- **At exec**: `task_exe` is set when the exec is allowed, cut to 255
  bytes if the path is longer. A denied exec keeps the old exe.
- **At fork or thread creation**: `lsm/task_alloc` copies `task_exe` to the
  new task.
- **Tasks that predate the load**: they have no entry, so only
  wildcard-exe rules match them. The loader may seed them by updating
  `task_exe` with a pidfd key and a `struct guard_path_key` value.
