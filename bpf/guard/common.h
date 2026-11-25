/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The map contract shared by every program of the core pack, and the rule
 * lookup they all use. crates/sensr-guard mirrors the structs below with
 * #[repr(C)]; README.md in this directory is the contract in prose. Change
 * both sides together.
 *
 * Every object declares the same maps. The loader creates each shared map
 * once and hands the same map to every object (by name); `scratch` is the
 * only per-object map.
 */
#ifndef SENSR_GUARD_COMMON_H
#define SENSR_GUARD_COMMON_H

/* kfunc prototypes from vmlinux.h are not used (helpers only). */
#define BPF_NO_KFUNC_PROTOTYPES
/* vmlinux.h has a typedef `config` (zstd); the contract's map is `config`. */
#define config vmlinux_config
#include "vmlinux.h"
#undef config
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "neverblock.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "sensr-guard programs assume a little-endian target"
#endif

#define GUARD_MAX_RULES 1024
#define GUARD_RULE_WORDS (GUARD_MAX_RULES / 64)
#define GUARD_PATH_LEN 256
#define GUARD_UNIT_LEN 64
#define GUARD_MAX_PATH_KEYS 4096
#define GUARD_MAX_NET_KEYS 2048
#define GUARD_MAX_PORT_KEYS 4096
#define GUARD_MAX_UNIT_KEYS 1025
#define GUARD_MAX_UID_KEYS 1025
#define GUARD_RINGBUF_BYTES (1 << 20)
/* d_path works in a PATH_MAX buffer; keys and events keep the first 255
 * bytes of a longer path (see long_to_target). */
#define GUARD_PATH_MAX 4096

/* Wildcard keys of the hash maps ("any" in that dimension). */
#define GUARD_PORT_ANY 0x10000u
#define GUARD_UID_ANY 0xffffffffu
/* unit_rules' wildcard is the all-zero (empty) name. */

#define GUARD_EPERM 1
#define GUARD_AF_INET 2
#define GUARD_AF_INET6 10
#define GUARD_SOCK_STREAM 1
#define GUARD_FMODE_WRITE 0x2

/*
 * Every object defines the maps and LICENSE. The pack links all objects
 * into one (`bpftool gen object core.bpf.o ...`), so the programs share
 * one instance of each map; weak definitions let the linker merge the
 * identical copies instead of refusing them.
 *
 * guard_pick is not shared that way: the linker would keep every weak
 * copy's code but only one symbol, and loaders (aya) refuse code without
 * a symbol. Each object names its own copy guard_pick_<GUARD_OBJ>, which
 * the object defines before including this file.
 */
#define GUARD_SHARED __attribute__((weak))
#ifndef GUARD_OBJ
#error "define GUARD_OBJ (the object's name) before including common.h"
#endif
#define GUARD_CAT2(a, b) a##b
#define GUARD_CAT(a, b) GUARD_CAT2(a, b)
#define guard_pick GUARD_CAT(guard_pick_, GUARD_OBJ)

/* Hook numbers: the order of sensr_guard::rule::Hook. */
enum guard_hook {
	GUARD_HOOK_EXEC = 0,
	GUARD_HOOK_CONNECT = 1,
	GUARD_HOOK_LISTEN = 2,
	GUARD_HOOK_FILE_WRITE = 3,
	GUARD_HOOK_SETUID = 4,
	GUARD_HOOK_MODULE = 5,
	GUARD_HOOK_BPF = 6,
};

enum guard_action {
	GUARD_ACTION_ALERT = 0,
	GUARD_ACTION_BLOCK = 1,
};

/* rules_meta[slot]; the slot is the rule's bit in every rule_set. */
struct guard_rule_meta {
	__u32 id; /* == slot (kept for the contract; reported as event.rule_id) */
	__u8 hook; /* enum guard_hook */
	__u8 action; /* enum guard_action */
	__u8 enabled; /* 0: never matches */
};

/* A set of rule slots: bit (slot % 64) of bits[slot / 64]. */
struct guard_rule_set {
	__u64 bits[GUARD_RULE_WORDS];
};

/* LPM key of exe_prefix_lpm and path_prefix_lpm. `prefixlen` is in bits.
 * Lookup keys carry the path with its NUL and prefixlen = 8 * (strlen + 1). */
struct guard_path_key {
	__u32 prefixlen;
	char path[GUARD_PATH_LEN];
};

struct guard_net4_key {
	__u32 prefixlen;
	__u8 addr[4]; /* network byte order */
};

struct guard_net6_key {
	__u32 prefixlen;
	__u8 addr[16]; /* network byte order */
};

struct guard_port_key {
	__u32 port; /* host order; GUARD_PORT_ANY for any port */
};

struct guard_unit_key {
	char name[GUARD_UNIT_LEN]; /* leaf cgroup name, zero-padded */
};

struct guard_uid_key {
	__u32 uid; /* GUARD_UID_ANY for any uid */
};

struct guard_config {
	__u8 kill_switch; /* 1: nothing blocks */
	__u32 guard_tgid; /* sensr-guard's pid; the bpf hook ignores it */
};

struct guard_event {
	__u64 ts; /* CLOCK_BOOTTIME, ns */
	__u32 pid, ppid, uid; /* pid = tgid */
	__u32 rule_id;
	__u8 hook, action, blocked;
	char exe[GUARD_PATH_LEN];
	char target[GUARD_PATH_LEN];
	__u8 addr[16]; /* network order; IPv4 in addr[0..4] */
	__u16 port; /* host order */
	__u8 family; /* AF_INET, AF_INET6 or 0 */
	char unit[GUARD_UNIT_LEN];
};

/* The Rust mirror asserts the same numbers. */
_Static_assert(sizeof(struct guard_rule_meta) == 8, "rule_meta");
_Static_assert(sizeof(struct guard_rule_set) == 128, "rule_set");
_Static_assert(sizeof(struct guard_path_key) == 260, "path_key");
_Static_assert(sizeof(struct guard_config) == 8, "guard_config");
_Static_assert(__builtin_offsetof(struct guard_event, exe) == 27, "event.exe");
_Static_assert(__builtin_offsetof(struct guard_event, target) == 283, "event.target");
_Static_assert(__builtin_offsetof(struct guard_event, addr) == 539, "event.addr");
_Static_assert(__builtin_offsetof(struct guard_event, port) == 556, "event.port");
_Static_assert(__builtin_offsetof(struct guard_event, family) == 558, "event.family");
_Static_assert(__builtin_offsetof(struct guard_event, unit) == 559, "event.unit");
_Static_assert(sizeof(struct guard_event) == 624, "event");

/* ---- maps (the contract) ---- */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, GUARD_MAX_RULES);
	__type(key, __u32);
	__type(value, struct guard_rule_meta);
} rules_meta SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, GUARD_MAX_PATH_KEYS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct guard_path_key);
	__type(value, struct guard_rule_set);
} exe_prefix_lpm SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, GUARD_MAX_PATH_KEYS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct guard_path_key);
	__type(value, struct guard_rule_set);
} path_prefix_lpm SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, GUARD_MAX_NET_KEYS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct guard_net4_key);
	__type(value, struct guard_rule_set);
} net4_lpm SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, GUARD_MAX_NET_KEYS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct guard_net6_key);
	__type(value, struct guard_rule_set);
} net6_lpm SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, GUARD_MAX_PORT_KEYS);
	__type(key, struct guard_port_key);
	__type(value, struct guard_rule_set);
} port_rules SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, GUARD_MAX_UNIT_KEYS);
	__type(key, struct guard_unit_key);
	__type(value, struct guard_rule_set);
} unit_rules SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, GUARD_MAX_UID_KEYS);
	__type(key, struct guard_uid_key);
	__type(value, struct guard_rule_set);
} uid_rules SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, GUARD_MAX_RULES);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct guard_config);
} config SEC(".maps") GUARD_SHARED;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, GUARD_RINGBUF_BYTES);
} events SEC(".maps") GUARD_SHARED;

/* Events the ring buffer had no room for (per CPU; userspace sums). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_dropped SEC(".maps") GUARD_SHARED;

/* The task's executable, set at exec and inherited at fork (task_alloc in
 * exec.bpf.c). Userspace may seed tasks that predate the load (pidfd key). */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct guard_path_key);
} task_exe SEC(".maps") GUARD_SHARED;

/* ---- per-object working memory (not part of the contract) ---- */

/* Per task, so a preempted program never shares it with another task. */
struct guard_scratch {
	struct guard_event ev;
	/* The subject path (lookup key): the first bytes of long_path. */
	struct guard_path_key target;
	/* d_path output; the extra GUARD_PATH_LEN gives room for the masked
	 * write that appends a file name to a directory path. */
	char long_path[GUARD_PATH_MAX + GUARD_PATH_LEN];
	struct guard_unit_key any_unit; /* never written: the all-zero wildcard */
	struct guard_path_key exe_none; /* zero-length key: the wildcard entry */
	struct guard_rule_set acc;
	struct guard_rule_set tmp;
	struct guard_rule_set proc; /* acc after the process dimensions */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct guard_scratch);
} scratch SEC(".maps") GUARD_SHARED;

/* ---- helpers ---- */

static __always_inline __u16 guard_ntohs(__u16 v)
{
	return __builtin_bswap16(v);
}

/* dst &= src; returns whether anything is left. */
static __always_inline int set_and(struct guard_rule_set *dst, const struct guard_rule_set *src)
{
	__u64 any = 0;

#pragma unroll
	for (int i = 0; i < GUARD_RULE_WORDS; i++) {
		dst->bits[i] &= src->bits[i];
		any |= dst->bits[i];
	}
	return any != 0;
}

static __always_inline void set_copy(struct guard_rule_set *dst, const struct guard_rule_set *src)
{
#pragma unroll
	for (int i = 0; i < GUARD_RULE_WORDS; i++)
		dst->bits[i] = src->bits[i];
}

static __always_inline void set_or(struct guard_rule_set *dst, const struct guard_rule_set *src)
{
#pragma unroll
	for (int i = 0; i < GUARD_RULE_WORDS; i++)
		dst->bits[i] |= src->bits[i];
}

static __always_inline void set_clear(struct guard_rule_set *dst)
{
#pragma unroll
	for (int i = 0; i < GUARD_RULE_WORDS; i++)
		dst->bits[i] = 0;
}

/*
 * acc &= (set(key) | set(any)) for a hash-map dimension with a wildcard
 * key. Returns whether anything is left.
 */
static __always_inline int and_hash_dim(struct guard_scratch *s, void *map, const void *key,
					const void *any_key)
{
	const struct guard_rule_set *a = bpf_map_lookup_elem(map, key);
	const struct guard_rule_set *b = bpf_map_lookup_elem(map, any_key);

	/* (No `!a && !b` shortcut: clang turns it into a pointer OR, which
	 * the verifier refuses.) */
	set_clear(&s->tmp);
	if (a)
		set_or(&s->tmp, a);
	if (b)
		set_or(&s->tmp, b);
	return set_and(&s->acc, &s->tmp);
}

/* acc &= set(lpm lookup of key); an LPM value already holds every rule of
 * the shorter prefixes that cover it, the wildcard included. */
static __always_inline int and_lpm_dim(struct guard_scratch *s, void *map, const void *key)
{
	const struct guard_rule_set *v = bpf_map_lookup_elem(map, key);

	if (!v)
		return 0;
	return set_and(&s->acc, v);
}

static __always_inline struct guard_scratch *scratch_get(struct task_struct *task)
{
	return bpf_task_storage_get(&scratch, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/* Copy a NUL-terminated buffer of GUARD_PATH_LEN bytes (map memory). */
static __always_inline void path_copy(char *dst, const char *src)
{
	__builtin_memcpy(dst, src, GUARD_PATH_LEN);
}

/*
 * Fill the event's identity fields and leave acc = exe set & unit set.
 * Returns 0 when no rule can match (nothing left to do).
 */
static __always_inline int begin(struct guard_scratch *s, struct task_struct *task, __u8 hook)
{
	struct guard_event *ev = &s->ev;
	struct guard_path_key *exe = bpf_task_storage_get(&task_exe, task, 0, 0);
	const struct guard_rule_set *v;
	const char *kname;

	ev->ts = bpf_ktime_get_boot_ns();
	ev->pid = bpf_get_current_pid_tgid() >> 32;
	ev->ppid = BPF_CORE_READ(task, real_parent, tgid);
	ev->uid = (__u32)bpf_get_current_uid_gid();
	ev->rule_id = 0;
	ev->hook = hook;
	ev->action = 0;
	ev->blocked = 0;
	ev->port = 0;
	ev->family = 0;
	__builtin_memset(ev->addr, 0, sizeof(ev->addr));
	__builtin_memset(ev->unit, 0, sizeof(ev->unit));
	kname = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
	bpf_probe_read_kernel_str(ev->unit, sizeof(ev->unit), kname);
	/* s->target is the caller's: some fill it before begin(). */

	/* exe dimension: an unknown exe matches only the wildcard (prefixlen
	 * 0) entry, which a zero-length lookup key reaches. */
	if (exe) {
		path_copy(ev->exe, exe->path);
		v = bpf_map_lookup_elem(&exe_prefix_lpm, exe);
	} else {
		struct guard_path_key *none = &s->exe_none;

		ev->exe[0] = 0;
		none->prefixlen = 0;
		v = bpf_map_lookup_elem(&exe_prefix_lpm, none);
	}
	if (!v)
		return 0;
	set_copy(&s->acc, v);

	/* unit dimension */
	return and_hash_dim(s, &unit_rules, ev->unit, &s->any_unit);
}

/*
 * The lowest enabled rule of `hook` in `acc`, a block rule before any alert
 * rule: returns slot | action << 16, or -1. A global function, so the
 * verifier checks its bounded walk (16 words of 64 bits) once per object
 * (named guard_pick_<object>, see GUARD_OBJ).
 */
__noinline int guard_pick(const struct guard_rule_set *acc, __u32 hook)
{
	int alert = -1;

	if (!acc)
		return -1;
	for (__u32 w = 0; w < GUARD_RULE_WORDS; w++) {
		__u64 bits = acc->bits[w];

		if (!bits)
			continue;
		for (__u32 b = 0; b < 64; b++) {
			__u32 slot = w * 64 + b;
			struct guard_rule_meta *m;

			if (!(bits & (1ULL << b)))
				continue;
			m = bpf_map_lookup_elem(&rules_meta, &slot);
			if (!m || !m->enabled || m->hook != hook)
				continue;
			if (m->action == GUARD_ACTION_BLOCK)
				return slot | (GUARD_ACTION_BLOCK << 16);
			if (alert < 0)
				alert = slot;
		}
	}
	return alert;
}

/*
 * Count the picked rule `r` (from guard_pick, >= 0), emit its event and
 * return the LSM verdict: -EPERM only for a block rule with the kill switch
 * off and the task outside the never-block units. `target` is copied into
 * the event (NULL: ev->target is already set).
 */
static __always_inline int emit(struct guard_scratch *s, int r, const char *target)
{
	struct guard_event *ev = &s->ev;
	struct guard_config *cfg;
	__u32 zero = 0, slot = r & 0xffff;
	__u8 action = r >> 16;
	__u64 *h;
	int verdict = 0;

	h = bpf_map_lookup_elem(&hits, &slot);
	if (h)
		*h += 1;

	ev->rule_id = slot;
	ev->action = action;
	if (action == GUARD_ACTION_BLOCK) {
		cfg = bpf_map_lookup_elem(&config, &zero);
		/* No config yet: fail open. */
		if (cfg && !cfg->kill_switch && !is_neverblock(ev->unit))
			verdict = -GUARD_EPERM;
	}
	ev->blocked = verdict != 0;
	if (target)
		path_copy(ev->target, target);
	if (bpf_ringbuf_output(&events, ev, sizeof(*ev), 0)) {
		h = bpf_map_lookup_elem(&ringbuf_dropped, &zero);
		if (h)
			*h += 1;
	}
	return verdict;
}

/* After every dimension has been ANDed into acc: pick, count, emit. */
static __always_inline int finish(struct guard_scratch *s, __u8 hook)
{
	int r = guard_pick(&s->acc, hook);

	if (r < 0)
		return 0;
	return emit(s, r, s->target.path);
}

/*
 * s->target from long_path holding a d_path result of `len` bytes (with
 * its NUL). A path of up to 255 characters keeps its NUL in the key
 * (prefixlen 8 * len); a longer one is cut to its first 255 bytes with
 * no NUL (prefixlen 8 * 255), so it can match prefix entries only.
 */
static __always_inline int long_to_target(struct guard_scratch *s, long len)
{
	if (len <= 0)
		return 0;
	path_copy(s->target.path, s->long_path);
	if (len > GUARD_PATH_LEN) {
		s->target.path[GUARD_PATH_LEN - 1] = 0; /* for the event only */
		s->target.prefixlen = (GUARD_PATH_LEN - 1) * 8;
	} else {
		s->target.prefixlen = len * 8;
	}
	return 1;
}

/* s->target = d_path(path), cut as long_to_target says. */
static __always_inline int target_d_path(struct guard_scratch *s, struct path *path)
{
	long len = bpf_d_path(path, s->long_path, GUARD_PATH_MAX);

	return long_to_target(s, len);
}

/* acc &= path_prefix_lpm(s->target) */
static __always_inline int and_target_path(struct guard_scratch *s)
{
	return and_lpm_dim(s, &path_prefix_lpm, &s->target);
}

/* The hook has no subject path (the event's target stays empty). */
static __always_inline void no_target_path(struct guard_scratch *s)
{
	s->target.prefixlen = 0;
	s->target.path[0] = 0;
}

/* No subject path: only path rules on the wildcard (prefixlen 0) match. */
static __always_inline int and_target_nopath(struct guard_scratch *s)
{
	no_target_path(s);
	return and_lpm_dim(s, &path_prefix_lpm, &s->target);
}

/* acc &= net set(addr) & (port set(port) | port set(any)). */
static __always_inline int and_target_net(struct guard_scratch *s, __u8 family, __u16 port)
{
	struct guard_event *ev = &s->ev;
	struct guard_port_key pk = { .port = port };
	struct guard_port_key any = { .port = GUARD_PORT_ANY };
	int ok;

	no_target_path(s);
	/* An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is that IPv4 address:
	 * looked up in net4_lpm and reported as AF_INET. */
	if (family == GUARD_AF_INET6) {
		__u32 w0, w1, w2;

		__builtin_memcpy(&w0, &ev->addr[0], 4);
		__builtin_memcpy(&w1, &ev->addr[4], 4);
		__builtin_memcpy(&w2, &ev->addr[8], 4);
		if (w0 == 0 && w1 == 0 && w2 == 0xffff0000u) { /* LE load of 00 00 ff ff */
			__builtin_memcpy(&ev->addr[0], &ev->addr[12], 4);
			__builtin_memset(&ev->addr[4], 0, 12);
			family = GUARD_AF_INET;
		}
	}
	ev->family = family;
	ev->port = port;
	if (family == GUARD_AF_INET) {
		struct guard_net4_key k = { .prefixlen = 32 };

		__builtin_memcpy(k.addr, ev->addr, 4);
		ok = and_lpm_dim(s, &net4_lpm, &k);
	} else {
		struct guard_net6_key k = { .prefixlen = 128 };

		__builtin_memcpy(k.addr, ev->addr, 16);
		ok = and_lpm_dim(s, &net6_lpm, &k);
	}
	if (!ok)
		return 0;
	return and_hash_dim(s, &port_rules, &pk, &any);
}

/*
 * s->target = d_path(dir) + "/" + name: the path of a directory entry,
 * built in long_path (the masked offsets keep every write inside it) and
 * cut as long_to_target says.
 */
static __always_inline int target_dir_entry(struct guard_scratch *s, const struct path *dir,
					    struct dentry *dentry)
{
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	long len = bpf_d_path((struct path *)dir, s->long_path, GUARD_PATH_MAX);
	long pos, n;

	if (len <= 0)
		return 0;
	pos = len - 1; /* the NUL */
	if (pos > 1) { /* not "/" */
		s->long_path[pos & (GUARD_PATH_MAX - 1)] = '/';
		pos++;
	}
	if (pos >= GUARD_PATH_MAX)
		return long_to_target(s, GUARD_PATH_MAX);
	n = bpf_probe_read_kernel_str(&s->long_path[pos & (GUARD_PATH_MAX - 1)],
				      GUARD_PATH_LEN, name);
	if (n <= 0)
		return 0;
	return long_to_target(s, pos + n);
}

/* Write `v` in decimal as the event's target (the uid a setuid gives). */
static __always_inline void target_u32(struct guard_scratch *s, __u32 v)
{
	__u32 t = v;
	int n = 1;

	no_target_path(s);
#pragma unroll
	for (int i = 0; i < 9; i++) {
		t /= 10;
		if (t)
			n++;
	}
#pragma unroll
	for (int i = 0; i < 10; i++) {
		if (i < n) {
			s->target.path[(n - 1 - i) & 15] = '0' + v % 10;
			v /= 10;
		}
	}
	s->target.path[n & 15] = 0;
}

#endif
