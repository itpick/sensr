/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * The never-block list: systemd units (leaf cgroup names, at their place in
 * the hierarchy) whose processes a block rule never stops, plus the root
 * cgroup (kernel threads and the usermode helpers the kernel starts, such as
 * modprobe for request_module). Alerts still apply to them.
 *
 * A name alone is not enough: a user's delegated subtree
 * (user.slice/user-UID.slice/user@UID.service/...) may create a cgroup
 * called sshd.service. So the service names and prefixes count only directly
 * under system.slice (depth 2), and init.scope only directly under the root
 * (depth 1).
 *
 * Compiled into the programs, not kept in a map, so stale or missing map
 * data can never lock anyone out. Rules cannot override it.
 *
 * Pure C with no kernel or libc includes: the BPF programs and the host test
 * (neverblock_test.c) use the same function. `leaf` is a NUL-terminated
 * name; in BPF it is a 64-byte buffer (GUARD_UNIT_LEN). The comparisons
 * stop at the first differing byte, so they never read past the NUL of a
 * shorter name, and the loops have constant bounds (the literal's size), so
 * clang unrolls them and the verifier sees straight-line code.
 */
#ifndef SENSR_GUARD_NEVERBLOCK_H
#define SENSR_GUARD_NEVERBLOCK_H

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifdef __clang__
#define NB_UNROLL _Pragma("unroll")
#else
#define NB_UNROLL
#endif

/* Longest name the programs read (with its NUL). */
#define NEVERBLOCK_LEAF_MAX 64

/* `leaf` equals the first `n` bytes of `lit` (n counts lit's NUL). */
static __always_inline int nb_eq(const char *leaf, const char *lit, int n)
{
NB_UNROLL
	for (int i = 0; i < n; i++)
		if (leaf[i] != lit[i])
			return 0;
	return 1;
}

/* `leaf` starts with `lit` (n counts lit's NUL, which is not compared). */
static __always_inline int nb_prefix(const char *leaf, const char *lit, int n)
{
NB_UNROLL
	for (int i = 0; i < n - 1; i++)
		if (leaf[i] != lit[i])
			return 0;
	return 1;
}

#define NB_EXACT(lit)                                                          \
	do {                                                                   \
		_Static_assert(sizeof(lit) <= NEVERBLOCK_LEAF_MAX, lit);       \
		if (nb_eq(leaf, lit, sizeof(lit)))                             \
			return 1;                                              \
	} while (0)

#define NB_PREFIX(lit)                                                         \
	do {                                                                   \
		_Static_assert(sizeof(lit) <= NEVERBLOCK_LEAF_MAX, lit);       \
		if (nb_prefix(leaf, lit, sizeof(lit)))                         \
			return 1;                                              \
	} while (0)

/*
 * 1 if blocks never apply to a task in the cgroup named `leaf`, at depth
 * `level` (0: the root cgroup), whose parent cgroup is named `parent`.
 */
static __always_inline int is_neverblock(const char *leaf, const char *parent, int level)
{
	if (level == 0)
		return 1;
	if (level == 1) {
		NB_EXACT("init.scope");
		return 0;
	}
	if (level != 2 || !nb_eq(parent, "system.slice", sizeof("system.slice")))
		return 0;
	NB_EXACT("sensr-agent.service");
	NB_EXACT("sensr-guard.service");
	NB_EXACT("sensr-api.service");
	NB_EXACT("sshd.service");
	NB_EXACT("systemd-networkd.service");
	NB_EXACT("systemd-resolved.service");
	NB_EXACT("systemd-journald.service");
	NB_EXACT("sensr-kea-dhcp4.service");
	NB_EXACT("sensr-unbound.service");
	NB_EXACT("nix-daemon.service");
	NB_EXACT("sensr-nic-recover.service");
	NB_PREFIX("sensr-update");
	NB_PREFIX("sensr-pi5-");
	NB_PREFIX("sensr-bootlog");
	NB_PREFIX("sensr-trial-");
	return 0;
}

#undef NB_EXACT
#undef NB_PREFIX
#undef NB_UNROLL

#endif
