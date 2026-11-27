/* Host test of neverblock.h (built with the host cc by
 * nix/tests/guard-bpf-build.nix; also `cc -o t neverblock_test.c && ./t`). */
#include <stdio.h>
#include "neverblock.h"

static int failures;

/* As in BPF: a name sits in a zero-padded 64-byte buffer. */
static void pad(char *buf, const char *name)
{
	int i;

	for (i = 0; i < 64; i++)
		buf[i] = 0;
	for (i = 0; i < 63 && name[i]; i++)
		buf[i] = name[i];
}

static void expect_at(const char *leaf, const char *parent, int level, int want)
{
	char lb[64], pb[64];

	pad(lb, leaf);
	pad(pb, parent);
	if (is_neverblock(lb, pb, level) != want) {
		fprintf(stderr, "is_neverblock(\"%s\", \"%s\", %d) != %d\n", leaf, parent, level,
			want);
		failures++;
	}
	/* And as bare C strings (no padding past the NUL). */
	if (is_neverblock(leaf, parent, level) != want) {
		fprintf(stderr, "is_neverblock(bare \"%s\", \"%s\", %d) != %d\n", leaf, parent,
			level, want);
		failures++;
	}
}

/* A system service: system.slice/<leaf>. */
static void expect(const char *leaf, int want)
{
	expect_at(leaf, "system.slice", 2, want);
}

int main(void)
{
	/* The brief's cases. */
	expect("sensr-agent.service", 1);
	expect("sensr-update-check.service", 1);
	expect("session-3.scope", 0);
	expect("sensr-agentx.service", 0);

	/* Every exact name. */
	expect_at("init.scope", "", 1, 1);
	expect("sensr-guard.service", 1);
	expect("sensr-api.service", 1);
	expect("sshd.service", 1);
	expect("systemd-networkd.service", 1);
	expect("systemd-resolved.service", 1);
	expect("systemd-journald.service", 1);
	expect("sensr-kea-dhcp4.service", 1);
	expect("sensr-unbound.service", 1);
	expect("nix-daemon.service", 1);
	expect("sensr-nic-recover.service", 1);

	/* Every prefix, alone and extended. */
	expect("sensr-update", 1);
	expect("sensr-update.service", 1);
	expect("sensr-pi5-install-boot.service", 1);
	expect("sensr-bootlog.service", 1);
	expect("sensr-bootlog-flush.service", 1);
	expect("sensr-trial-health.service", 1);

	/* Near misses. */
	expect("", 0);
	expect("/", 0);
	expect("init.scop", 0);
	expect("init.scopes", 0);
	expect("sshd.service2", 0);
	expect("sshd", 0);
	expect("sshd@1.service", 0);
	expect("sensr-pi5", 0);
	expect("sensr-pi4-x.service", 0);
	expect("sensr-updat", 0);
	expect("xsensr-update.service", 0);
	expect("sensr-trial", 0);
	expect("user@0.service", 0);
	expect("sensr-agent.servic", 0);

	/* The root cgroup: kernel threads and usermode helpers (modprobe from
	 * request_module), whatever its name reads as. */
	expect_at("", "", 0, 1);
	expect_at("/", "", 0, 1);

	/* init.scope counts only directly under the root. */
	expect("init.scope", 0);
	expect_at("init.scope", "app.slice", 5, 0);

	/* A delegated subtree naming its cgroups after exempt units gets
	 * nothing: user@1000.service/app.slice/<leaf> is depth 5, and a leaf
	 * made directly in a delegated cgroup has another parent. */
	expect_at("sshd.service", "app.slice", 5, 0);
	expect_at("sensr-update-x", "app.slice", 5, 0);
	expect_at("sensr-agent.service", "user@1000.service", 4, 0);
	expect_at("sshd.service", "user-1000.slice", 3, 0);
	expect_at("sensr-update-x", "user@1000.service", 4, 0);
	/* Depth 2 under another slice is not system.slice. */
	expect_at("sshd.service", "user.slice", 2, 0);
	expect_at("sshd.service", "machine.slice", 2, 0);
	expect_at("sshd.service", "system.slicex", 2, 0);
	expect_at("sshd.service", "system.slic", 2, 0);
	/* A sub-cgroup of an exempt service (Delegate=) is deeper: not exempt. */
	expect_at("payload", "sshd.service", 3, 0);
	expect_at("sshd.service", "system.slice", 3, 0);
	/* Depth 1 is never a service. */
	expect_at("sshd.service", "", 1, 0);
	expect_at("system.slice", "", 1, 0);

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("neverblock: all cases pass\n");
	return 0;
}
