/* Host test of neverblock.h (built with the host cc by
 * nix/tests/guard-bpf-build.nix; also `cc -o t neverblock_test.c && ./t`). */
#include <stdio.h>
#include "neverblock.h"

static int failures;

static void expect(const char *leaf, int want)
{
	char buf[64] = { 0 };
	int i;

	/* As in BPF: the name sits in a zero-padded 64-byte buffer. */
	for (i = 0; i < 63 && leaf[i]; i++)
		buf[i] = leaf[i];
	if (is_neverblock(buf) != want) {
		fprintf(stderr, "is_neverblock(\"%s\") != %d\n", leaf, want);
		failures++;
	}
	/* And as a bare C string (no padding past the NUL). */
	if (is_neverblock(leaf) != want) {
		fprintf(stderr, "is_neverblock(bare \"%s\") != %d\n", leaf, want);
		failures++;
	}
}

int main(void)
{
	/* The brief's cases. */
	expect("sensr-agent.service", 1);
	expect("sensr-update-check.service", 1);
	expect("session-3.scope", 0);
	expect("sensr-agentx.service", 0);

	/* Every exact name. */
	expect("init.scope", 1);
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

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("neverblock: all cases pass\n");
	return 0;
}
