// SPDX-License-Identifier: GPL-2.0-only
/* bpf: BPF program loads and link creation by any process but sensr-guard
 * (hook `bpf`). sensr-guard (config.guard_tgid) is never reported or
 * blocked. The target names the command. */
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/bpf")
int BPF_PROG(guard_bpf, int cmd, union bpf_attr *attr, unsigned int size, bool kernel,
	     int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_config *cfg;
	struct guard_scratch *s;
	__u32 zero = 0;

	if (ret)
		return ret; /* an earlier LSM already denied it */
	if (cmd != BPF_PROG_LOAD && cmd != BPF_LINK_CREATE)
		return 0;
	cfg = bpf_map_lookup_elem(&config, &zero);
	if (cfg && cfg->guard_tgid && cfg->guard_tgid == bpf_get_current_pid_tgid() >> 32)
		return 0;
	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_BPF))
		return 0;
	no_target_path(s);
	if (cmd == BPF_PROG_LOAD)
		__builtin_memcpy(s->target.path, "prog_load", sizeof("prog_load"));
	else
		__builtin_memcpy(s->target.path, "link_create", sizeof("link_create"));
	return finish(s, GUARD_HOOK_BPF);
}
