// SPDX-License-Identifier: GPL-2.0-only
/* exec: process launches (hook `exec`). The target is the program being
 * started; the process match uses the program that calls exec. Also keeps
 * task_exe current: set here at exec, copied to every new task at fork. */
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm.s/bprm_check_security")
int BPF_PROG(guard_exec, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s = scratch_get(task);
	struct guard_path_key *cache;
	long len;
	int verdict = 0;

	if (!s)
		return 0;
	len = bpf_d_path((struct path *)&bprm->file->f_path, s->target.path, GUARD_PATH_LEN);
	if (len <= 0 || len > GUARD_PATH_LEN)
		return 0;

	if (begin(s, task, GUARD_HOOK_EXEC)) {
		if (target_from_len(s, len) && and_target_path(s))
			verdict = finish(s, GUARD_HOOK_EXEC, NULL);
	}

	/* Cache the new exe, even when nothing matched. A denied exec leaves
	 * the old image running, so keep the old path then. */
	if (verdict == 0) {
		cache = bpf_task_storage_get(&task_exe, task, 0,
					     BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (cache) {
			path_copy(cache->path, s->target.path);
			cache->prefixlen = len * 8;
		}
	}
	return verdict;
}

/* A new task (fork or thread) runs its parent's program until it execs. */
SEC("lsm/task_alloc")
int BPF_PROG(guard_exec_inherit, struct task_struct *task, unsigned long clone_flags)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct guard_path_key *from = bpf_task_storage_get(&task_exe, parent, 0, 0);
	struct guard_path_key *to;

	if (!from)
		return 0;
	to = bpf_task_storage_get(&task_exe, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (to) {
		path_copy(to->path, from->path);
		to->prefixlen = from->prefixlen;
	}
	return 0;
}
