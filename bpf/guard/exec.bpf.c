// SPDX-License-Identifier: GPL-2.0-only
/* exec: process launches (hook `exec`). The target is the program being
 * started; the process match uses the program that calls exec. Also keeps
 * task_exe current: set here at exec, copied to every new task at fork. */
#define GUARD_OBJ exec
#include "common.h"

char LICENSE[] SEC("license") GUARD_SHARED = "GPL";

SEC("lsm.s/bprm_check_security")
int BPF_PROG(guard_exec, struct linux_binprm *bprm, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s = scratch_get(task);
	struct guard_path_key *cache;
	long len;
	int verdict = 0;

	if (ret)
		return ret; /* an earlier LSM already denied it */
	if (!s)
		return 0;
	len = bpf_d_path((struct path *)&bprm->file->f_path, s->long_path, GUARD_PATH_MAX);
	if (!long_to_target(s, len)) {
		/* No path (longer than PATH_MAX): cache "unknown", not the old exe. */
		s->target.prefixlen = 0;
		s->target.path[0] = 0;
	} else if (begin(s, task, GUARD_HOOK_EXEC) && and_target_path(s)) {
		verdict = finish(s, GUARD_HOOK_EXEC);
	}

	/* Cache the new exe (cut to 255 bytes if longer), even when nothing
	 * matched. A denied exec leaves the old image running, so keep the
	 * old path then. */
	if (verdict == 0) {
		cache = bpf_task_storage_get(&task_exe, task, 0,
					     BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (cache) {
			path_copy(cache->path, s->target.path);
			cache->prefixlen = s->target.prefixlen;
		}
	}
	return verdict;
}

/* A new task (fork or thread) runs its parent's program until it execs. */
SEC("lsm/task_alloc")
int BPF_PROG(guard_exec_inherit, struct task_struct *task, unsigned long clone_flags, int ret)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct guard_path_key *from;
	struct guard_path_key *to;

	if (ret)
		return ret; /* an earlier LSM already denied it */
	from = bpf_task_storage_get(&task_exe, parent, 0, 0);

	if (!from)
		return 0;
	to = bpf_task_storage_get(&task_exe, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (to) {
		path_copy(to->path, from->path);
		to->prefixlen = from->prefixlen;
	}
	return 0;
}
