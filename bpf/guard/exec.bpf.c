// SPDX-License-Identifier: GPL-2.0-only
/* exec: process launches (hook `exec`). The target is the program being
 * started; the process match uses the program that calls exec. Also keeps
 * task_exe current: set once an exec has gone through (bprm_committed_creds),
 * copied to every new task at fork, and seeded for the tasks that were
 * already running when the pack loaded (an iterator the loader runs once). */
#define GUARD_OBJ exec
#include "common.h"

char LICENSE[] SEC("license") GUARD_SHARED = "GPL";

SEC("lsm.s/bprm_check_security")
int BPF_PROG(guard_exec, struct linux_binprm *bprm, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;
	long len;

	if (ret)
		return ret; /* an earlier LSM already denied it */
	s = scratch_get(task);
	if (!s)
		return 0;
	len = bpf_d_path((struct path *)&bprm->file->f_path, s->long_path, GUARD_PATH_MAX);
	if (!long_to_target(s, len))
		return 0;
	if (!begin(s, task, GUARD_HOOK_EXEC) || !and_target_path(s))
		return 0;
	return finish(s, GUARD_HOOK_EXEC);
}

/* The cache entry for a d_path result of `len` bytes (with its NUL) in
 * `buf`, cut as long_to_target says; "unknown" without a path. */
static __always_inline void cache_path(struct guard_path_key *cache, const char *buf, long len)
{
	if (len <= 0) {
		cache->prefixlen = 0;
		cache->path[0] = 0;
		return;
	}
	path_copy(cache->path, buf);
	if (len > GUARD_PATH_LEN) {
		cache->path[GUARD_PATH_LEN - 1] = 0;
		cache->prefixlen = (GUARD_PATH_LEN - 1) * 8;
	} else {
		cache->prefixlen = len * 8;
	}
}

/*
 * The exec went through (every LSM allowed it and the new image is
 * committed): cache the new exe, cut to 255 bytes if longer. An exec that
 * is denied, by a rule here or anyone else, or that fails later never gets
 * here, so the old image's path stays.
 */
SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(guard_exec_commit, const struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s = scratch_get(task);
	struct guard_path_key *cache;
	long len;

	if (!s)
		return 0;
	cache = bpf_task_storage_get(&task_exe, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cache)
		return 0;
	len = bpf_d_path((struct path *)&bprm->file->f_path, s->long_path, GUARD_PATH_MAX);
	cache_path(cache, s->long_path, len);
	return 0;
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

/* d_path output of the seeding iterator (per CPU: it does not sleep). Only
 * this object has it, so it is not GUARD_SHARED. */
struct guard_seed_buf {
	char long_path[GUARD_PATH_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct guard_seed_buf);
} seed_buf SEC(".maps");

/*
 * Seed task_exe for every task that has no entry yet: the tasks that were
 * running before the pack loaded (the loader reads this iterator once,
 * right after attaching everything). The exe is the task's mm->exe_file;
 * kernel threads have none and stay "unknown". A task that execs or forks
 * meanwhile already has an entry, which is kept.
 */
SEC("iter/task")
int guard_seed_exe(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	struct guard_seed_buf *b;
	struct guard_path_key *cache;
	struct mm_struct *mm;
	struct file *exe;
	__u32 zero = 0;
	long len;

	if (!task)
		return 0;
	if (bpf_task_storage_get(&task_exe, task, 0, 0))
		return 0;
	mm = task->mm;
	if (!mm)
		return 0;
	exe = mm->exe_file;
	if (!exe)
		return 0;
	b = bpf_map_lookup_elem(&seed_buf, &zero);
	if (!b)
		return 0;
	len = bpf_d_path((struct path *)&exe->f_path, b->long_path, GUARD_PATH_MAX);
	if (len <= 0)
		return 0;
	cache = bpf_task_storage_get(&task_exe, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (cache)
		cache_path(cache, b->long_path, len);
	return 0;
}
