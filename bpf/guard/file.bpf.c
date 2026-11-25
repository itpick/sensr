// SPDX-License-Identifier: GPL-2.0-only
/* file: writes to protected paths (hook `file_write`): opens for writing,
 * unlinks, and renames (either side). */
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm.s/file_open")
int BPF_PROG(guard_file_open, struct file *file, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;

	if (ret)
		return ret; /* an earlier LSM already denied it */
	if (!(file->f_mode & GUARD_FMODE_WRITE))
		return 0;
	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_FILE_WRITE))
		return 0;
	if (!target_d_path(s, (struct path *)&file->f_path) || !and_target_path(s))
		return 0;
	return finish(s, GUARD_HOOK_FILE_WRITE);
}

SEC("lsm.s/path_unlink")
int BPF_PROG(guard_path_unlink, const struct path *dir, struct dentry *dentry, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;

	if (ret)
		return ret;
	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_FILE_WRITE))
		return 0;
	if (!target_dir_entry(s, dir, dentry) || !and_target_path(s))
		return 0;
	return finish(s, GUARD_HOOK_FILE_WRITE);
}

/*
 * Both sides of a rename are checked; the stronger match wins (block over
 * alert, the old path on a tie) and is the one event emitted. So moving a
 * file into a blocked directory is blocked even when the source directory
 * has an alert rule.
 */
SEC("lsm.s/path_rename")
int BPF_PROG(guard_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;
	int r_old = -1, r_new = -1;

	if (ret)
		return ret;
	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_FILE_WRITE))
		return 0;
	set_copy(&s->proc, &s->acc);
	if (target_dir_entry(s, old_dir, old_dentry) && and_target_path(s)) {
		r_old = guard_pick(&s->acc, GUARD_HOOK_FILE_WRITE);
		if (r_old >= 0)
			path_copy(s->ev.target, s->target.path);
	}
	set_copy(&s->acc, &s->proc);
	if (target_dir_entry(s, new_dir, new_dentry) && and_target_path(s))
		r_new = guard_pick(&s->acc, GUARD_HOOK_FILE_WRITE);
	if (r_new >= 0 && (r_old < 0 || (r_new >> 16) > (r_old >> 16)))
		return emit(s, r_new, s->target.path);
	if (r_old >= 0)
		return emit(s, r_old, NULL);
	return 0;
}
