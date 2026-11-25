// SPDX-License-Identifier: GPL-2.0-only
/* file: writes to protected paths (hook `file_write`): opens for writing,
 * unlinks, and renames (either side). */
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm.s/file_open")
int BPF_PROG(guard_file_open, struct file *file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;
	long len;

	if (!(file->f_mode & GUARD_FMODE_WRITE))
		return 0;
	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_FILE_WRITE))
		return 0;
	len = bpf_d_path((struct path *)&file->f_path, s->target.path, GUARD_PATH_LEN);
	if (!target_from_len(s, len) || !and_target_path(s))
		return 0;
	return finish(s, GUARD_HOOK_FILE_WRITE, NULL);
}

SEC("lsm.s/path_unlink")
int BPF_PROG(guard_path_unlink, const struct path *dir, struct dentry *dentry)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s = scratch_get(task);

	if (!s || !begin(s, task, GUARD_HOOK_FILE_WRITE))
		return 0;
	if (!target_dir_entry(s, dir, dentry) || !and_target_path(s))
		return 0;
	return finish(s, GUARD_HOOK_FILE_WRITE, NULL);
}

SEC("lsm.s/path_rename")
int BPF_PROG(guard_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s = scratch_get(task);
	int matched = 0, verdict;

	if (!s || !begin(s, task, GUARD_HOOK_FILE_WRITE))
		return 0;
	set_copy(&s->proc, &s->acc);
	if (target_dir_entry(s, old_dir, old_dentry) && and_target_path(s)) {
		verdict = finish(s, GUARD_HOOK_FILE_WRITE, &matched);
		if (matched)
			return verdict;
	}
	set_copy(&s->acc, &s->proc);
	if (!target_dir_entry(s, new_dir, new_dentry) || !and_target_path(s))
		return 0;
	return finish(s, GUARD_HOOK_FILE_WRITE, NULL);
}
