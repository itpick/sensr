// SPDX-License-Identifier: GPL-2.0-only
/* module: kernel module loads (hook `module`), from a file (finit_module)
 * or from memory (init_module). */
#define GUARD_OBJ module
#include "common.h"

char LICENSE[] SEC("license") GUARD_SHARED = "GPL";

SEC("lsm.s/kernel_read_file")
int BPF_PROG(guard_module_file, struct file *file, enum kernel_read_file_id id, bool contents,
	     int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;

	if (ret)
		return ret; /* an earlier LSM already denied it */
	if (id != READING_MODULE && id != bpf_core_enum_value(enum kernel_read_file_id,
							     READING_MODULE_COMPRESSED))
		return 0;
	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_MODULE))
		return 0;
	if (!target_d_path(s, (struct path *)&file->f_path) || !and_target_path(s))
		return 0;
	return finish(s, GUARD_HOOK_MODULE);
}

SEC("lsm/kernel_load_data")
int BPF_PROG(guard_module_data, enum kernel_load_data_id id, bool contents, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;

	if (ret)
		return ret; /* an earlier LSM already denied it */
	if (id != LOADING_MODULE)
		return 0;
	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_MODULE))
		return 0;
	if (!and_target_nopath(s))
		return 0;
	return finish(s, GUARD_HOOK_MODULE);
}
