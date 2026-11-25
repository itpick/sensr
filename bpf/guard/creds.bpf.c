// SPDX-License-Identifier: GPL-2.0-only
/* creds: privilege changes by setuid (hook `setuid`). The target is the new
 * effective uid. */
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/task_fix_setuid")
int BPF_PROG(guard_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;
	struct guard_uid_key k, any = { .uid = GUARD_UID_ANY };

	if (ret)
		return ret; /* an earlier LSM already denied it */
	k.uid = new->euid.val;
	if (k.uid == old->euid.val && new->uid.val == old->uid.val)
		return 0;
	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_SETUID))
		return 0;
	target_u32(s, k.uid);
	if (!and_hash_dim(s, &uid_rules, &k, &any))
		return 0;
	return finish(s, GUARD_HOOK_SETUID);
}
