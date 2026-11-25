// SPDX-License-Identifier: GPL-2.0-only
/* connect: outbound connections (hook `connect`), IPv4 and IPv6. */
#define GUARD_OBJ connect
#include "common.h"

char LICENSE[] SEC("license") GUARD_SHARED = "GPL";

/* Copy the address and port of an AF_INET/AF_INET6 sockaddr into the event;
 * returns the family, or 0 for anything else. */
static __always_inline __u8 read_sockaddr(struct guard_scratch *s, struct sockaddr *address,
					  int addrlen, __u16 *port)
{
	__u16 family = 0;

	if (bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family))
		return 0;
	if (family == GUARD_AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
		struct sockaddr_in sin;

		if (bpf_probe_read_kernel(&sin, sizeof(sin), address))
			return 0;
		__builtin_memcpy(s->ev.addr, &sin.sin_addr.s_addr, 4);
		*port = guard_ntohs(sin.sin_port);
		return GUARD_AF_INET;
	}
	if (family == GUARD_AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 sin6;

		if (bpf_probe_read_kernel(&sin6, sizeof(sin6), address))
			return 0;
		__builtin_memcpy(s->ev.addr, &sin6.sin6_addr, 16);
		*port = guard_ntohs(sin6.sin6_port);
		return GUARD_AF_INET6;
	}
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(guard_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;
	__u16 port = 0;
	__u8 family;

	if (ret)
		return ret; /* an earlier LSM already denied it */

	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_CONNECT))
		return 0;
	family = read_sockaddr(s, address, addrlen, &port);
	if (!family || !and_target_net(s, family, port))
		return 0;
	return finish(s, GUARD_HOOK_CONNECT);
}
