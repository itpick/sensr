// SPDX-License-Identifier: GPL-2.0-only
/* listen: new listening ports (hook `listen`). TCP is seen at listen(), with
 * the bound address; other inet sockets (UDP) at bind() to a non-zero port. */
#define GUARD_OBJ listen
#include "common.h"

char LICENSE[] SEC("license") GUARD_SHARED = "GPL";

SEC("lsm/socket_bind")
int BPF_PROG(guard_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_scratch *s;
	__u16 family = 0, port = 0;

	if (ret)
		return ret; /* an earlier LSM already denied it */

	/* Stream sockets are reported by guard_listen. */
	if (BPF_CORE_READ(sock, type) == GUARD_SOCK_STREAM)
		return 0;
	if (bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family))
		return 0;
	if (family != GUARD_AF_INET && family != GUARD_AF_INET6)
		return 0;

	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_LISTEN))
		return 0;
	if (family == GUARD_AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
		struct sockaddr_in sin;

		if (bpf_probe_read_kernel(&sin, sizeof(sin), address))
			return 0;
		__builtin_memcpy(s->ev.addr, &sin.sin_addr.s_addr, 4);
		port = guard_ntohs(sin.sin_port);
	} else if (family == GUARD_AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 sin6;

		if (bpf_probe_read_kernel(&sin6, sizeof(sin6), address))
			return 0;
		__builtin_memcpy(s->ev.addr, &sin6.sin6_addr, 16);
		port = guard_ntohs(sin6.sin6_port);
	} else {
		return 0;
	}
	/* Port 0: an ephemeral (client) port, not a listening one. */
	if (!port || !and_target_net(s, (__u8)family, port))
		return 0;
	return finish(s, GUARD_HOOK_LISTEN);
}

SEC("lsm/socket_listen")
int BPF_PROG(guard_listen, struct socket *sock, int backlog, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct sock *sk;
	struct guard_scratch *s;
	__u16 family, port;

	if (ret)
		return ret; /* an earlier LSM already denied it */
	sk = BPF_CORE_READ(sock, sk);

	if (!sk)
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != GUARD_AF_INET && family != GUARD_AF_INET6)
		return 0;
	port = BPF_CORE_READ(sk, __sk_common.skc_num);

	s = scratch_get(task);
	if (!s || !begin(s, task, GUARD_HOOK_LISTEN))
		return 0;
	if (family == GUARD_AF_INET) {
		__be32 a = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

		__builtin_memcpy(s->ev.addr, &a, 4);
	} else {
		struct in6_addr a6 = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);

		__builtin_memcpy(s->ev.addr, &a6, 16);
	}
	if (!and_target_net(s, (__u8)family, port))
		return 0;
	return finish(s, GUARD_HOOK_LISTEN);
}
