#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "bpftracker.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
 * NOTE:
 *
 * I want this to be compatible to old kernels and, considering v4.15 as my
 * supported baseline, it does not support global variables. Without global
 * data it is hard to get a pointer of a populated struct at a retprobe...
 * this would be the best case to get all socket information from connect()
 * and similar. Because of that, I'm getting information from different
 * probes, considering the time of the execution they are called and
 * amount of populated info they have in structs like sk, sock, inet, ...
 *
 * Note that there are also changes in data types that have to be considered
 * in order to have the same functions probed. One example is sk_protocol
 * variable from struct sock: it was a a bitfield back in 4.15 but now is
 * a full u16 variable.
 */

#define BASE \
	struct data_t data = {};					\
	struct task_struct *task = (void *) bpf_get_current_task();	\
	u64 id1 = bpf_get_current_pid_tgid(); 				\
	u64 id2 = bpf_get_current_uid_gid(); 				\
	u32 tgid = id1 >> 32, pid = id1; 				\
	u32 gid = id2 >> 32, uid = id2; 				\
	data.pid = tgid;						\
	data.uid = uid;							\
	data.uid = gid;							\
	bpf_probe_read_kernel(&data.loginuid, sizeof(unsigned int), &task->loginuid.val); \
	bpf_probe_read_kernel_str(&data.comm, 16, task->comm);

#define COMMON \
	BASE								\
	struct inet_sock *inet = inet_sk(sk);				\
	struct tcp_sock *tp = tcp_sk(sk);				\
	struct flowi4 *fl4= &inet->cork.fl.u.ip4;			\
	struct flowi6 *fl6= &inet->cork.fl.u.ip6;			\
	struct ipv6_pinfo *np = inet6_sk(sk);				\

// helper functions: helper functions used in kernel that needed some tweaks
// in order to work with eBPF: base pointers need to be read from kernel addr
// space before pointer arithmetics

#undef htons
#define htons(x) ((__be16)(__u16)(x))

static __always_inline bool
check_for_zeros_v4(struct data_t *gdata)
{
	if (gdata->sport == 0 || gdata->dport == 0)
		return 1;
	if (gdata->saddr == 0 || gdata->daddr == 0)
		return 1;

	return 0;
}

static __always_inline bool
check_for_zeros_v6(struct data_t *gdata)
{
	if (gdata->sport == 0 || gdata->dport == 0)
		return 1;

	if ((gdata->saddr6.in6_u.u6_addr32[0] == 0  &&
	     gdata->saddr6.in6_u.u6_addr32[1] == 0  &&
	     gdata->saddr6.in6_u.u6_addr32[2] == 0  &&
	     gdata->saddr6.in6_u.u6_addr32[3] == 0) ||
	    (gdata->daddr6.in6_u.u6_addr32[0] == 0  &&
	     gdata->daddr6.in6_u.u6_addr32[1] == 0  &&
	     gdata->daddr6.in6_u.u6_addr32[2] == 0  &&
	     gdata->daddr6.in6_u.u6_addr32[3] == 0))
		return 1;

	return 0;
}

static __always_inline struct inet_sock *
inet_sk(const struct sock *sk)
{
	struct inet_sock *ptr;

	bpf_probe_read_kernel(&ptr, sizeof (void *), &sk);

	return ptr;
}

static __always_inline struct tcp_sock *
tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

static __always_inline struct ipv6_pinfo *
inet6_sk(const struct sock *__sk)
{
	struct inet_sock *inet = inet_sk(__sk);
	struct ipv6_pinfo *ptr;

	bpf_probe_read_kernel(&ptr, sizeof(void *), &inet->pinet6);

	return ptr;
}

static inline unsigned char *
skb_transport_header(const struct sk_buff *skb)
{
	u16 transp_header;
	unsigned char *head;

	bpf_probe_read_kernel(&head, sizeof(void *), &skb->head);
	bpf_probe_read_kernel(&transp_header, sizeof(u16), &skb->transport_header);

	return head + transp_header;
}

static inline bool
skb_is_udp4(const struct sk_buff *skb)
{
	u16 protocol;

	bpf_probe_read_kernel(&protocol, sizeof(u16), &skb->protocol);

	return protocol == 8; // htons(ETH_P_IP) and not htons(ETH_P_IPV6)
}

static inline unsigned char *
skb_network_header(const struct sk_buff *skb)
{
	u16 net_header;
	unsigned char *head;

	bpf_probe_read_kernel(&head, sizeof(void *), &skb->head);
	bpf_probe_read_kernel(&net_header, sizeof(u16), &skb->network_header);

	return head + net_header;
}

static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_network_header(skb);
}

// TCPv4/TCPv6 inbound: probe compatible to v4.15 and v5.8

static __always_inline int
inet_getname_enter(struct pt_regs *ctx, int family, struct sock *sk)
{
	COMMON;

	volatile u8 skc_state;	// sk_type is bitfield, guess if this is UDP or TCP

	bpf_probe_read_kernel((u8 *) &skc_state, sizeof(u8), (u8 *) &sk->__sk_common.skc_state);
	if (skc_state != 2)	// TCP_SYN_SENT
		return 0;

	data.thesource = 0;	// INBOUND
	data.family = family;	// AF_INET or AF_INET6
	data.proto = 6;		// IPPROTO_TCP

	switch(family) {
	case 2:
		bpf_probe_read_kernel(&data.sport, sizeof(u16), &inet->sk.__sk_common.skc_dport);
		bpf_probe_read_kernel(&data.saddr, sizeof(u32), &inet->sk.__sk_common.skc_daddr);
		bpf_probe_read_kernel(&data.dport, sizeof(u16), &inet->inet_sport);
		bpf_probe_read_kernel(&data.daddr, sizeof(u32), &inet->inet_saddr);
		if (check_for_zeros_v4(&data))
			return 0;
		break;
	case 10:
		bpf_probe_read_kernel(&data.sport, sizeof(u16), &inet->sk.__sk_common.skc_dport);
		bpf_probe_read_kernel(&data.saddr6, sizeof(struct in6_addr), &inet->sk.__sk_common.skc_v6_daddr);
		bpf_probe_read_kernel(&data.dport, sizeof(u16), &inet->inet_sport);
		bpf_probe_read_kernel(&data.daddr6, sizeof(struct in6_addr), &np->saddr);
		if (check_for_zeros_v6(&data))
			return 0;
		break;
	default:
		return 0;
	}

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

SEC("kprobe/inet_getname")
int BPF_KPROBE(inet_getname, struct socket *sock, struct sockaddr *uaddr, int peer)
{
	struct sock *sk;
	bpf_probe_read_kernel(&sk, sizeof(void *), &sock->sk);
	return inet_getname_enter(ctx, 2, sk);
}

SEC("kprobe/inet6_getname")
int BPF_KPROBE(inet6_getname, struct socket *sock, struct sockaddr *uaddr, int peer)
{
	struct sock *sk;
	bpf_probe_read_kernel(&sk, sizeof(void *), &sock->sk);
	return inet_getname_enter(ctx, 10, sk);
}

// TCPv4/TCPv6 outbound: probe compatible to v4.15 and v5.8

static __always_inline int
tcp_connect_enter(struct pt_regs *ctx, struct sock *sk)
{
	COMMON;

	volatile u8 skc_state;	// sk_type is bitfield, guess if this is UDP or TCP

	bpf_probe_read_kernel((u8 *) &skc_state, sizeof(u8), (u8 *) &sk->__sk_common.skc_state);
	if (skc_state != 2)	// TCP_SYN_SENT
		return 0;

	data.thesource = 1;	// OUTBOUND
	data.proto = 6;		// IPPROTO_TCP

	bpf_probe_read_kernel(&data.family, sizeof(u8), &sk->__sk_common.skc_family);

	switch (data.family) {
	case 2: // AF_INET
		bpf_probe_read_kernel(&data.saddr, sizeof(u32), &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&data.daddr, sizeof(u32), &sk->__sk_common.skc_daddr);
		bpf_probe_read_kernel(&data.sport, sizeof(u16), &inet->inet_sport);
		bpf_probe_read_kernel(&data.dport, sizeof(u16), &sk->__sk_common.skc_dport);
		if (check_for_zeros_v4(&data))
			return 0;
		break;
	case 10: // AF_INET6
		bpf_probe_read_kernel(&data.saddr6, sizeof(data.saddr6), &sk->__sk_common.skc_v6_rcv_saddr);
		bpf_probe_read_kernel(&data.daddr6, sizeof(data.daddr6), &sk->__sk_common.skc_v6_daddr);
		bpf_probe_read_kernel(&data.sport, sizeof(u16), &inet->inet_sport);
		bpf_probe_read_kernel(&data.dport, sizeof(u16), &sk->__sk_common.skc_dport);
		if (check_for_zeros_v6(&data))
			return 0;
		break;
	}

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
	return tcp_connect_enter(ctx, sk);
}

// UDPv4 outbound tracing: compatible to v4.15 and v5.8

static __always_inline int
udp_send_skb_enter(struct pt_regs *ctx, struct sock *sk, struct flowi4 *flow4)
{
	BASE;

	data.thesource = 1;	// OUTBOUND

	// NOTE: sk->sk_protocol not portable between v4.15 and v5.8, use flow if available
	bpf_probe_read_kernel(&data.family, sizeof(u8), &sk->__sk_common.skc_family);
	bpf_probe_read_kernel(&data.proto, sizeof(u8), &flow4->__fl_common.flowic_proto);
	bpf_probe_read_kernel(&data.saddr, sizeof(u32), &flow4->saddr);
	bpf_probe_read_kernel(&data.daddr, sizeof(u32), &flow4->daddr);
	bpf_probe_read_kernel(&data.sport, sizeof(u16), &flow4->uli.ports.sport);
	bpf_probe_read_kernel(&data.dport, sizeof(u16), &flow4->uli.ports.dport);

	if (check_for_zeros_v4(&data))
		return 0;

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb, struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork)
{
	struct sock *sk;
	bpf_probe_read_kernel(&sk, sizeof(void *), &skb->sk);
	return udp_send_skb_enter(ctx, sk, fl4);
}

// UDPv6 outbound tracing: compatible to v4.15 and v5.8

static __always_inline int
udp_v6_send_skb_enter(struct pt_regs *ctx, struct sock *sk, struct flowi6 *flow6)
{
	BASE;

	data.thesource = 1;	// OUTBOUND

	// NOTE: sk->sk_protocol not portable between v4.15 and v5.8, use flow if available
	bpf_probe_read_kernel(&data.family, sizeof(u8), &sk->__sk_common.skc_family);
	bpf_probe_read_kernel(&data.proto, sizeof(u8), &flow6->__fl_common.flowic_proto);
	bpf_probe_read_kernel(&data.saddr6, sizeof(struct in6_addr), &flow6->saddr);
	bpf_probe_read_kernel(&data.daddr6, sizeof(struct in6_addr), &flow6->daddr);
	bpf_probe_read_kernel(&data.sport, sizeof(u16), &flow6->uli.ports.sport);
	bpf_probe_read_kernel(&data.dport, sizeof(u16), &flow6->uli.ports.dport);

	if (check_for_zeros_v6(&data))
		return 0;

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

SEC("kprobe/udp_v6_send_skb")
int BPF_KPROBE(udp_v6_send_skb, struct sk_buff *skb, struct flowi6 *fl6, struct inet_cork *cork)
{
	struct sock *sk;
	bpf_probe_read_kernel(&sk, sizeof(void *), &skb->sk);
	return udp_v6_send_skb_enter(ctx, sk, fl6);
}

// UDPv4/UDPv6 inbound: probe compatible to v4.15 and v5.8

static __always_inline int
skb_consume_udp_enter(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
	COMMON;

	data.thesource = 0;	// INBOUND
	data.proto = 17;	// IPPROTO_UDP

	if (skb_is_udp4(skb)) {
		struct iphdr *iph = ip_hdr(skb);
		struct udphdr *udph = udp_hdr(skb);
		data.family = 2;
		bpf_probe_read_kernel(&data.sport, sizeof(u16), &udph->source);
		bpf_probe_read_kernel(&data.saddr, sizeof(u32), &iph->saddr);
		bpf_probe_read_kernel(&data.dport, sizeof(u16), &udph->dest);
		bpf_probe_read_kernel(&data.daddr, sizeof(u32), &iph->daddr);
		if (check_for_zeros_v4(&data))
			return 0;
	} else {
		struct ipv6hdr *iph = ipv6_hdr(skb);
		struct udphdr *udph = udp_hdr(skb);
		data.family = 10;
		bpf_probe_read_kernel(&data.sport, sizeof(u16), &udph->source);
		bpf_probe_read_kernel(&data.saddr6, sizeof(struct in6_addr), &iph->saddr);
		bpf_probe_read_kernel(&data.dport, sizeof(u16), &udph->dest);
		bpf_probe_read_kernel(&data.daddr6, sizeof(struct in6_addr), &iph->daddr);
		if (check_for_zeros_v6(&data))
			return 0;
	}

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
	return skb_consume_udp_enter(ctx, sk, skb);
}

char LICENSE[] SEC("license") = "GPL";
