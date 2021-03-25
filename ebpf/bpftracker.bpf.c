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

static __always_inline int
enter_ip_route_output_flow(enum ev_type etype, struct pt_regs *ctx, struct flowi4 *flp4)
{
	struct data_t data = {};
	struct task_struct *task = (void *) bpf_get_current_task();
	// process related
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;
	u64 ts = bpf_ktime_get_ns();
	// network related
	/*
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct flowi4 *fl4;
	*/
	// vars
	__be16 orig_sport, orig_dport;
	__be32 daddr, nexthop;

	// current process basic information
	data.pid = tgid;
	data.uid = uid;
	data.uid = gid;
	bpf_probe_read_kernel(&data.loginuid, sizeof(unsigned int), &task->loginuid.val);
	bpf_probe_read_kernel_str(&data.comm, TASK_COMM_LEN, task->comm);

	// networking information

	bpf_probe_read_kernel(&data.saddr, sizeof(__be32), &flp4->saddr);
	bpf_probe_read_kernel(&data.daddr, sizeof(__be32), &flp4->daddr);
	bpf_probe_read_kernel(&data.proto, sizeof(u8), &flp4->__fl_common.flowic_proto);
	//bpf_probe_read_kernel(&data.proto, sizeof(u8), &flp4->__fl_common.flowic_proto);
	//bpf_probe_read_kernel(&data.proto, sizeof(u8), &flp4->__fl_common.flowic_proto);

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

SEC("kprobe/ip_route_output_flow")
int BPF_KPROBE(ip_route_output_flow, struct net *net, struct flowi4 *flp4, const struct sock *sk)
{
	return enter_ip_route_output_flow(EV_CONNECT, ctx, flp4);
}

char LICENSE[] SEC("license") = "GPL";
