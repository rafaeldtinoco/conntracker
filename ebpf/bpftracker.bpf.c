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

static __always_inline void *nla_data(struct nlattr *nla)
{
	return (char *) nla + NLA_HDRLEN;
}

static __always_inline int
probe_enter(enum ev_type etype, void *ctx, struct nlmsghdr *nlh, struct nlattr *attr[])
{
	struct task_struct *task = (void *) bpf_get_current_task();

	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;
	u64 ts = bpf_ktime_get_ns();

	struct data_t data = {};

	data.pid = tgid;
	data.uid = uid;
	data.uid = gid;
	data.etype = etype;

	bpf_probe_read_kernel(&data.loginuid, sizeof(unsigned int), &task->loginuid.val);
	bpf_probe_read_kernel_str(&data.comm, TASK_COMM_LEN, task->comm);

	struct nlattr *nla_name, *nla_name2, *nla_type;
	bpf_probe_read_kernel(&nla_name, sizeof(void *), &attr[IPSET_ATTR_SETNAME]);
	bpf_probe_read_kernel_str(&data.ipset_name, IPSET_MAXNAMELEN, nla_data(nla_name));

	switch (data.etype) {
	case EXCHANGE_CREATE:
		bpf_probe_read_kernel(&nla_type, sizeof(void *), &attr[IPSET_ATTR_TYPENAME]);
		bpf_probe_read_kernel_str(&data.ipset_type, IPSET_MAXNAMELEN, nla_data(nla_type));
		break;
	default:
		break;
		;;
	}

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

SEC("kprobe/ip_set_create")
int BPF_KPROBE(ip_set_create, struct net *net, struct sock *ctnl, struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_CREATE, ctx, nlh, attr);
}

static __always_inline int
probe_return(enum ev_type etype, void *ctx, int ret)
{
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;

	switch (etype) {
	case EXCHANGE_CREATE:
		return 0;
	default:
		break;
	}

	return 1;
}

SEC("kretprobe/ip_set_create")
int BPF_KRETPROBE(ip_set_create_ret, int ret)
{
	return probe_return(EXCHANGE_CREATE, ctx, ret);
}

char LICENSE[] SEC("license") = "GPL";
