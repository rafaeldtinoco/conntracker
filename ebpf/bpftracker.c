#include "general.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bpftracker.h"
#include "bpftracker.skel.h"

#include "flows.h"
#include "iptables.h"

static int bpfverbose = 0;

#define __NR_perf_event_open 298

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

struct bpftracker_bpf *bpftracker;
struct perf_buffer *pb = NULL;

extern int tracefeat;

static int output(struct data_t *e)
{
	struct in_addr src, dst;
	u16 psrc = 0, pdst = 0;
	char *tempbuf, *username;
	char *currtime = get_currtime();
	char *source = NULL, *destination = NULL;

	/* discard iptables interference */

	if (g_strstr_len(e->comm, 16, "iptables") != NULL)
		return 0;
	if (g_strstr_len(e->comm, 16, "ip6tables") != NULL)
		return 0;

	src.s_addr = e->saddr;
	dst.s_addr = e->daddr;

	psrc = htons(e->sport);
	pdst = htons(e->dport);

	psrc = psrc > 1024 ? 1024 : psrc;

	username = (e->loginuid != -1) ? get_username(e->loginuid) : get_username(e->uid);
	tempbuf = g_malloc0(128);
	g_snprintf(tempbuf, 128, "%s,pid:%u,uid:%s", e->comm, e->pid, username);

	if (e->pid == 2996992)
		return 0;

	switch (e->family) {
	case AF_INET:
		source = ipv4_str(&src);
		destination = ipv4_str(&dst);

		switch (e->proto) {
		case IPPROTO_TCP:
			add_tcpv4flow(src, dst, (u16) ntohs(psrc), (u16) ntohs(pdst), 1, tempbuf);
			if (tracefeat)
				add_tcpv4trace(src, dst, (u16) ntohs(psrc), (u16) ntohs(pdst), 1);
			break;
		case IPPROTO_UDP:
			add_udpv4flow(src, dst, (u16) ntohs(psrc), (u16) ntohs(pdst), 0, tempbuf);
			if (tracefeat)
				add_udpv4trace(src, dst, (u16) ntohs(psrc), (u16) ntohs(pdst), 0);
			break;
		default:
			break;
		}
		break;
	case AF_INET6:
		source = ipv6_str(&e->saddr6);
		destination = ipv6_str(&e->daddr6);

		switch (e->proto) {
		case IPPROTO_TCP:
			add_tcpv6flow(e->saddr6, e->daddr6, (u16) ntohs(psrc), (u16) ntohs(pdst), 1, tempbuf);
			if (tracefeat)
				add_tcpv6trace(e->saddr6, e->daddr6, (u16) ntohs(psrc), (u16) ntohs(pdst), 1);
			break;
		case IPPROTO_UDP:
			add_udpv6flow(e->saddr6, e->daddr6, (u16) ntohs(psrc), (u16) ntohs(pdst), 0, tempbuf);
			if (tracefeat)
				add_udpv6trace(e->saddr6, e->daddr6, (u16) ntohs(psrc), (u16) ntohs(pdst), 0);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	// DEBUG:
	//
	// WRAPOUT("(%s) %s (pid: %d) (loginuid: %d) | (%u) %s (%u) => %s (%u)",
	// 		currtime, e->comm, e->pid, e->loginuid, (u8) e->proto,
	// 		source, psrc, destination, pdst);

	if (username) { g_free(username); }
	g_free(tempbuf);
	free(source);
	free(destination);
	free(currtime);

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !bpfverbose)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct data_t *e = data;

	output(e);

	return;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int bpftracker_init(void)
{
	__u32 full, major, minor, patch;
	char *kern_version = getenv("LIBBPF_KERN_VERSION");
	int err = 0, pid_max;
	struct perf_buffer_opts pb_opts;

	libbpf_set_print(libbpf_print_fn);

	if ((err = bump_memlock_rlimit()))
		EXITERR("failed to increase rlimit: %d", err);

	if (!(bpftracker = bpftracker_bpf__open()))
		EXITERR("failed to open BPF object");

	if ((pid_max = get_pid_max()) < 0)
		EXITERR("failed to get pid_max");

	if (kern_version) {
		if (sscanf(kern_version, "%u.%u.%u", &major, &minor, &patch) != 3)
			WARN("could not parse env variable kern_version");

		full = KERNEL_VERSION(major, minor, patch);

		if (bpf_object__set_kversion(bpftracker->obj, full) < 0)
			EXITERR("could not set kern_version attribute");
	}

	if ((err = bpftracker_bpf__load(bpftracker)))
		RETERR("failed to load BPF object: %d", err);

	if ((err = bpftracker_bpf__attach(bpftracker)))
		RETERR("failed to attach: %d", err);

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;

	pb = perf_buffer__new(bpf_map__fd(bpftracker->maps.events), PERF_BUFFER_PAGES, &pb_opts);

	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		RETERR("failed to open perf buffer: %d\n", err);
	}

	return err;
}

int bpftracker_cleanup(void)
{
	perf_buffer__free(pb);
	bpftracker_bpf__destroy(bpftracker);

	return 0;
}

int bpftracker_poll(gpointer ptr)
{
	int *timeout = ptr;

	if (perf_buffer__poll(pb, *timeout) < 0)
		return -1;

	return TRUE; // TRUE will continue processing events
}
