#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "general.h"

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bpftracker.h"
#include "bpftracker.skel.h"

static int bpfverbose = 0;

#define __NR_perf_event_open 298

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static char *get_currtime(void)
{
	char *datetime = malloc(100);
	time_t t = time(NULL);
	struct tm *tmp;

	memset(datetime, 0, 100);

	if ((tmp = localtime(&t)) == NULL)
		EXITERR("could not get localtime");

	if ((strftime(datetime, 100, "%Y/%m/%d_%H:%M", tmp)) == 0)
		EXITERR("could not parse localtime");

	return datetime;
}

static int get_pid_max(void)
{
	FILE *f;
	int pid_max = 0;

	if ((f = fopen("/proc/sys/kernel/pid_max", "r")) < 0)
		RETERR("failed to open proc_sys pid_max");

	if (fscanf(f, "%d\n", &pid_max) != 1)
		RETERR("failed to read proc_sys pid_max");

	fclose(f);

	return pid_max;
}

int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static int output(struct data_t *e)
{
	char *currtime = get_currtime();

	switch (e->etype) {
	case EXCHANGE_CREATE:
		WRAPOUT("(%s) %s (pid: %d) (uid: %d) - CREATE %s (type: %s)\n",
			currtime, e->comm, e->pid,
			e->loginuid, e->ipset_name,
			e->ipset_type);
		break;
		;;
	default:
		break;
		;;
	}

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

/*
void trap(int what)
{
	exiting = 1;
}
*/

struct bpftracker_bpf *bpftracker;
struct perf_buffer *pb = NULL;

int bpftracker_init(void)
{
	__u32 full, major, minor, patch;
	char *kern_version = getenv("LIBBPF_KERN_VERSION");
	int err = 0, pid_max;
	struct perf_buffer_opts pb_opts;

	//signal(SIGINT, trap);
	//signal(SIGTERM, trap);

	libbpf_set_print(libbpf_print_fn);

	if ((err = bump_memlock_rlimit()))
		EXITERR_FMT("failed to increase rlimit: %d", err);

	if (!(bpftracker = bpftracker_bpf__open()))
		EXITERR_FMT("failed to open BPF object");

	if ((pid_max = get_pid_max()) < 0)
		EXITERR_FMT("failed to get pid_max");

	if (kern_version) {
		if (sscanf(kern_version, "%u.%u.%u", &major, &minor, &patch) != 3)
			WARN("could not parse env variable kern_version");

		full = KERNEL_VERSION(major, minor, patch);

		if (bpf_object__set_kversion(bpftracker->obj, full) < 0)
			EXITERR("could not set kern_version attribute");
	}

	if ((err = bpftracker_bpf__load(bpftracker)))
		CLEANERR("failed to load BPF object: %d\n", err);

	if ((err = bpftracker_bpf__attach(bpftracker)))
		CLEANERR("failed to attach\n");

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;

	pb = perf_buffer__new(bpf_map__fd(bpftracker->maps.events), PERF_BUFFER_PAGES, &pb_opts);

	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	return err;

cleanup:
	perf_buffer__free(pb);
	bpftracker_bpf__destroy(bpftracker);

	return err;
}

int bpftracker_cleanup(void)
{
	perf_buffer__free(pb);
	bpftracker_bpf__destroy(bpftracker);

	return 0;
}

/*
	printf("Tracing... Hit Ctrl-C to end.\n");

	while (1) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;

		if (exiting)
			break;
	}

*/
