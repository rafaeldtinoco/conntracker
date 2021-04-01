/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#include "general.h"
#include "flows.h"
#include "iptables.h"

int logfd;
char *logfile;
int amiadaemon;
int tracefeat;
int traceitall;

char *get_currtime(void)
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

int get_pid_max(void)
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

char *get_username(uint32_t uid)
{
	char *username = g_malloc0(64);
	struct passwd *p = getpwuid(uid);

	if (!p || !p->pw_name)
		strncpy(username, "-", 64);
	else
		strncpy(username, p->pw_name, 64);

	return username;
}

void cleanup(void)
{
	out_all();
	free_flows();
	endlog();
	del_conntrack();
	iptables_cleanup();
}

int makemeadaemon(void)
{
	int fd;

	g_fprintf(stdout, "Daemon mode. Check syslog for messages!\n");

	switch(fork()) {
	case -1:	return -1;
	case 0:		break;
	default:	exit(0);
	}

	if (setsid() == -1)
		return -1;

	switch(fork()) {
	case -1:	return -1;
	case 0:		break;
	default:	exit(0);
	}

	umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (chdir("/") == -1)
		return -1;

	close(0); close(1); close(2);

	fd = open("/dev/null", O_RDWR);

	if (fd != 0)
		return -1;
	if (dup2(0, 1) != 1)
		return -1;
	if (dup2(0, 2) != 2)
		return -1;

	return 0;
}

int dontmakemeadaemon(void)
{
	g_fprintf(stdout, "Foreground mode...<Ctrl-C> or or SIG_TERM to end it.\n");

	umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return 0;
}

void initlog(gchar *outfile)
{
	// syslog with informational messages

	openlog(NULL, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_USER);

	WRAPOUT("Starting to capture conntrack events");

	logfile = g_strdup_printf("%s", outfile);

	if (g_strcmp0(logfile, "-") == 0) {
		logfd = 1; g_free(logfile); logfile = g_strdup("STDOUT");
		return;
	}

	logfd = open(logfile, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (logfd == -1) {
		fprintf(stderr, "could not open logfile %s\n", logfile);
		exit(1);
	}

	return;
}

void endlog(void)
{
	if (logfd > 2) {
		close(logfd);
		logfd = -1;
	}

	closelog();

	if (logfile != NULL)
		g_free(logfile);

	WRAPOUT("Finished capturing conntrack/ulog events");
}

void out_logfile(void)
{
	WRAPOUT("Dumping internal data into: %s", logfile);
}
