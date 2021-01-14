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

void initlog(char *prefix)
{
	// syslog with informational messages

	openlog(NULL, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_USER);

	// temporary log file generated for each execution

	logfile = g_strdup_printf("/tmp/%s.log", basename(prefix));

	logfd = open(logfile, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (logfd == -1) {
		perror("open");
		exit(1);
	}

	syslogwrap("Starting to capture conntrack events");
}

void endlog(void)
{
	close(logfd);
	closelog();
	g_free(logfile);

	syslogwrap("Finished capturing conntrack/ulog events");
}

void out_logfile(void)
{
	syslogwrap("Dumping internal data into: %s", logfile);
}
