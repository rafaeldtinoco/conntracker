#include "general.h"

int logfd;
char *logfile;
int amiadaemon;

/* debug */

void debug(char *string)
{
#ifdef DEBUG
	syslogwrap("DEBUG: %s", string);
#endif
}

/* daemon */

int makemeadaemon(void)
{
	int fd;

	g_fprintf(stdout, "Daemon mode. Check syslog for messages!\n");

	switch(fork()) {
	case -1: return -1;
	case 0: break;
	default: exit(SUCCESS);
	}

	if (setsid() == -1)
		return -1;

	switch(fork()) {
	case -1: return -1;
	case 0: break;
	default: exit(SUCCESS);
	} umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

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

	return SUCCESS;
}

int dontmakemeadaemon(void)
{
	g_fprintf(stdout, "Foreground mode...<Ctrl-C> or or SIG_TERM to end it.\n");

	umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return SUCCESS;
}

void initlog(char *prefix)
{
	/* syslog with informational messages */
	openlog(NULL, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_USER);

	/* temporary log file generated for each execution */
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

	syslogwrap("Finished capturing conntrack events");
}

void out_logfile(void)
{
	syslogwrap("Dumping internal data into: %s", logfile);
}
