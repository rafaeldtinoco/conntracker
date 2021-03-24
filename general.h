/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#ifndef GENERAL_H_
#define GENERAL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <libgen.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <gmodule.h>
#include <glib/gprintf.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#define LESS -1
#define EQUAL 0
#define MORE 1

extern int amiadaemon;

int makemeadaemon(void);
int dontmakemeadaemon(void);
void initlog(gchar *);
void endlog(void);
void out_logfile(void);
void cleanup(void);

#define _WRAPOUT(nl, ...)					\
{								\
	switch (amiadaemon) {					\
	case 0:							\
		g_fprintf(stdout, __VA_ARGS__);			\
		if (nl)						\
			g_fprintf(stdout, "\n");		\
		break;						\
	case 1:							\
		syslog(LOG_USER | LOG_INFO, __VA_ARGS__);	\
		break;						\
	}							\
}

#define WRAPOUT0(...) _WRAPOUT(0, __VA_ARGS__)
#define WRAPOUT1(...) _WRAPOUT(1, __VA_ARGS__)
#define WRAPOUT WRAPOUT1

#define HERE WRAPOUT1("line %d, file %s, function %s", __LINE__, __FILE__, __func__)

#define WARN(...)			\
{					\
	WRAPOUT0("WARN: ");		\
	WRAPOUT1(__VA_ARGS__);		\
}

#define EXITERR(...)			\
{					\
	WRAPOUT0("ERROR: ");		\
	WRAPOUT1(__VA_ARGS__);		\
	HERE;				\
	exit(1);			\
}

#define PERROR(reason)			\
{					\
	WRAPOUT0("PERROR: ");		\
	perror(reason);			\
	HERE;				\
	exit(1);			\
}

#define RETERR(...)			\
{					\
	WRAPOUT0("ERROR: ");		\
	WRAPOUT1(__VA_ARGS__);		\
	HERE;				\
	return -1;			\
}

#define CLEANERR(...)			\
{					\
	WRAPOUT0("ERROR: ");		\
	WRAPOUT1(__VA_ARGS__);		\
	HERE;				\
	goto cleanup;			\
}

#endif /* GENERAL_H_ */
