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

#include <gmodule.h>
#include <glib/gprintf.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

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

#define WRAPOUT(...)										\
{												\
	switch (amiadaemon) {									\
	case 0:											\
		g_fprintf(stdout, __VA_ARGS__);							\
		g_fprintf(stdout, "\n");							\
		break;										\
	case 1:											\
		syslog(LOG_USER | LOG_INFO, __VA_ARGS__);					\
		break;										\
	}											\
}

#define HERE WRAPOUT("line %d, file %s, function %s\n", __LINE__, __FILE__, __func__)

#define EXITERR(reason)										\
{												\
	perror(reason);										\
	HERE;											\
	cleanup();										\
	exit(1);										\
}

#endif /* GENERAL_H_ */
