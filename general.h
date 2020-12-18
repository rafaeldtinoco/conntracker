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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <gmodule.h>
#include <glib/gprintf.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define SUCCESS 0
#define ERROR -1

#define LESS -1
#define EQUAL 0
#define MORE 1

#define HERE printf("line %d, file %s, function %s\n", __LINE__, __FILE__, __func__)

extern int amiadaemon;

int makemeadaemon(void);
int dontmakemeadaemon(void);
void initlog(char *);
void endlog(void);
void out_logfile(void);
void debug(char *);

/* log functions */

#define syslogwrap(...)										\
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

#endif /* GENERAL_H_ */
