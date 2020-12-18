#ifndef NLMSG_H_
#define NLMSG_H_

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

#include <linux/netlink.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <linux/netfilter/nfnetlink_log.h>

struct mnl_socket *ulognlct_open(void);
int ulognlct_close(struct mnl_socket *);

struct nlmsghdr * nflog_nlmsg_put_header(char *, uint8_t, uint8_t, uint16_t);
int nflog_attr_put_cfg_mode(struct nlmsghdr *, uint8_t, uint32_t);
int nflog_attr_put_cfg_cmd(struct nlmsghdr *, uint8_t);
int nflog_nlmsg_parse(const struct nlmsghdr *, struct nlattr **);

#endif /* NLMSG_H_ */
