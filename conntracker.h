/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#ifndef CONNTRACKER_H_
#define CONNTRACKER_H_

#include "general.h"

void cleanup(void);
void trap(int);

gint conntrackio_event_cb(enum nf_conntrack_msg_type, struct nf_conntrack *, void *);
gint ulognlctiocbio_event_cb(const struct nlmsghdr *, void *);

gboolean conntrackiocb(GIOChannel *, GIOCondition, gpointer);
gboolean ulognlctiocb(GIOChannel *, GIOCondition, gpointer);

// from libnfnetlink: libnfnetlink.c

struct nfnl_subsys_handle {
	struct nfnl_handle 	*nfnlh;
	uint32_t		subscriptions;
	uint8_t			subsys_id;
	uint8_t			cb_count;
	struct nfnl_callback 	*cb;
};

#define NFNL_MAX_SUBSYS 16

struct nfnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	uint32_t		subscriptions;
	uint32_t		seq;
	uint32_t		dump;
	uint32_t		rcv_buffer_size;
	uint32_t		flags;
	struct nlmsghdr 	*last_nlhdr;
	struct nfnl_subsys_handle subsys[NFNL_MAX_SUBSYS+1];
};

extern const struct nfnl_handle *nfct_nfnlh(struct nfct_handle *cth);

// from libmnl: socket.c

struct mnl_socket {
	int 			fd;
	struct sockaddr_nl	addr;
};

#endif /* CONNTRACKER_H_ */
