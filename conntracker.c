/*
 * (C) 2021 by Rafael David Tinoco <rafael.tinoco@ibm.com>
 * (C) 2021 by Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 */

#include "conntracker.h"
#include "general.h"
#include "flows.h"
#include "footprint.h"
#include "nlmsg.h"
#include "iptables.h"

GMainLoop *loop;

gint ulognlctiocbio_event_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	const char *prefix = NULL;

	struct nfgenmsg *nfg;
	struct nlattr *attrs[NFULA_MAX + 1] = { NULL };

	struct nf_conntrack *ct = NULL;
	struct footprint fp;

	// raw netlink msgs related to ulog (trace match)

	ret = nflog_nlmsg_parse(nlh, attrs);

	if (ret != MNL_CB_OK)
		EXITERR("nflog_nlmsg_parse");

	nfg = mnl_nlmsg_get_payload(nlh);

	if (attrs[NFULA_PREFIX])
		prefix = mnl_attr_get_str(attrs[NFULA_PREFIX]);

	if (prefix == NULL)
		EXITERR("mnl_attr_get_str");

	if (attrs[NFULA_CT] == NULL)
		return MNL_CB_OK;

	/*
	 * when receiving ulog netlink msgs from kernel (for TRACE) we have:
	 *
	 * TRACE: table:chain:type:position
	 *        [0]   [1]   [2]  [3]
	 */

	gchar **vector = g_strsplit_set((prefix+strlen("TRACE: ")), ":", -1);

	memset(&fp, 0, sizeof(struct footprint));

	// chain name

	g_strlcpy(fp.chain, vector[1], strlen(vector[1])+1);

	// table name

	if (g_ascii_strcasecmp("raw", vector[0]) == 0)
		fp.table = FOOTPRINT_TABLE_RAW;
	if (g_ascii_strcasecmp("mangle", vector[0]) == 0)
		fp.table = FOOTPRINT_TABLE_MANGLE;
	if (g_ascii_strcasecmp("nat", vector[0]) == 0)
		fp.table = FOOTPRINT_TABLE_NAT;
	if (g_ascii_strcasecmp("filter", vector[0]) == 0)
		fp.table = FOOTPRINT_TABLE_FILTER;
	if (fp.table == 0)
		fp.table = FOOTPRINT_TABLE_UNKNOWN;

	// rule type

	if (g_ascii_strcasecmp("policy", vector[2]) == 0)
		fp.type = FOOTPRINT_TYPE_POLICY;
	if (g_ascii_strcasecmp("rule", vector[2]) == 0)
		fp.type = FOOTPRINT_TYPE_RULE;
	if (g_ascii_strcasecmp("return", vector[2]) == 0)
		fp.type = FOOTPRINT_TYPE_RETURN;
	if (fp.type == 0)
		fp.type = FOOTPRINT_TYPE_UNKNOWN;

	// position of the rule

	fp.position = (uint32_t) ((long int) strtol(vector[3], NULL, 0));

	g_strfreev(vector);

	// conntrack data related, extracted from the netlink communication

	ct = nfct_new();

	if (ct == NULL)
		EXITERR("nfct_new");

	if (nfct_payload_parse(mnl_attr_get_payload(attrs[NFULA_CT]),
			       mnl_attr_get_payload_len(attrs[NFULA_CT]),
			       nfg->nfgen_family, ct) < 0)
		EXITERR("nfct_payload_parse");

	/*
	 * ready to call conntracio_event_cb (like) function to populate
	 * in-memory trees note: different than when calling from
	 * libnetfilter_conntrack path, this one includes the tracing data with
	 * a pointer to a local footprint struct (that shall be copied in the
	 * conntrackio_event_cb and kept in memory with the flow list items
	 */

	ret = conntrackio_event_cb(NF_NETLINK_CONNTRACK_UPDATE, ct, &fp);

	nfct_destroy(ct);

	return MNL_CB_OK;
}

gint conntrackio_event_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
	short reply = 0;

	uint8_t *family = NULL, *proto = NULL;
	uint16_t *psrc = NULL, *pdst = NULL;
	uint8_t *itype = NULL, *icode = NULL;
	uint32_t *constatus = NULL;
	struct in_addr ipv4src, ipv4dst;
	struct in6_addr *ipv6src = NULL, *ipv6dst = NULL;
	uint16_t privport = htons(1024);

	struct footprint *fp = data;

	// initialize to avoid compiler warnings

	memset(&ipv4src, 0, sizeof(struct in_addr));
	memset(&ipv4dst, 0, sizeof(struct in_addr));

	// check if flow ever got a reply from the peer

	constatus = (uint32_t *) nfct_get_attr(ct, ATTR_STATUS);

	if (*constatus & IPS_SEEN_REPLY)
		reply = 1;

	// skip address families other than IPv4 and IPv6

	family = (uint8_t *) nfct_get_attr(ct, ATTR_L3PROTO);

	switch (*family) {
	case AF_INET:
	case AF_INET6:
		break;
	default:
		return NFCT_CB_CONTINUE;
	}

	// skip IP protocols other than TCP / UDP / ICMP / ICMPv6

	proto = (uint8_t *) nfct_get_attr(ct, ATTR_L4PROTO);

	switch (*proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		break;
	default:
		return NFCT_CB_CONTINUE;
	}

	// netfilter: address family only attributes

	switch (*family) {
	case AF_INET:
		ipv4src.s_addr = *((in_addr_t *) nfct_get_attr(ct, ATTR_IPV4_SRC));
		ipv4dst.s_addr = *((in_addr_t *) nfct_get_attr(ct, ATTR_IPV4_DST));
		break;
	case AF_INET6:
		ipv6src = (struct in6_addr *) nfct_get_attr(ct, ATTR_IPV6_SRC);
		ipv6dst = (struct in6_addr *) nfct_get_attr(ct, ATTR_IPV6_DST);
		break;
	}

	// netfilter: protocol only attributes

	switch (*proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		psrc = (uint16_t *) nfct_get_attr(ct, ATTR_PORT_SRC);
		pdst = (uint16_t *) nfct_get_attr(ct, ATTR_PORT_DST);
		// NOTE: all unprivileged source ports logged as 1024
		if ((int) ntohs(*psrc) > 1024)
			psrc = &privport;
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		itype = (uint8_t *) nfct_get_attr(ct, ATTR_ICMP_TYPE);
		icode = (uint8_t *) nfct_get_attr(ct, ATTR_ICMP_CODE);
		break;
	}

	// store the flows in memory for further processing

	switch (*family) {
	case AF_INET:
		switch (*proto) {
		case IPPROTO_TCP:
			add_tcpv4flow(ipv4src, ipv4dst, *psrc, *pdst, reply);
			if (fp != NULL)
				add_tcpv4fp(ipv4src, ipv4dst, *psrc, *pdst, reply, fp);
			else
				add_tcpv4trace(ipv4src, ipv4dst, *psrc, *pdst, reply);
			break;
		case IPPROTO_UDP:
			add_udpv4flow(ipv4src, ipv4dst, *psrc, *pdst, reply);
			if (fp != NULL)
				add_udpv4fp(ipv4src, ipv4dst, *psrc, *pdst, reply, fp);
			else
				add_udpv4trace(ipv4src, ipv4dst, *psrc, *pdst, reply);
			break;
		case IPPROTO_ICMP:
			add_icmpv4flow(ipv4src, ipv4dst, *itype, *icode, reply);
			if (fp != NULL)
				add_icmpv4fp(ipv4src, ipv4dst, *itype, *icode, reply, fp);
			else
				add_icmpv4trace(ipv4src, ipv4dst, *itype, *icode, reply);
			break;
		}
		break;
	case AF_INET6:
		switch (*proto) {
		case IPPROTO_TCP:
			add_tcpv6flow(*ipv6src, *ipv6dst, *psrc, *pdst, reply);
			if (fp != NULL)
				add_tcpv6fp(*ipv6src, *ipv6dst, *psrc, *pdst, reply, fp);
			else
				add_tcpv6trace(*ipv6src, *ipv6dst, *psrc, *pdst, reply);
			break;
		case IPPROTO_UDP:
			add_udpv6flow(*ipv6src, *ipv6dst, *psrc, *pdst, reply);
			if (fp != NULL)
				add_udpv6fp(*ipv6src, *ipv6dst, *psrc, *pdst, reply, fp);
			else
				add_udpv6trace(*ipv6src, *ipv6dst, *psrc, *pdst, reply);
			break;
		case IPPROTO_ICMPV6:
			add_icmpv6flow(*ipv6src, *ipv6dst, *itype, *icode, reply);
			if (fp != NULL)
				add_icmpv6fp(*ipv6src, *ipv6dst, *itype, *icode, reply, fp);
			else
				add_icmpv6trace(*ipv6src, *ipv6dst, *itype, *icode, reply);
			break;
		}
		break;
	}

	return NFCT_CB_CONTINUE;
}

void trap(int what)
{
	cleanup();
	exit(0);
}

gboolean ulognlctiocb(GIOChannel *source, GIOCondition condition, gpointer data)
{
	// deal with ulog (+ conntrack) netfilter netlink messages

	gint ret;
	struct mnl_socket *ulognl = data;
	guint portid = mnl_socket_get_portid(ulognl);
	unsigned char buf[MNL_SOCKET_BUFFER_SIZE] __attribute__ ((aligned));

	ret = mnl_socket_recvfrom(ulognl, buf, sizeof(buf));

	if (ret < 0) {

		// try it again (buffer space issues)
		ret = mnl_socket_recvfrom(ulognl, buf, sizeof(buf));

		if (ret < 0) {
			// give up
			EXITERR("mnl_socket_recvfrom");
		}
	}

	ret = mnl_cb_run(buf, ret, 0, portid, ulognlctiocbio_event_cb, NULL);

	if (ret < 0)
		EXITERR("mnl_cb_run");

	return TRUE; // return FALSE to stop event
}

gboolean conntrackiocb(GIOChannel *source, GIOCondition condition, gpointer data)
{
	/*
	 * deal with conntrack netlink messages by using glib main loop
	 * instead of nfct_catch() approach from libnetfilter-conntrack
	 */

	gint ret;
	struct nfnl_handle *nfnlh = data;
	unsigned char buf[nfnlh->rcv_buffer_size] __attribute__ ((aligned));

	ret = nfnl_recv(nfnlh, buf, sizeof(buf));

	if (ret < 0 && errno != EINTR)
		EXITERR("nfnl_recv");

	ret = nfnl_process(nfnlh, buf, ret);

	if (ret <= NFNL_CB_STOP)
		EXITERR("nfnl_process");

	return TRUE; // return FALSE to stop event
}

int main(int argc, char **argv)
{
	int opt, ret = 0;
	gchar *outfile = NULL;

	GIOChannel *conntrackio;
	GIOChannel *ulognlctio;

	struct nfct_handle *nfcth;
	struct nfnl_handle *nfnlh;
	struct mnl_socket *ulognl;

	nfnetlink_start();

	ret |= iptables_cleanup();
	ret |= add_conntrack();

	if (ret == -1)
		EXITERR("add_conntrack()");

	loop = g_main_loop_new(NULL, FALSE);

	signal(SIGINT, trap);
	signal(SIGTERM, trap);

	amiadaemon = 0;

	while ((opt = getopt(argc, argv, "fdho:")) != -1)
		switch(opt) {
		case 'f':
			break;
		case 'd':
			amiadaemon = 1;
			break;
		case 'o':
			outfile = g_strdup(optarg);
			break;
		case 'h':
		default:
			g_fprintf(stdout,
				  "\n"
				  "Syntax: %s [options]\n"
				  "\n"
				  "\t[options]:\n"
				  "\n"
				  "\t-d: daemon mode        (syslog msgs, output file, kill pidfile)\n"
				  "\t-f: foreground mode    (stdout msgs, output file, ctrl+c, default)\n"
				  "\t-o: -o file.out        (output file, default: /tmp/conntracker.log)\n"
				  "\t    -o -               (standard output)\n"
				  "\n"
				  "* = default\n"
				  "\n",
				  argv[0]);
			exit(0);
		}

	if (outfile == NULL)
		outfile = g_strdup("/tmp/conntracker.log");

	initlog(outfile);

	alloc_flows();

	amiadaemon ? ret = makemeadaemon() : dontmakemeadaemon();

	if (ret == -1)
		EXITERR("makemeadaemon");

	// conntrack initialization

	nfcth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE);

	if (nfcth == NULL)
		EXITERR("nfct_open");

	nfct_callback_register(nfcth, NFCT_T_ALL, conntrackio_event_cb, NULL);

	// conntrack socket file descriptor callback

	nfnlh = (struct nfnl_handle *) nfct_nfnlh(nfcth);

	conntrackio = g_io_channel_unix_new(nfnlh->fd);
	g_io_add_watch(conntrackio, G_IO_IN, conntrackiocb, nfnlh);

	// netfilter ulog netlink (through libmnl) initialization

	ulognl = ulognlct_open();

	if (ulognl == NULL)
		EXITERR("ulognlct_open");

	ulognlctio = g_io_channel_unix_new(ulognl->fd);
	g_io_add_watch(ulognlctio, G_IO_IN, ulognlctiocb, ulognl);

	g_main_loop_run(loop);

	ret |= nfct_close(nfcth);
	ret |= ulognlct_close(ulognl);

	if (ret == -1)
		EXITERR("closing error")

	g_main_loop_unref(loop);

	cleanup();

	exit(0);
}
