#include "conntracker.h"
#include "general.h"
#include "flows.h"
#include "nlmsg.h"

static gint ulognlctiocbio_event_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	uint32_t mark = 0;
	const char *prefix = NULL;

	struct nfgenmsg *nfg;
	struct nlattr *attrs[NFULA_MAX + 1] = { NULL };
	struct nfulnl_msg_packet_hdr *ph = NULL;

	struct nf_conntrack *ct = NULL;
	struct footprint fp;

	/* raw netlink msgs related to ulog (trace match) */

	ret = nflog_nlmsg_parse(nlh, attrs);
	if (ret != MNL_CB_OK)
		return ret;

	nfg = mnl_nlmsg_get_payload(nlh);

	if (attrs[NFULA_PREFIX])
		prefix = mnl_attr_get_str(attrs[NFULA_PREFIX]);

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

	/* chain name */

	g_strlcpy(fp.chain, vector[1], strlen(vector[1]));

	/* table name */

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

	/* rule type */

	if (g_ascii_strcasecmp("policy", vector[2]) == 0)
		fp.table = FOOTPRINT_TYPE_POLICY;
	if (g_ascii_strcasecmp("rule", vector[2]) == 0)
		fp.table = FOOTPRINT_TYPE_RULE;
	if (g_ascii_strcasecmp("return", vector[2]) == 0)
		fp.table = FOOTPRINT_TYPE_RETURN;
	if (fp.type == 0)
		fp.type = FOOTPRINT_TYPE_UNKNOWN;

	/* position of the rule */

	fp.position = (uint32_t) ((long int) strtol(vector[3], NULL, 0));

	g_strfreev(vector);

	/* conntrack data related, extracted from the netlink communication */

	ct = nfct_new();

	if (ct == NULL)
		return MNL_CB_ERROR;

	if (nfct_payload_parse(mnl_attr_get_payload(attrs[NFULA_CT]),
			       mnl_attr_get_payload_len(attrs[NFULA_CT]),
			       nfg->nfgen_family, ct) < 0) {
		return MNL_CB_ERROR;
	}

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

static gint conntrackio_event_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
	short reply = 0;

	uint8_t *family = NULL, *proto = NULL;
	uint16_t *port_src = NULL, *port_dst = NULL;
	uint8_t *itype = NULL, *icode = NULL;
	uint32_t *constatus = NULL;
	struct in_addr ipv4_src_in, ipv4_dst_in;
	struct in6_addr *ipv6_src_in = NULL, *ipv6_dst_in = NULL;
	uint16_t privport = htons(1024);

	/* initialize to avoid compiler warnings */

	memset(&ipv4_src_in, 0, sizeof(struct in_addr));
	memset(&ipv4_dst_in, 0, sizeof(struct in_addr));

	/* check if flow ever got a reply from the peer */

	constatus = (uint32_t *) nfct_get_attr(ct, ATTR_STATUS);

	if (*constatus & IPS_SEEN_REPLY)
		reply = 1;

	/* skip address families other than IPv4 and IPv6 */

	family = (uint8_t *) nfct_get_attr(ct, ATTR_L3PROTO);

	switch (*family) {
	case AF_INET:
	case AF_INET6:
		break;
	default:
		debug("skipping non AF_INET/AF_INET6 traffic");
		return NFCT_CB_CONTINUE;
	}

	/* skip IP protocols other than TCP / UDP / ICMP / ICMPv6 */

	proto = (uint8_t *) nfct_get_attr(ct, ATTR_L4PROTO);

	switch (*proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		break;
	default:
		debug("skipping non UDP/TCP/ICMP/ICMPv6 traffic");
		return NFCT_CB_CONTINUE;
	}

	/* netfilter: address family only attributes */

	switch (*family) {
	case AF_INET:
		ipv4_src_in.s_addr = *((in_addr_t *) nfct_get_attr(ct, ATTR_IPV4_SRC));
		ipv4_dst_in.s_addr = *((in_addr_t *) nfct_get_attr(ct, ATTR_IPV4_DST));
		break;
	case AF_INET6:
		ipv6_src_in = (struct in6_addr *) nfct_get_attr(ct, ATTR_IPV6_SRC);
		ipv6_dst_in = (struct in6_addr *) nfct_get_attr(ct, ATTR_IPV6_DST);
		break;
	}

	/* netfilter: protocol only attributes */

	switch (*proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		port_src = (uint16_t *) nfct_get_attr(ct, ATTR_PORT_SRC);
		port_dst = (uint16_t *) nfct_get_attr(ct, ATTR_PORT_DST);
		/* all unprivileged source ports logged as 1024 */
		if ((int) ntohs(*port_src) > 1024)
			port_src = &privport;
		// printf("source: %s (port: %u)\n", inet_ntoa(ipv4_src_in), ntohs(*port_src));
		// printf("destination: %s (port: %u)\n", inet_ntoa(ipv4_dst_in), ntohs(*port_dst));
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		itype = (uint8_t *) nfct_get_attr(ct, ATTR_ICMP_TYPE);
		icode = (uint8_t *) nfct_get_attr(ct, ATTR_ICMP_CODE);
		break;
	}

	/* store the flows in memory for further processing */

	switch (*family) {
	case AF_INET:
		switch (*proto) {
		case IPPROTO_TCP:
			addtcpv4flow(ipv4_src_in, ipv4_dst_in, *port_src, *port_dst, reply);
			break;
		case IPPROTO_UDP:
			addudpv4flow(ipv4_src_in, ipv4_dst_in, *port_src, *port_dst, reply);
			break;
		case IPPROTO_ICMP:
			addicmpv4flow(ipv4_src_in, ipv4_dst_in, *itype, *icode, reply);
			break;
		}
		break;
	case AF_INET6:
		switch (*proto) {
		case IPPROTO_TCP:
			addtcpv6flow(*ipv6_src_in, *ipv6_dst_in, *port_src, *port_dst, reply);
			break;
		case IPPROTO_UDP:
			addudpv6flow(*ipv6_src_in, *ipv6_dst_in, *port_src, *port_dst, reply);
			break;
		case IPPROTO_ICMPV6:
			addicmpv6flow(*ipv6_src_in, *ipv6_dst_in, *itype, *icode, reply);
			break;
		}
		break;
	}

	return NFCT_CB_CONTINUE;
}

void cleanup(void)
{
	out_all();
	free_flows();
	endlog();
}

void trap(int what)
{
	cleanup();
	exit(SUCCESS);
}

gboolean ulognlctiocb(GIOChannel *source, GIOCondition condition, gpointer data)
{
	/* deal with ulog (+ conntrack) netfilter netlink messages */

	gint ret;
	struct mnl_socket *ulognl = data;
	guint portid = mnl_socket_get_portid(ulognl);
	unsigned char buf[MNL_SOCKET_BUFFER_SIZE] __attribute__ ((aligned));

	ret = mnl_socket_recvfrom(ulognl, buf, sizeof(buf));

	if (ret < 0)
		return FALSE;

	ret = mnl_cb_run(buf, ret, 0, portid, ulognlctiocbio_event_cb, NULL);

	if (ret < 0)
		return FALSE;

	/* return FALSE to stop event source */
	return TRUE;
}

gboolean conntrackiocb(GIOChannel *source, GIOCondition condition, gpointer data)
{
	/* deal with conntrack netlink messages by using glib main loop
	 * instead of nfct_catch() approach from libnetfilter-conntrack
	 */

	gint ret;
	struct nfnl_handle *nfnlh = data;
	unsigned char buf[nfnlh->rcv_buffer_size] __attribute__ ((aligned));

	ret = nfnl_recv(nfnlh, buf, sizeof(buf));

	if (ret < 0 && errno != EINTR)
		return FALSE;

	ret = nfnl_process(nfnlh, buf, ret);

	if (ret <= NFNL_CB_STOP)
		return FALSE;

	/* return FALSE to stop event source */
	return TRUE;
}

int main(int argc, char **argv)
{
	int opt, ret = 0;
	guint conntrackioid;
	guint ulognlctioid;

	GIOChannel *conntrackio;
	GIOChannel *ulognlctio;

	struct nfct_handle *nfcth;
	struct nfnl_handle *nfnlh;
	struct mnl_socket *ulognl;

	GMainLoop *loop;

	loop = g_main_loop_new(NULL, FALSE);

	signal(SIGINT, trap);
	signal(SIGTERM, trap);

	while ((opt = getopt(argc, argv, "df")) != -1)
		switch(opt) {
		case 'f':
			amiadaemon = 0;
			break;
		case 'd':
			amiadaemon = 1;
			break;
		default:
			g_fprintf(stdout, "Syntax: %s -[f|d] for foreground/daemon mode\n", argv[0]);
			exit(SUCCESS);
		}

	initlog(argv[0]);
	alloc_flows();

	amiadaemon ? makemeadaemon() : dontmakemeadaemon();

	/* conntrack initialization */

	nfcth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE);
	if (!nfcth) {
		perror("nfct_open");
		ret = EXIT_FAILURE;
		goto endclean;
	}

	nfct_callback_register(nfcth, NFCT_T_ALL, conntrackio_event_cb, NULL);

	/* conntrack socket file descriptor callback */

	nfnlh = (struct nfnl_handle *) nfct_nfnlh(nfcth);

	conntrackio = g_io_channel_unix_new(nfnlh->fd);
	//conntrackioid = g_io_add_watch(conntrackio, G_IO_IN, conntrackiocb, nfnlh);

	/* netfilter ulog netlink (through libmnl) initialization */

	ulognl = ulognlct_open();
	if (ulognl == NULL) {
		ret = EXIT_FAILURE;
		goto endclean;
	}

	ulognlctio = g_io_channel_unix_new(ulognl->fd);
	ulognlctioid = g_io_add_watch(ulognlctio, G_IO_IN, ulognlctiocb, ulognl);

	g_main_loop_run(loop);

	ret |= nfct_close(nfcth);

	ret |= ulognlct_close(ulognl);

	g_main_loop_unref(loop);

endclean:

	cleanup();

	exit(ret);
}
