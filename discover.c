#include "discover.h"

// cat here is being piped to so it can mitigate LP: #1913187 (Bionic)
char *sscmd = "ss -Hnp -o state established '( dport = %d )' src %s dst %s | cat -";

gchar *disc_app_oper(gchar *src, gchar *dst, uint16_t dport)
{
	FILE *wrap;

	gchar *buffer;
	gchar *comando;
	gchar *temp;
	gchar **vector;
	gchar *ret = NULL;

	buffer = g_malloc0(1024);
	comando = g_strdup_printf(sscmd, dport, src, dst);

	wrap = popen(comando, "r");
	temp = fgets(buffer, 1024, wrap);
	pclose(wrap);

	if (!temp)
		goto nothing;

	g_strstrip(buffer);

	if (strlen(buffer) == 0)
		goto nothing;

	temp = g_strstr_len(buffer, strlen(buffer), "users:");

	if ((!temp) || strlen(temp) == 0)
		goto nothing;

	vector = g_strsplit_set(temp, "\"", 3);

	if (!vector || !vector[0] || !vector[1] || strlen(vector[1]) == 0)
		goto nothing1;

	ret = g_strdup(vector[1]);

nothing1:

	g_strfreev(vector);

nothing:
	g_free(comando);
	g_free(buffer);

	return ret;
}

// ----

gint disc_app_tcpv4flow(struct tcpv4flow *flow)
{
	gint ret = 0;

	gchar *src = ipv4_str(&flow->addrs.src);
	gchar *dst = ipv4_str(&flow->addrs.dst);
	uint16_t dport = ntohs(flow->base.dst);

	if (!flow->foots.cmd)
		flow->foots.cmd = disc_app_oper(src, dst, dport);

	g_free(src);
	g_free(dst);

	return ret;
}
