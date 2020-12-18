# Connection Tracker / Firewall Rules Indicator

[Network Traffic Restrictions Document](https://ibm.box.com/s/78m9julsaaza20ebv389z5z5smutuhsn)<BR>
[CIO-1494: Conntracker Jira Card](https://jiracloud.swg.usma.ibm.com:8443/browse/CIO-1494)

## Problem

So you are **currently thinking about creating a set of firewall rules**,
perhaps setting REJECT as a default policy to your chains, but **you don't have
a clear picture of what is the traffic that you currently have**.

If you block too much you might end up having lots of complains about services
that used to work and does not work anymore. If you don't block enough you end
up having an insecure environment.

## Solutions

There are multiple ways you can understand the traffic passing through your firewall.

 1. One of the most common ways, that pops up to our head immediately, is to
    match some flows in our firewall and target them to the **LOG target
    plugin**. It will dump characteristics or matched packets into the syslog and
    you can further analyze it.

 2. Another way of doing it would be to use **better targets**, such as **NFLOG**...
    and gain some more flexibility using ulogd2 userland daemon. Just like the
    LOG target, you can get characteristics of matched packets into NFLOG kernel
    backend and have those delivered to ulogd2 userland daemon. With ulogd2 you
    can even write those logs into a database, or capture it in libpcap dump
    format.

 3. Of course... if you're on fire you might even chose to **tcpdump** your
    firewall. You would have to filter for packets initializing streams, sort
    them, filter garbage, etc.

## Making conntrack to do the dirt job

Those already familiar with netfilter and conntrack might already have thought
about using it to discover all conntrack events. So, instead of reinventing the
wheel, we call tell the kernel to track all the flows for us - at least for a
certain time - and get all the events out of it.

One way of doing it would be doing:

```
$ sudo conntrack -E -e NEW

    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=53798 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=53798
    [NEW] tcp      6 120 SYN_SENT src=192.168.100.118 dst=34.71.14.52 sport=40414 dport=443 [UNREPLIED] src=34.71.14.52 dst=192.168.200.2 sport=443 dport=40414
    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=33914 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=33914
    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=41433 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=41433
    [NEW] tcp      6 120 SYN_SENT src=192.168.100.118 dst=130.44.215.56 sport=40752 dport=80 [UNREPLIED] src=130.44.215.56 dst=192.168.200.2 sport=80 dport=40752
```

You can wrap all that information using a script, and extract all the relevant data - to knowing needed flows for your network - or you can use this tool. What this tool basically does is:

 * To rely on kernel conntrack mechanism to report all flows happening (you
   need to add a conntrack rule to your firewall).
 * Maintain an in-memory sorted/balanced btree of all flows
   (tcpv4/udpv4/icmpv4/tcpv6/udpv6/icmpv6) that happened during monitoring
   time.
 * Dump this list of all monitored flows in a consumable (sorted) way so you
   can understand what are the rules your firewall will need.

## Compiling it

In order to compile it you will need the following Debian/Ubuntu packages installed:

 * libnetfilter-conntrack-dev
 * libglib2.0-dev
 * pkg-config

In order to run it in another host you will need at least packages:

 * libnetfilter-conntrack3
 * libglib2.0-0

installed.

## Using it

After compiling the conntracker tool you will need to run it as root in your firewall. You can run it in foreground (the default mode) or in background (passing -d argument). If you run it in foreground, all the informational messages are going to be displayed in standard output. If you chose to run it as daemon, the information messages will be displayed in SYSLOG. In both cases, all the flows observed during the tool execution time will be written to a temporary file under /tmp. Observed flows are written in a sorted way so they can be consumed, by one who is willing to create firewall rules, more easily.


According to:

![](docs/netfilter.png)

The best places for you to activate connection tracking for are the PREROUTING and OUTPUT chains in the RAW table. Those are the best places because they are the first chains where packets from and to the host will pass through.

With that, an example of conntrack matching rules - to trigger the connection tracker for all possible flows, thus help our tool in finding the flows - is:


```
 $ sudo iptables -t raw -A PREROUTING -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
 $ sudo iptables -t raw -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
``` 

And if you also want to identify IPv6 flows:

```
 $ sudo ip6tables -t raw -A PREROUTING -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
 $ sudo ip6tables -t raw -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
```

**Note**: This tool depends on the netfilter conntrack kernel capabilities and, because of that, you need to have an iptables rule using conntrack as a matching module. For this example I am placing a generic conntrack match rule in the RAW table, making sure the “conntrack” module tracks all the flows and does it before any other rule in any chain, in any table.

### Foreground mode

```
$ sudo ./conntracker -f
Starting to capture conntrack events
Foreground mode...<Ctrl-C> or or SIG_TERM to end it.
Dumping internal data into: /tmp/conntracker.log
Finished capturing conntrack events

$ cat /tmp/conntracker.log
 TCPv4 [           0] src = 192.168.100.111 (port=1024) to dst = 157.240.12.54 (port=443) (confirmed)
 TCPv4 [           1] src = 192.168.100.118 (port=1024) to dst = 65.8.205.11 (port=443) (confirmed)
 TCPv4 [           2] src = 192.168.100.118 (port=1024) to dst = 192.48.236.11 (port=443) (confirmed)
 TCPv4 [           3] src = 192.168.100.118 (port=1024) to dst = 65.8.205.28 (port=443) (confirmed)
 TCPv4 [           4] src = 192.168.100.118 (port=1024) to dst = 65.8.205.49 (port=80) (confirmed)
 TCPv4 [           5] src = 192.168.100.118 (port=1024) to dst = 34.69.16.85 (port=443) (confirmed)
 TCPv4 [           6] src = 192.168.100.118 (port=1024) to dst = 65.8.205.93 (port=80) (confirmed)
 UDPv4 [           0] src = 0.0.0.0 (port=68) to dst = 255.255.255.255 (port=67)
 UDPv4 [           1] src = 192.168.100.123 (port=500) to dst = 200.169.116.51 (port=500) (confirmed)
 UDPv4 [           2] src = 192.168.100.152 (port=1024) to dst = 50.23.190.219 (port=50101) (confirmed)
 UDPv4 [           3] src = 192.168.100.203 (port=1024) to dst = 8.8.8.8 (port=53) (confirmed)
 UDPv4 [           4] src = 192.168.100.203 (port=1024) to dst = 172.217.29.10 (port=443) (confirmed)
 UDPv4 [           5] src = 192.168.100.203 (port=1024) to dst = 172.217.28.14 (port=443) (confirmed)
 UDPv4 [           6] src = 192.168.100.203 (port=1024) to dst = 216.58.202.14 (port=443) (confirmed)
ICMPv4 [           0] src = 192.168.100.152 to dst = 172.217.162.196 (type=0 | code=0) (confirmed)
```

### Daemon mode

```
$ sudo conntracker -d
Daemon mode. Check syslog for messages!

$ tail -1 /var/log/syslog
Dec  7 21:51:55 firewall conntracker[44982]: Starting to capture conntrack events

$ sudo kill $(pidof conntracker)

$ tail -2 /var/log/syslog
Dec  7 21:52:34 firewall conntracker[44984]: Dumping internal data into: /tmp/conntracker.log
Dec  7 21:52:34 firewall conntracker[44984]: Finished capturing conntrack events

$ cat /tmp/conntracker.log
...
```

**Note**: Note here that conntrack could be already being used by other tables, like mangle or nat. This will make the conntracker tool to keep track of all those flows as well. One way to solve this is to make the tool only observe connection trackings that have a specific mark set by CONNMARK target. This is a good workaround if the existing conntrack rules step into our way (TODO ?)

## Things to notice

The output of “conntracker” tool is self explanatory BUT some observations should be made:

  1. The output is **sorted** by **PROTOCOL** first, then by **SOURCE** ADDRESS, then by
     **DESTINATION** ADDRESS and finally by SOURCE and DESTINATION ports. This is
     on purpose so the person executing it is able to observe IPs of a same
     subnet mask close enough to decide if future iptables rules should be HOST
     or SUBNET oriented. (Example: I have observed 192.168.100.100 to
     192.168.100.254 hosts communicating to a destiny port 80... I can then
     decide to allow 192.168.100.0/24 subnet instead of having one rule per
     IP).

  2. Several (port=1024) can be observed. That happens because **ANY SOURCE PORT
     bigger than 1024 is set as “1024”**. This makes observability much easier as
     the source ports tend to be random enough to cause confusion when
     observing flows. So, if you see (port=1024) in a flow, it likely means
     that an unprivileged source port was used by the source IP to communicate
     with a destiny port of a remote host.

  3. At the end of each flow you can find the “**(confirmed)**” statement
     sometimes. This has different meanings depending on the protocol being
     reported:
   * **TCP**: “(confirmed)” means that there was a bidirectional communication in
    that flow or, in other words, both hosts send and received packets in a
    connection. The TCP case is easy because it is a connection oriented
    protocol and its easy to know if there is an ongoing connection (with ACKs
    being sent).
   * **UDP**: “(confirmed)” means that there was a bi-direction communication in that
    flow. It means that one peer sent an UDP packet from a source port to
    another peer in a destination port. The other peer responded from this same
    destination port to the source port of the first one. Note: differently
    than TCP, when we can know for sure the connection was NOT blocked, In UDP
    we cannot say that for sure since some hosts might only send UDP packets
    and they might be received by the other peer that does not need to respond
    (as there are no ACKs). With that... even the flows not stating
    “(confirmed)” should be taking in consideration when designing the firewall
    rules.
   * **ICMP**: Very similar to the UDP case but, as there are no ports in ICMP
    communication, the flows are tracked by their types and codes. Some types
    are replies to another, some replies have the same type but different
    codes, and so on. Example: If you see an ICMP flow of type 0 (ECHO REPLY)
    being logged and with a “(confirmed)” statement at the end... it means that
    there was an ICMP ECHO REQUEST tracked already coming from the opposite
    direction (thus the confirmed state).

  4. This tool is a **work-in-progress** and there are many possible TODOs (convert
    to a daemon, dump tables w/ SIGUSER, etc).
