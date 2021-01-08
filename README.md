# Connection Tracker / Firewall Rules Indicator

## Problems

1. You need to build firewall rules for flows you don't know.
2. You need to understand what traffic goes through your firewall.
3. You need a firewall rule to blame for something (block/acceptance)

## Solutions

1. You can tcpdump/wireshark your firewall and be crazy.
2. You can match a flow and target to LOG plugin, observing tons of log entries.
3. You can use NFLOG target plugin together with ulogd2 daemon.

or you can use **conntracker**.

## Doing things by hand

Let's say you don't have conntracker. To have something similar to what it provides, you would have to:

1. Make conntracker do the dirty job: map/unmap existing networking flows. 

```
$ sudo iptables -t raw -I PREROUTING 1 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
$ sudo iptables -t raw -I OUTPUT 1 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
$ sudo ip6tables -t raw -I PREROUTING 1 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
$ sudo ip6tables -t raw -I OUTPUT 1 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
```

and to analyze the outcome:

```
$ sudo conntrack -E -e NEW

    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=53798 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=53798
    [NEW] tcp      6 120 SYN_SENT src=192.168.100.118 dst=34.71.14.52 sport=40414 dport=443 [UNREPLIED] src=34.71.14.52 dst=192.168.200.2 sport=443 dport=40414
    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=33914 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=33914
    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=41433 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=41433
    [NEW] tcp      6 120 SYN_SENT src=192.168.100.118 dst=130.44.215.56 sport=40752 dport=80 [UNREPLIED] src=130.44.215.56 dst=192.168.200.2 sport=80 dport=40752
```

sorting all the output by protocol, source/destination addresses and source/destination port numbers. This would tell you what firewall rules would have to exist in your firewall to allow the flows (or block them).

But this is just half of the problem. If you want to understand why a specific flow is being blocked, you would have to trace that flow and check through which firewall rules that flow is flowing.

To trace all networking flows, you could:

```
sudo iptables -t raw -A PREROUTING -j TRACE
sudo iptables -t raw -A OUTPUT-j TRACE
sudo ip6tables -t raw -A PREROUTING -j TRACE
sudo ip6tables -t raw -A OUTPUT-j TRACE
```

and observe kmsg:

```
[ 1934.356558] TRACE: raw:OUTPUT:policy:2 IN= OUT=home SRC=192.168.100.203 DST=192.168.100.153 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=26607 DF PROTO=TCP SPT=35310 DPT=22 SEQ=3621638314 ACK=4253970834 WINDOW=10016 RES=0x00 ACK URGP=0 OPT (0101080A938A85A902782273) UID=1000 GID=1000 
[ 1934.867689] TRACE: filter:OUTPUT:policy:1 IN= OUT=home SRC=192.168.100.203 DST=192.168.100.153 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=26608 DF PROTO=TCP SPT=35310 DPT=22 SEQ=3621638314 ACK=4253970990 WINDOW=10016 RES=0x00 ACK URGP=0 OPT (0101080A938A87A802782470) UID=1000 GID=1000 
[ 1935.393687] TRACE: raw:OUTPUT:policy:2 IN= OUT=home SRC=192.168.100.203 DST=192.168.100.153 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=26610 DF PROTO=TCP SPT=35310 DPT=22 SEQ=3621638406 ACK=4253971082 WINDOW=10016 RES=0x00 ACK URGP=0 OPT (0101080A938A89B60278267A) UID=1000 GID=1000 
[ 1935.687541] TRACE: filter:OUTPUT:policy:1 IN= OUT=home SRC=192.168.100.203 DST=192.168.100.153 LEN=52 TOS=0x10 PREC=0x00 TTL=64 ID=26611 DF PROTO=TCP SPT=35310 DPT=22 SEQ=3621638406 ACK=4253971238 WINDOW=10016 RES=0x00 ACK URGP=0 OPT (0101080A938A8ADC0278279B) UID=1000 GID=1000 
```


but then you would add too much work to your netfilter code, making kernel to inform about all flows being tracked by conntracker, for example. Correct thing to do would be to trace each flow for a specific amount of time, once its first seen, and then stop it. 

The **conntracker** tool does all that automatically.

## Compiling

In order to compile it you will need the following Ubuntu packages installed:

 * pkg-config
 * libglib2.0-dev
 * libmnl-dev
 * libnetfilter-conntrack-dev

In order to run it in another host you will need at least packages:

 * libglib2.0-0
 * libmnl0
 * libnetfilter-conntrack3

installed.

## Using

Easily follow 2 steps:

1. Execute conntracker either in foreground (-f, default) or as daemon (-d).
2. Read the log file: /tmp/conntracker.log.

The output of “conntracker” tool is self explanatory BUT some observations should be made:

  1. The output is **sorted** by **PROTOCOL** first, then by **SOURCE** ADDRESS, then by
     **DESTINATION** ADDRESS and finally by SOURCE and DESTINATION ports. This is
     on purpose so the person executing it is able to observe IPs of a same
     subnet mask close enough to decide if future iptables rules should be HOST
     or SUBNET oriented. (Example: I have observed 192.168.100.100 to
     192.168.100.254 hosts communicating to a destiny port 80... I can then
     decide to allow 192.168.100.0/24 subnet instead of having one rule per
     IP).

  2. In between the lines indicating each flow, you may find lines similar to:<BR><BR>
     `table: xxxx, chain: xxxx, type: xxxx, position: xxxx`<BR><BR>
     Possible values for "table" are: `raw, mangle, nat or filter`<BR>
     Possible values for "chain" are: `PREROUTING, POSTROUTING, FORWARD, INPUT, OUTPUT or custom`<BR>
     Possible values for "type" are: `policy, rule or return`<BR>
     <BR>
     those lines indicate that, for **conntracker** was able to trace netfilter rules and tables THAT flow passed through. Next thing to do is to observe the picture bellow so you know the path the flow had inside your netfilter:
     
  ![](docs/netfilter.png)

  3. Several (port=1024) can be observed. That happens because **ANY SOURCE PORT
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

## Example

```
$ sudo ./conntracker 
Starting to capture conntrack events
Foreground mode...<Ctrl-C> or or SIG_TERM to end it.
Dumping internal data into: /tmp/conntracker.log
Finished capturing conntrack/ulog events
```

To check what was observed during the execution of the tool, and through which netfilter tables and rules that flow passed through, you just have to check generated file:

```
$ cat /tmp/conntracker.log 
 TCPv4 [           0] src = 127.0.0.1 (port=1024) to dst = 127.0.0.1 (port=3128) (confirmed)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [           1] src = 10.250.97.1 (port=1024) to dst = 10.250.97.135 (port=22) (confirmed)
 TCPv4 [           2] src = 10.250.97.1 (port=1024) to dst = 10.250.97.135 (port=36576) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [           3] src = 10.250.97.1 (port=1024) to dst = 10.250.97.135 (port=36580) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [           4] src = 192.168.100.203 (port=1024) to dst = 35.186.224.12 (port=443) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
 TCPv4 [           5] src = 192.168.100.203 (port=1024) to dst = 192.168.100.13 (port=8009) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [           6] src = 192.168.100.203 (port=1024) to dst = 35.186.224.25 (port=443) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [           7] src = 192.168.100.203 (port=1024) to dst = 104.19.216.45 (port=443) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [           8] src = 192.168.100.203 (port=1024) to dst = 149.154.175.51 (port=443) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [           9] src = 192.168.100.203 (port=1024) to dst = 172.217.162.106 (port=443) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [          10] src = 192.168.100.203 (port=1024) to dst = 172.217.192.109 (port=993) (confirmed)
 TCPv4 [          11] src = 192.168.100.203 (port=1024) to dst = 172.217.173.110 (port=443) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [          12] src = 192.168.100.203 (port=1024) to dst = 162.213.33.129 (port=443) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [          13] src = 192.168.100.203 (port=1024) to dst = 192.168.100.153 (port=22) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 TCPv4 [          14] src = 192.168.100.203 (port=1024) to dst = 64.233.190.188 (port=5228) (confirmed)
                                table: filter, chain: INPUT, type: policy, position: 1
 TCPv4 [          15] src = 192.168.100.203 (port=1024) to dst = 192.168.100.251 (port=8080) (confirmed)
 UDPv4 [           0] src = 10.250.91.1 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [           1] src = 10.250.91.1 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [           2] src = 10.250.91.1 (port=1024) to dst = 10.250.91.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: policy, position: 2
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [           3] src = 10.250.92.1 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [           4] src = 10.250.92.1 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [           5] src = 10.250.92.1 (port=1024) to dst = 10.250.92.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: policy, position: 2
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [           6] src = 10.250.93.1 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [           7] src = 10.250.93.1 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [           8] src = 10.250.93.1 (port=1024) to dst = 10.250.93.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: policy, position: 2
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [           9] src = 10.250.94.1 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [          10] src = 10.250.94.1 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          11] src = 10.250.94.1 (port=1024) to dst = 10.250.94.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: policy, position: 2
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [          12] src = 10.250.95.1 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [          13] src = 10.250.95.1 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          14] src = 10.250.95.1 (port=1024) to dst = 10.250.95.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: policy, position: 2
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [          15] src = 10.250.96.1 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [          16] src = 10.250.96.1 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          17] src = 10.250.96.1 (port=1024) to dst = 10.250.96.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: policy, position: 2
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [          18] src = 10.250.97.1 (port=1024) to dst = 10.250.97.135 (port=41671)
 UDPv4 [          19] src = 10.250.97.1 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [          20] src = 10.250.97.1 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          21] src = 10.250.97.1 (port=1024) to dst = 10.250.97.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: rule, position: 1
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [          22] src = 192.168.200.1 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [          23] src = 192.168.150.3 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [          24] src = 192.168.150.3 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          25] src = 192.168.150.3 (port=1024) to dst = 192.168.150.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: policy, position: 2
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [          26] src = 192.168.200.3 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [          27] src = 192.168.200.3 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          28] src = 192.168.200.3 (port=1024) to dst = 192.168.200.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: policy, position: 2
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [          29] src = 192.168.100.13 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [          30] src = 192.168.100.13 (port=1024) to dst = 239.255.255.250 (port=1902)
 UDPv4 [          31] src = 192.168.100.13 (port=1024) to dst = 224.0.0.251 (port=5353)
                                table: nat, chain: INPUT, type: policy, position: 1
                                table: nat, chain: PREROUTING, type: policy, position: 1
                                table: filter, chain: INPUT, type: policy, position: 1
 UDPv4 [          32] src = 192.168.100.14 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          33] src = 192.168.100.128 (port=1024) to dst = 224.0.0.251 (port=5353)
                                table: filter, chain: INPUT, type: policy, position: 1
 UDPv4 [          34] src = 192.168.100.131 (port=1024) to dst = 224.0.0.251 (port=5353)
                                table: filter, chain: INPUT, type: policy, position: 1
 UDPv4 [          35] src = 10.250.97.135 (port=1024) to dst = 192.168.100.203 (port=1234)
 UDPv4 [          36] src = 10.250.97.135 (port=1024) to dst = 192.168.100.251 (port=53) (confirmed)
 UDPv4 [          37] src = 192.168.100.150 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          38] src = 192.168.100.153 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          39] src = 192.168.100.203 (port=1024) to dst = 239.255.255.250 (port=1900)
 UDPv4 [          40] src = 192.168.100.203 (port=1024) to dst = 224.0.0.251 (port=5353)
 UDPv4 [          41] src = 192.168.100.203 (port=1024) to dst = 192.168.100.255 (port=57621)
                                table: raw, chain: PREROUTING, type: rule, position: 1
                                table: nat, chain: OUTPUT, type: policy, position: 1
                                table: nat, chain: POSTROUTING, type: policy, position: 2
                                table: filter, chain: INPUT, type: policy, position: 1
                                table: filter, chain: OUTPUT, type: policy, position: 1
 UDPv4 [          42] src = 192.168.100.251 (port=1024) to dst = 192.168.100.203 (port=53570)
 UDPv4 [          43] src = 192.168.100.251 (port=1024) to dst = 192.168.100.203 (port=40569)
 UDPv4 [          44] src = 192.168.100.251 (port=1024) to dst = 192.168.100.203 (port=50150)
 UDPv4 [          45] src = 192.168.100.251 (port=1024) to dst = 192.168.100.203 (port=48126)
 UDPv4 [          46] src = 192.168.100.251 (port=1024) to dst = 239.255.255.250 (port=1900)
ICMPv4 [           0] src = 192.168.100.203 to dst = 8.8.8.8 (type=0 | code=0) (confirmed)
 TCPv6 [           0] src = fe80::1453:5dff:fe1a:ca68 (port=1024) to dst = fe80::216:3eff:fe7f:aedd (port=22) (confirmed)
ICMPv6 [           0] src = fe80::1453:5dff:fe1a:ca68 to dst = fe80::216:3eff:fe7f:aedd (type=0 | code=0) (confirmed)
ICMPv6 [           1] src = fe80::1453:5dff:fe1a:ca68 to dst = fe80::3c76:fdff:fea2:82b4 (type=0 | code=0)
```

If I want to only see IPv4 flows, with no trace output, for example, you might work with grep:

```
$ cat /tmp/conntracker.log | egrep -E "^\s+TCPv4"
 TCPv4 [           0] src = 127.0.0.1 (port=1024) to dst = 127.0.0.1 (port=3128) (confirmed)
 TCPv4 [           1] src = 10.250.97.1 (port=1024) to dst = 10.250.97.135 (port=22) (confirmed)
 TCPv4 [           2] src = 10.250.97.1 (port=1024) to dst = 10.250.97.135 (port=36576) (confirmed)
 TCPv4 [           3] src = 10.250.97.1 (port=1024) to dst = 10.250.97.135 (port=36580) (confirmed)
 TCPv4 [           4] src = 192.168.100.203 (port=1024) to dst = 35.186.224.12 (port=443) (confirmed)
 TCPv4 [           5] src = 192.168.100.203 (port=1024) to dst = 192.168.100.13 (port=8009) (confirmed)
 TCPv4 [           6] src = 192.168.100.203 (port=1024) to dst = 35.186.224.25 (port=443) (confirmed)
 TCPv4 [           7] src = 192.168.100.203 (port=1024) to dst = 104.19.216.45 (port=443) (confirmed)
 TCPv4 [           8] src = 192.168.100.203 (port=1024) to dst = 149.154.175.51 (port=443) (confirmed)
 TCPv4 [           9] src = 192.168.100.203 (port=1024) to dst = 172.217.162.106 (port=443) (confirmed)
 TCPv4 [          10] src = 192.168.100.203 (port=1024) to dst = 172.217.192.109 (port=993) (confirmed)
 TCPv4 [          11] src = 192.168.100.203 (port=1024) to dst = 172.217.173.110 (port=443) (confirmed)
 TCPv4 [          12] src = 192.168.100.203 (port=1024) to dst = 162.213.33.129 (port=443) (confirmed)
 TCPv4 [          13] src = 192.168.100.203 (port=1024) to dst = 192.168.100.153 (port=22) (confirmed)
 TCPv4 [          14] src = 192.168.100.203 (port=1024) to dst = 64.233.190.188 (port=5228) (confirmed)
 TCPv4 [          15] src = 192.168.100.203 (port=1024) to dst = 192.168.100.251 (port=8080) (confirmed)
```
  
> Note: Like said previously, all the output is sorted by protocol, source and destination addresses. This makes your life - of creating/identifying firewall rules - much easier.