# Connection Tracker / Firewall Rules Indicator

## Problems

1. Monitor host application's connections;
2. Understand the traffic from host (or firewall);
3. Create iptables (or nf_tables) rules;
4. Blame a firewall rule for a behavior (accept/deny);
5. Optimize your firewall rules;

## Solutions

1. You can tcpdump/wireshark your firewall and be crazy.
2. You can match a flow and target to LOG plugin, observing tons of log entries.
3. You can use NFLOG target plugin together with ulogd2 daemon.

or you can use **conntracker**.

## Doing things by hand

Let's say you don't have conntracker. To have something similar to what it provides, you would have to:

1. Make conntracker do the dirty job: map/unmap existing networking flows. 

```
*nat
:PREROUTING ACCEPT [190:33697]
:INPUT ACCEPT [65:12120]
:OUTPUT ACCEPT [404:50597]
:POSTROUTING ACCEPT [386:47349]
COMMIT
*raw
:PREROUTING ACCEPT [50:67129]
:OUTPUT ACCEPT [40:2928]
COMMIT
*mangle
:PREROUTING ACCEPT [242:293814]
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:POSTROUTING ACCEPT [272:34654]
-A PREROUTING -m conntrack --ctdir REPLY -j NFLOG
-A INPUT -p udp -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p tcp -j ACCEPT
-A FORWARD -m conntrack --ctstate INVALID,NEW,RELATED,ESTABLISHED,UNTRACKED,SNAT,DNAT -j NFLOG
-A FORWARD -p udp -j ACCEPT
-A FORWARD -p icmp -j ACCEPT
-A FORWARD -p ipv6-icmp -j ACCEPT
-A FORWARD -p tcp -j ACCEPT
-A OUTPUT -m conntrack --ctdir ORIGINAL -j NFLOG
-A OUTPUT -p udp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT
-A OUTPUT -p ipv6-icmp -j ACCEPT
-A OUTPUT -p tcp -j ACCEPT
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -p udp -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p tcp -j ACCEPT
-A FORWARD -p udp -j ACCEPT
-A FORWARD -p icmp -j ACCEPT
-A FORWARD -p ipv6-icmp -j ACCEPT
-A FORWARD -p tcp -j ACCEPT
-A OUTPUT -p udp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT
-A OUTPUT -p ipv6-icmp -j ACCEPT
-A OUTPUT -p tcp -j ACCEPT
COMMIT
```

and to analyze the outcome:

```
# conntrack -E -e NEW

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
# iptables -t raw -A PREROUTING -j TRACE
# iptables -t raw -A OUTPUT-j TRACE
# ip6tables -t raw -A PREROUTING -j TRACE
# ip6tables -t raw -A OUTPUT-j TRACE
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

```
$ ./configure --prefix=/usr --enable-debug
generating makefile ...
configuration complete, type make to build.

$ make
cc -MMD -Wall -O2 -g -ggdb -DEBUG `pkg-config --cflags glib-2.0`   -c -o conntracker.o conntracker.c
cc -MMD -Wall -O2 -g -ggdb -DEBUG `pkg-config --cflags glib-2.0`   -c -o flows.o flows.c
cc -MMD -Wall -O2 -g -ggdb -DEBUG `pkg-config --cflags glib-2.0`   -c -o footprint.o footprint.c
cc -MMD -Wall -O2 -g -ggdb -DEBUG `pkg-config --cflags glib-2.0`   -c -o general.o general.c
cc -MMD -Wall -O2 -g -ggdb -DEBUG `pkg-config --cflags glib-2.0`   -c -o iptables.o iptables.c
cc -MMD -Wall -O2 -g -ggdb -DEBUG `pkg-config --cflags glib-2.0`   -c -o nlmsg.o nlmsg.c
cc -o conntracker conntracker.o flows.o footprint.o general.o iptables.o nlmsg.o `pkg-config --libs glib-2.0` `pkg-config --libs libmnl` `pkg-config --libs libnetfilter_conntrack`
```

## Installing

Makefile will install compiled binary in $prefix/bin directory:

```
$ sudo make install
mkdir -p /usr/bin
cp conntracker /usr/bin/conntracker
```

and uninstall it as well:

```
$ sudo make uninstall
rm -f /usr/bin/conntracker
```

## Installing Packages

This will install the "conntracker" PPA with stable packages:

```
$ sudo add-apt-repository ppa:conntracker/stable
Note: PPA publishes dbgsym
  You need to add 'main/debug' component to install the ddebs,
  but apt update will print warning if the PPA has no ddebs
Repository: 'deb http://ppa.launchpad.net/conntracker/stable/ubuntu/ groovy main'
More info: https://launchpad.net/~conntracker/+archive/ubuntu/stable
Adding repository.
Press [ENTER] to continue or Ctrl-c to cancel.
```

After installing the PPA you can install the conntracker package:

```
$ sudo apt-get update
$ sudo apt-get install conntracker
$ sudo conntracker
```

And you will get automatic updates every time there is one.

## Installing Manually

If you don't want to add the PPA through "add-apt-repository", you may add the repository key manually, update your sources.list file:

```
$ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys AE4B4EA33C3DAE9E441E256C6B25BC6DF8365E53
$ echo "deb http://ppa.launchpad.net/conntracker/stable/ubuntu/ `lsb_release -cs` main" | sudo tee -a /etc/apt/sources.list
```

And install the binary package:

```
$ sudo apt-get update
$ sudo apt-get install conntracker
$ sudo conntracker
```

## Using

Easily follow 2 steps:

1. Execute conntracker [options]:

```
# ./conntracker -h

Syntax: ./conntracker [options]

        [options]:

        -d: daemon mode        (syslog msgs, output file, kill pidfile)
        -f: foreground mode    (stdout msgs, output file, ctrl+c, default)
        -o: -o file.out        (output file, default: /tmp/conntracker.log)
            -o -               (standard output)
        -c: conntrack only     (disable flow tracing feature)
        -e: trace everything   (trace all packets)

        1) Default options:

           - only ALLOWED packets are tracked and traced.
           - will see IPs, ports and protocols (flows).
           - will see by which tables/chains the flow pass through.
           - DROPPED/REJECTED packets are not seen!

        2) With -c option:

           - only ALLOWED packets are tracked and traced.
           - will see IPs, ports and protocols (flows).
           - will see flows only, no traces!
           - DROPPED/REJECTED packets are not seen!
           - best option for non existing rules.

        3) With -e option:

           - ALL packets are tracked and traced.
           - will see IPs, ports and protocols (flows).
           - will see by which tables/chains the flow pass through.
           - DROPPED/REJECTED packets will be traced!
           - best option for existing rules! (which rule to blame for DROP)

        Note: Option (3) is the best one but it is more intrusive
              and for that reason it is not the default one!

        Note: You may experience full socket buffer errors when running this.
              Unfortunately thats because kernel talks too much sometimes =o)

Check https://rafaeldtinoco.github.io/conntracker/ for more info!
```

2. Read generated file (or output).

### Output File

The output of “conntracker” tool is self explanatory BUT some observations should be made:

  1. The output is **sorted** by **PROTOCOL** first, then by **SOURCE ADDRESS**, then by
     **DESTINATION ADDRESS** and finally by **SOURCE** and **DESTINATION PORTS**. This is
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
     those lines indicate that **conntracker** was able to trace netfilter rules and tables THAT flow passed through.

     **OBSERVE THE PICTURE BELLOW AND MATCH THE TRACES**

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
 TCPv4 [           0] src = 10.250.97.1 (port=1024) to dst = 10.250.97.143 (port=22) (confirmed)
                                table: mangle, chain: OUTPUT, type: rule, position: 0
                                table: mangle, chain: OUTPUT, type: rule, position: 4
                                table: mangle, chain: POSTROUTING, type: policy
                                table: filter, chain: OUTPUT, type: rule, position: 4
 TCPv4 [           1] src = 192.168.100.203 (port=1024) to dst = 162.213.33.134 (port=443) (confirmed)
                                table: mangle, chain: OUTPUT, type: rule, position: 0
                                table: mangle, chain: OUTPUT, type: rule, position: 4
                                table: mangle, chain: POSTROUTING, type: policy
                                table: filter, chain: OUTPUT, type: rule, position: 4
 UDPv4 [           0] src = 127.0.0.1 (port=1024) to dst = 127.0.0.1 (port=53) (confirmed)
 UDPv4 [           1] src = 192.168.100.13 (port=1024) to dst = 224.0.0.251 (port=5353)
                                table: mangle, chain: INPUT, type: rule, position: 1
                                table: mangle, chain: PREROUTING, type: policy
                                table: filter, chain: INPUT, type: rule, position: 1
 UDPv4 [           2] src = 10.250.97.143 (port=1024) to dst = 8.8.8.8 (port=53) (confirmed)
                                table: mangle, chain: FORWARD, type: rule, position: 0
                                table: mangle, chain: FORWARD, type: rule, position: 1
                                table: mangle, chain: POSTROUTING, type: policy
                                table: mangle, chain: PREROUTING, type: policy
                                table: filter, chain: FORWARD, type: rule, position: 1
 UDPv4 [           3] src = 192.168.100.251 (port=1024) to dst = 224.0.0.251 (port=5353)
                                table: mangle, chain: INPUT, type: rule, position: 1
                                table: mangle, chain: PREROUTING, type: policy
                                table: filter, chain: INPUT, type: rule, position: 1
ICMPv4 [           0] src = 10.250.97.143 to dst = 8.8.4.4 (type=0 | code=0) (confirmed)
                                table: mangle, chain: FORWARD, type: rule, position: 0
                                table: mangle, chain: FORWARD, type: rule, position: 2
                                table: mangle, chain: POSTROUTING, type: policy
                                table: mangle, chain: PREROUTING, type: policy
                                table: filter, chain: FORWARD, type: rule, position: 2
ICMPv4 [           1] src = 10.250.97.143 to dst = 8.8.8.8 (type=0 | code=0) (confirmed)
                                table: mangle, chain: FORWARD, type: rule, position: 0
                                table: mangle, chain: FORWARD, type: rule, position: 2
                                table: mangle, chain: POSTROUTING, type: policy
                                table: mangle, chain: PREROUTING, type: policy
                                table: filter, chain: FORWARD, type: rule, position: 2
ICMPv4 [           2] src = 192.168.100.203 to dst = 8.8.4.4 (type=0 | code=0) (confirmed)
                                table: mangle, chain: OUTPUT, type: rule, position: 0
                                table: mangle, chain: OUTPUT, type: rule, position: 2
                                table: mangle, chain: POSTROUTING, type: policy
                                table: filter, chain: OUTPUT, type: rule, position: 2
ICMPv4 [           3] src = 192.168.100.203 to dst = 8.8.8.8 (type=0 | code=0) (confirmed)
                                table: mangle, chain: OUTPUT, type: rule, position: 0
                                table: mangle, chain: OUTPUT, type: rule, position: 2
                                table: mangle, chain: POSTROUTING, type: policy
                                table: filter, chain: OUTPUT, type: rule, position: 2
 TCPv6 [           0] src = fe80::da:ddff:fe1a:bcd (port=1024) to dst = fe80::5054:ff:fe8d:ad04 (port=22) (confirmed)
                                table: mangle, chain: OUTPUT, type: rule, position: 0
                                table: mangle, chain: OUTPUT, type: rule, position: 4
                                table: mangle, chain: POSTROUTING, type: policy
                                table: filter, chain: OUTPUT, type: rule, position: 4
ICMPv6 [           0] src = fe80::da:ddff:fe1a:bcd to dst = fe80::5054:ff:fe8d:ad04 (type=0 | code=0) (confirmed)
                                table: mangle, chain: OUTPUT, type: rule, position: 0
                                table: mangle, chain: OUTPUT, type: rule, position: 3
                                table: mangle, chain: POSTROUTING, type: policy
                                table: filter, chain: OUTPUT, type: rule, position: 3
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

## Compatibility

The **conntracker** tool has been tested in Ubuntu Linux Groovy, Focal and Bionic using iptables.

** PAY ATTENTION **: Latest Ubuntus support both:

- iptables
- nf_tables

And whenever you execute "iptables" command you are actually, by default, executing the nf_tables based iptables (nft - in compatibility mode). Because this tool extensively uses iptables NFLOG & TRACE targets, and they are not compatible with nf_tables, it is **MANDATORY** that you use "iptables-legacy" for your firewall rules when using this tool. After discovering all the rules you want to create/keep/delete, you can go back to iptables-nft if you want.

> It is likely that another version of this tool will be created supporting NFT (nf_tables) only.

## TODOs

- Tests
