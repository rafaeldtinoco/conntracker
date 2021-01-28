#!/bin/bash

./tools/wipe.sh

if [ -f /sbin/iptables-legacy ]; then
        iptable="iptables-legacy"
        ip6table="ip6tables-legacy"
else
        iptable="iptables"
        ip6table="ip6tables"
fi

iptables="sudo $iptable -w"
ip6tables="sudo $ip6table -w"

# ipv4

for table in filter mangle; do

$iptables -t $table -A OUTPUT --proto udp -j ACCEPT
$iptables -t $table -A OUTPUT --proto icmp -j ACCEPT
$iptables -t $table -A OUTPUT --proto icmpv6 -j ACCEPT
$iptables -t $table -A OUTPUT --proto tcp -j ACCEPT

$iptables -t $table -A INPUT --proto udp -j ACCEPT
$iptables -t $table -A INPUT --proto icmp -j ACCEPT
$iptables -t $table -A INPUT --proto icmpv6 -j ACCEPT
$iptables -t $table -A INPUT --proto tcp -j ACCEPT

$iptables -t $table -A FORWARD --proto udp -j ACCEPT
$iptables -t $table -A FORWARD --proto icmp -j ACCEPT
$iptables -t $table -A FORWARD --proto icmpv6 -j ACCEPT
$iptables -t $table -A FORWARD --proto tcp -j ACCEPT

$iptables -t $table -P OUTPUT DROP
$iptables -t $table -P INPUT DROP
$iptables -t $table -P FORWARD DROP

done

# ipv6

for table in filter mangle; do

$ip6tables -t $table -A OUTPUT --proto udp -j ACCEPT
$ip6tables -t $table -A OUTPUT --proto icmp -j ACCEPT
$ip6tables -t $table -A OUTPUT --proto icmpv6 -j ACCEPT
$ip6tables -t $table -A OUTPUT --proto tcp -j ACCEPT

$ip6tables -t $table -A INPUT --proto udp -j ACCEPT
$ip6tables -t $table -A INPUT --proto icmp -j ACCEPT
$ip6tables -t $table -A INPUT --proto icmpv6 -j ACCEPT
$ip6tables -t $table -A INPUT --proto tcp -j ACCEPT

$ip6tables -t $table -A FORWARD --proto udp -j ACCEPT
$ip6tables -t $table -A FORWARD --proto icmp -j ACCEPT
$ip6tables -t $table -A FORWARD --proto icmpv6 -j ACCEPT
$ip6tables -t $table -A FORWARD --proto tcp -j ACCEPT

$ip6tables -t $table -P OUTPUT DROP
$ip6tables -t $table -P INPUT DROP
$ip6tables -t $table -P FORWARD DROP

done
