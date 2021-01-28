#!/bin/bash

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

$iptables -t filter -P INPUT ACCEPT
$iptables -t filter -P OUTPUT ACCEPT
$iptables -t filter -P FORWARD ACCEPT

$iptables -t mangle -P INPUT ACCEPT
$iptables -t mangle -P OUTPUT ACCEPT
$iptables -t mangle -P FORWARD ACCEPT

$iptables -t raw -F
$iptables -t raw -X
$iptables -t filter -F
$iptables -t filter -X
$iptables -t mangle -F
$iptables -t mangle -X
$iptables -t nat -F
$iptables -t nat -X

# ipv6

$ip6tables -t filter -P INPUT ACCEPT
$ip6tables -t filter -P OUTPUT ACCEPT
$ip6tables -t filter -P FORWARD ACCEPT

$ip6tables -t mangle -P INPUT ACCEPT
$ip6tables -t mangle -P OUTPUT ACCEPT
$ip6tables -t mangle -P FORWARD ACCEPT

$ip6tables -t raw -F
$ip6tables -t raw -X
$ip6tables -t filter -F
$ip6tables -t filter -X
$ip6tables -t mangle -F
$ip6tables -t mangle -X
$ip6tables -t nat -F
$ip6tables -t nat -X
