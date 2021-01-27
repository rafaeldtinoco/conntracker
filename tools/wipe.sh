#!/bin/bash

iptableses="iptables ip6tables iptables-legacy ip6tables-legacy"

for iptable in $iptableses; do

	if [ ! -f /sbin/$iptable ]; then
		echo no $iptable found, continuing
		continue
	fi

	iptables="sudo $iptable -w"

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

done
