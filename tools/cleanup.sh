#!/bin/bash

for table in raw nat mangle filter
do
	sudo iptables -t $table -F
	sudo ip6tables -t $table -F
done
