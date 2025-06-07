#!/bin/bash

for i  in $(seq 0 3); do 
	ip netns del ns$i  2>/dev/null || true
done

for i in $(seq 0 3); do
	ip link delete veth${i}-host 2>/dev/null || true
done 

iptables -t nat -F
