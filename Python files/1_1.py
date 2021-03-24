#!/usr/bin/python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface = "br-2b1fb0c14649", filter = 'net 10.0.0', prn=print_pkt)

print("Hello!")
