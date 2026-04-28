#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-90fe1db80792', filter='icmp', prn=print_pkt)
