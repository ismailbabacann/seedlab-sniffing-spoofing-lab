#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

sniff(iface='br-90fe1db80792', filter='net 128.230.0.0/16', prn=print_pkt)

