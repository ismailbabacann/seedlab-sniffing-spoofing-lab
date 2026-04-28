#!/usr/bin/env python3
from scapy.all import *

def traceroute(dest, max_hops=30):
    print(f"{dest} hedefine traceroute başlıyor...\n")
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=dest, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=2)

        if reply is None:
            print(f"{ttl}. hop: Cevap yok")
        elif reply[ICMP].type == 11:
            print(f"{ttl}. hop: {reply[IP].src}")
        elif reply[ICMP].type == 0:
            print(f"{ttl}. hop: {reply[IP].src}  ← HEDEFE ULAŞTI!")
            break

traceroute('10.9.0.6')
