#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.dst = '10.9.0.5'
a.src = '1.2.3.4'
b = ICMP()
p = a/b
send(p)
print("Sahte paket gönderildi!")
