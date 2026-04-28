#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.src = "1.2.3.4"       # sahte kaynak IP
a.dst = "10.9.0.6"      # Host B (gerçek hedef)

b = ICMP()

p = a / b
send(p, verbose=True)
