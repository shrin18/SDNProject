#! /usr/bin/env python3
 
from scapy.all import DNS, DNSQR, IP, sr1, UDP
 
dns_req = IP(dst='8.8.8.8')/
    UDP(dport=53)/
    DNS(rd=1, qd=DNSQR(qname='www.thepacketgeek.com'))
answer = sr1(dns_req, verbose=0)
 
print(answer[DNS].summary())
 
 
 
============================Console Output:===========================
Begin emission:
..Finished to send 1 packets.
..*
Received 5 packets, got 1 answers, remaining 0 packets
DNS Ans "198.71.55.197"
