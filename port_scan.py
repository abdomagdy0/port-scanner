from scapy.all import *

ports = [25,8080,443,53,80,8443]

def SynScan(host):
    ans = sr(IP(dst=host)/TCP(sport=5555,dport=ports,flags="S"),timeout=2,verbose=0)
    print("open ports at %s:" %host)
    for (s,r) in ans:
        if s[TCP].dport == r[TCP].sport:
            print(s[TCP].dport)

def DNSScan(host):
    ans = sr(IP(dst=host)/UDP(sport=5555,dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
    if ans:
        print("DNS Server Found at %s"%host)
    
host = "8.8.8.8"
SynScan(host)
DNSScan(host)