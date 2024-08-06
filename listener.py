from scapy.all import sniff
from scapy.layers.inet import IP,TCP
from collections import defaultdict
from time import time
from datetime import datetime
import threading
import http_server


syn_packets = defaultdict(list)
http_requests = defaultdict(list)
PORT = 5123
known_good_ips = {'8.8.8.8', '8.8.4.4'}  # Example DNS IPs

# Create or overwrite the log file
with open("alerts.log", "a") as log_file:
    log_file.write("=" * 25 + str(datetime.now()) + "=" * 25 + "\n")

# Function to detect various attacks
def detect_port_scan(packet):
    tcp_layer = packet.getlayer(TCP)
    return tcp_layer and tcp_layer.flags == 'S'

def detect_ping_sweep(packet):
    icmp_layer = packet.getlayer('ICMP')
    return icmp_layer and icmp_layer.type == 8

def detect_syn_flood(packet):
    tcp_layer = packet.getlayer(TCP)
    if tcp_layer:
        if 'S' in tcp_layer.flags:
            src_ip = packet.getlayer(IP).src
            current_time = time()
            syn_packets[src_ip].append(current_time)
            syn_packets[src_ip] = [t for t in syn_packets[src_ip] if current_time - t < 10]
            return len(syn_packets[src_ip]) > 20
    return False

def log_alert(message):
    with open("alerts.log", "a") as log_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_file.write(f"[{timestamp}] {message}\n")

def detect_dns_spoof(packet):
    dns_layer = packet.getlayer('DNS')
    if dns_layer and dns_layer.ancount > 0:
        for i in range(dns_layer.ancount):
            rr = dns_layer.an[i]
            if rr.type == 1 and rr.rdata not in known_good_ips:
                return True
    return False

def detect_http_flood(packet):
    tcp_layer = packet.getlayer(TCP)
    if tcp_layer and packet.haslayer(IP):
        payload = bytes(packet[TCP].payload)
        if b'GET ' in payload or b'POST ' in payload:
            src_ip = packet[IP].src
            current_time = time()
            http_requests[src_ip].append(current_time)
            http_requests[src_ip] = [t for t in http_requests[src_ip] if current_time - t < 10]
            return len(http_requests[src_ip]) > 50
    return False

def packet_callback(packet):
    ip_layer = packet.getlayer(IP)
    if ip_layer:
        ip_src = ip_layer.src
        if detect_http_flood(packet):
            alert_msg = f"HTTP flood detected from {ip_src}"
        elif detect_syn_flood(packet):
            alert_msg = f"SYN flood detected from {ip_src}"
        elif detect_ping_sweep(packet):
            alert_msg = f"Ping sweep detected from {ip_src}"
        elif detect_dns_spoof(packet):
            alert_msg = f"DNS spoofing detected from {ip_src}"
        elif detect_port_scan(packet):
            alert_msg = f"Port scan detected from {ip_src}"
        else:
            return
        log_alert(alert_msg)
        print(alert_msg)  # Print the alert to console

def start_sniffing():
    bpf_filter = f'tcp port {PORT} or icmp'
    sniff(filter=bpf_filter, prn=packet_callback, count=0)  # Set count=0 to run indefinitely

if __name__ == "__main__":
    server_thread = threading.Thread(target=http_server.run,daemon=True)
    server_thread.start()
    print("Start sniffing and IDS")
    start_sniffing()
