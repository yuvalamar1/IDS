from scapy.all import sniff
from collections import defaultdict
from time import time
from datetime import datetime

# Initialize global structures for tracking attacks
syn_packets = defaultdict(list)
http_requests = defaultdict(list)
known_good_ips = {'8.8.8.8', '8.8.4.4'}  # Example DNS IPs, add more as needed

# Open log file in write mode to overwrite it at the start
with open("alerts.log", "a") as log_file:
    log_file.write("Intrusion Detection System Alerts Log\n")
    log_file.write("=" * 25+ str(datetime.now()) +"="*25 + "\n")


def detect_port_scan(packet):
    tcp_layer = packet.getlayer('TCP')
    if tcp_layer:
        flags = tcp_layer.flags
        if flags == 'S':  # SYN flag
            return True
    return False


def detect_ping_sweep(packet):
    icmp_layer = packet.getlayer('ICMP')
    if icmp_layer and icmp_layer.type == 8:  # ICMP echo request
        return True
    return False


def detect_syn_flood(packet):
    tcp_layer = packet.getlayer('TCP')
    if tcp_layer and tcp_layer.flags == 'S':
        src_ip = packet.getlayer('IP').src
        current_time = time()
        syn_packets[src_ip].append(current_time)
        syn_packets[src_ip] = [t for t in syn_packets[src_ip] if current_time - t < 10]
        if len(syn_packets[src_ip]) > 20:  # Threshold for SYN flood
            return True
    return False


def detect_dns_spoof(packet):
    dns_layer = packet.getlayer('DNS')
    if dns_layer and dns_layer.ancount > 0:
        for i in range(dns_layer.ancount):
            rr = dns_layer.an[i]
            if rr.type == 1 and rr.rdata not in known_good_ips:  # A record
                return True
    return False


def detect_http_flood(packet):
    http_layer = packet.getlayer('HTTPRequest')
    if http_layer:
        src_ip = packet.getlayer('IP').src
        current_time = time()
        http_requests[src_ip].append(current_time)
        http_requests[src_ip] = [t for t in http_requests[src_ip] if current_time - t < 10]
        if len(http_requests[src_ip]) > 50:  # Threshold for HTTP flood
            return True
    return False


def packet_callback(packet):
    ip_layer = packet.getlayer('IP')
    if ip_layer:
        ip_src = ip_layer.src
        ip_dst = ip_layer.dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")

        if detect_port_scan(packet):
            alert_msg = f"Port scan detected from {ip_src}"
            log_alert(alert_msg)
            print(alert_msg)
        elif detect_ping_sweep(packet):
            alert_msg = f"Ping sweep detected from {ip_src}"
            log_alert(alert_msg)
            print(alert_msg)
        elif detect_syn_flood(packet):
            alert_msg = f"SYN flood detected from {ip_src}"
            log_alert(alert_msg)
            print(alert_msg)
        elif detect_dns_spoof(packet):
            alert_msg = f"DNS spoofing detected from {ip_src}"
            log_alert(alert_msg)
            print(alert_msg)
        elif detect_http_flood(packet):
            alert_msg = f"HTTP flood detected from {ip_src}"
            log_alert(alert_msg)
            print(alert_msg)


def log_alert(message):
    with open("alerts.log", "a") as log_file:
        log_file.write(message + "\n")


def show_alerts():
    try:
        with open("alerts.log", "r") as log_file:
            for line in log_file:
                print(line.strip())
    except FileNotFoundError:
        print("No alerts have been logged yet.")


if __name__ == "__main__":
    sniff(prn=packet_callback, count=100)
    show_alerts()
