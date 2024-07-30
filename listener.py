# listener.py
import tkinter as tk
from scapy.all import sniff
from collections import defaultdict
from time import time
from datetime import datetime

# Initialize global structures for tracking attacks
syn_packets = defaultdict(list)
http_requests = defaultdict(list)
known_good_ips = {'8.8.8.8', '8.8.4.4'}  # Example DNS IPs

# Function to detect various attacks
def detect_port_scan(packet):
    tcp_layer = packet.getlayer('TCP')
    return tcp_layer and tcp_layer.flags == 'S'

def detect_ping_sweep(packet):
    icmp_layer = packet.getlayer('ICMP')
    return icmp_layer and icmp_layer.type == 8

def detect_syn_flood(packet):
    tcp_layer = packet.getlayer('TCP')
    if tcp_layer and tcp_layer.flags == 'S':
        src_ip = packet.getlayer('IP').src
        current_time = time()
        syn_packets[src_ip].append(current_time)
        syn_packets[src_ip] = [t for t in syn_packets[src_ip] if current_time - t < 10]
        return len(syn_packets[src_ip]) > 20
    return False

def detect_dns_spoof(packet):
    dns_layer = packet.getlayer('DNS')
    if dns_layer and dns_layer.ancount > 0:
        for rr in dns_layer.ancount:
            if rr.type == 1 and rr.rdata not in known_good_ips:
                return True
    return False

def detect_http_flood(packet):
    http_layer = packet.getlayer('HTTPRequest')
    if http_layer:
        src_ip = packet.getlayer('IP').src
        current_time = time()
        http_requests[src_ip].append(current_time)
        http_requests[src_ip] = [t for t in http_requests[src_ip] if current_time - t < 10]
        return len(http_requests[src_ip]) > 50
    return False

def packet_callback(packet):
    ip_layer = packet.getlayer('IP')
    if ip_layer:
        ip_src = ip_layer.src
        if detect_port_scan(packet):
            alert_msg = f"Port scan detected from {ip_src}"
        elif detect_ping_sweep(packet):
            alert_msg = f"Ping sweep detected from {ip_src}"
        elif detect_syn_flood(packet):
            alert_msg = f"SYN flood detected from {ip_src}"
        elif detect_dns_spoof(packet):
            alert_msg = f"DNS spoofing detected from {ip_src}"
        elif detect_http_flood(packet):
            alert_msg = f"HTTP flood detected from {ip_src}"
        else:
            return
        log_alert(alert_msg)
        update_alerts(alert_msg)

def log_alert(message):
    with open("alerts.log", "a") as log_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_file.write(f"[{timestamp}] {message}\n")

def update_alerts(message):
    alerts_listbox.insert(tk.END, message)
    alerts_listbox.yview(tk.END)

def start_sniffing():
    sniff(filter="tcp", prn=packet_callback, count=0)  # Set count=0 to run indefinitely

# GUI setup
root = tk.Tk()
root.title("IDS Listener")

alerts_frame = tk.Frame(root)
alerts_frame.pack(padx=10, pady=10)

alerts_listbox = tk.Listbox(alerts_frame, width=80, height=20)
alerts_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(alerts_frame, orient=tk.VERTICAL)
scrollbar.config(command=alerts_listbox.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

alerts_listbox.config(yscrollcommand=scrollbar.set)

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=10)

root.mainloop()
