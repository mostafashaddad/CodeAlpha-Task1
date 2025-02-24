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
# from scapy.layers.l2 import ARP, Ether
# from scapy.all import Raw
# import json
# import sqlite3
# import tkinter as tk
# from tkinter import ttk, messagebox, filedialog, scrolledtext
# from datetime import datetime
# import logging
# import base64
# import sys

# # إعدادات الترميز
# sys.stdout.reconfigure(encoding='utf-8')
# sys.stdin.reconfigure(encoding='utf-8')

# # إعداد نظام التسجيل (Logging)
# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s - %(levelname)s - %(message)s",
#     handlers=[
#         logging.FileHandler("sniffer.log", encoding="utf-8"),  # استخدام ترميز UTF-8
#         logging.StreamHandler()
#     ]
# )

# # إعداد قاعدة البيانات
# def setup_database():
#     """إعداد قاعدة البيانات لتخزين الحزم."""
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

# # الحصول على عنوان MAC الحالي
# def get_current_mac(interface):
#     """الحصول على عنوان MAC لواجهة معينة."""
#     try:
#         addrs = psutil.net_if_addrs()
#         mac = addrs[interface][0].address if interface in addrs else None
#         return mac if mac and re.match(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", mac) else "No MAC assigned"
#     except Exception as e:
#         logging.error(f"Error getting MAC address: {e}")
#         return "No MAC assigned"

# # الحصول على عنوان IP الحالي
# def get_current_ip(interface):
#     """الحصول على عنوان IP لواجهة معينة."""
#     try:
#         addrs = psutil.net_if_addrs()
#         for addr in addrs.get(interface, []):
#             if addr.family.name == 'AF_INET':
#                 return addr.address
#         return "No IP assigned"
#     except Exception as e:
#         logging.error(f"Error getting IP address: {e}")
#         return "No IP assigned"

# # عرض جدول IP وMAC
# def ip_table():
#     """عرض جدول يوضح واجهات الشبكة وعناوين IP وMAC."""
#     addrs = psutil.net_if_addrs()
#     table = PrettyTable([f"{Fore.GREEN}Interface", "MAC Address", f"IP Address{Style.RESET_ALL}"])
#     for interface, details in addrs.items():
#         mac = get_current_mac(interface)
#         ip = get_current_ip(interface)
#         table.add_row([interface, mac, ip])
#     print(table)

# # تحليل الحزم
# def analyze_packet(packet):
#     """تحليل الحزمة واستخراج المعلومات."""
#     packet_info = {
#         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         "source_ip": None,
#         "destination_ip": None,
#         "protocol": None,
#         "summary": packet.summary()
#     }

#     if packet.haslayer(Ether):
#         packet_info["source_mac"] = packet[Ether].src
#         packet_info["destination_mac"] = packet[Ether].dst

#     if packet.haslayer(IP):
#         packet_info["source_ip"] = packet[IP].src
#         packet_info["destination_ip"] = packet[IP].dst
#         packet_info["protocol"] = "IPv4"

#     if packet.haslayer(TCP):
#         packet_info["protocol"] = "TCP"
#         packet_info["source_port"] = packet[TCP].sport
#         packet_info["destination_port"] = packet[TCP].dport

#     if packet.haslayer(UDP):
#         packet_info["protocol"] = "UDP"
#         packet_info["source_port"] = packet[UDP].sport
#         packet_info["destination_port"] = packet[UDP].dport

#     if packet.haslayer(ICMP):
#         packet_info["protocol"] = "ICMP"

#     if packet.haslayer(DNS):
#         packet_info["protocol"] = "DNS"

#     if packet.haslayer(HTTPRequest):
#         packet_info["protocol"] = "HTTP"

#     return packet_info

# # تسجيل الحزمة في قاعدة البيانات
# def log_packet(packet_info, conn):
#     """تسجيل الحزمة في قاعدة البيانات."""
#     cursor = conn.cursor()
#     cursor.execute("""
#         INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, summary)
#         VALUES (?, ?, ?, ?, ?)
#     """, (packet_info["timestamp"], packet_info["source_ip"], packet_info["destination_ip"], packet_info["protocol"], packet_info["summary"]))
#     conn.commit()

# # حفظ الحزم في ملف نصي
# def save_packets_to_file(packets, filename):
#     """حفظ الحزم في ملف نصي."""
#     with open(filename, "w", encoding="utf-8") as f:
#         for packet in packets:
#             f.write(json.dumps(packet, indent=4) + "\n")

# # واجهة المستخدم الرسومية
# class SnifferApp:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Mem Sheen Dragon - Network Sniffer")
#         self.conn = setup_database()

#         # إعداد الواجهة
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

#         self.packet_display = scrolledtext.ScrolledText(root, width=100, height=20)
#         self.packet_display.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

#         self.sniff_thread = None
#         self.running = False
#         self.packets = []

#     def refresh_interfaces(self):
#         """تحديث قائمة واجهات الشبكة."""
#         interfaces = list(psutil.net_if_addrs().keys())
#         self.interface_dropdown['values'] = interfaces
#         if interfaces:
#             self.interface_var.set(interfaces[0])

#     def start_sniffing(self):
#         """بدء التقاط الحزم."""
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
#         """إيقاف التقاط الحزم."""
#         if self.running:
#             self.running = False
#             self.status_label.config(text="Status: Stopped")
#             self.start_button.config(state=tk.NORMAL)
#             self.stop_button.config(state=tk.DISABLED)

#     def sniff_packets(self, interface, filter_type):
#         """التقاط الحزم."""
#         try:
#             scapy.sniff(iface=interface, filter="ip", prn=self.process_packet, store=False)
#         except Exception as e:
#             messagebox.showerror("Error", f"An error occurred: {e}")

#     def process_packet(self, packet):
#         """معالجة الحزمة الملتقطة."""
#         packet_info = analyze_packet(packet)
#         self.packets.append(packet_info)
#         log_packet(packet_info, self.conn)
#         self.update_packet_display(packet_info)

#     def update_packet_display(self, packet_info):
#         """تحديث واجهة المستخدم بعرض الحزم."""
#         self.packet_display.insert(tk.END, json.dumps(packet_info, indent=4) + "\n")
#         self.packet_display.yview(tk.END)

#     def export_packets(self):
#         """تصدير الحزم إلى ملف."""
#         file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
#         if file_path:
#             save_packets_to_file(self.packets, file_path)
#             messagebox.showinfo("Success", f"Packets exported to {file_path} successfully!")

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = SnifferApp(root)
#     root.mainloop()



#New version 

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
from scapy.layers.l2 import ARP, Ether
from scapy.all import Raw
import json
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from datetime import datetime
import logging
import base64
import sys
import csv

# إعدادات الترميز
sys.stdout.reconfigure(encoding='utf-8')
sys.stdin.reconfigure(encoding='utf-8')

# إعداد نظام التسجيل (Logging)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("sniffer.log", encoding="utf-8"),  # استخدام ترميز UTF-8
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

# تحليل الحزم
def analyze_packet(packet):
    """تحليل الحزمة واستخراج المعلومات."""
    packet_info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "summary": packet.summary()
    }

    if packet.haslayer(Ether):
        packet_info["source_mac"] = packet[Ether].src
        packet_info["destination_mac"] = packet[Ether].dst

    if packet.haslayer(IP):
        packet_info["source_ip"] = packet[IP].src
        packet_info["destination_ip"] = packet[IP].dst
        packet_info["protocol"] = "IPv4"

    if packet.haslayer(TCP):
        packet_info["protocol"] = "TCP"
        packet_info["source_port"] = packet[TCP].sport
        packet_info["destination_port"] = packet[TCP].dport

    if packet.haslayer(UDP):
        packet_info["protocol"] = "UDP"
        packet_info["source_port"] = packet[UDP].sport
        packet_info["destination_port"] = packet[UDP].dport

    if packet.haslayer(ICMP):
        packet_info["protocol"] = "ICMP"

    if packet.haslayer(DNS):
        packet_info["protocol"] = "DNS"

    if packet.haslayer(HTTPRequest):
        packet_info["protocol"] = "HTTP"

    return packet_info

# تسجيل الحزمة في قاعدة البيانات
def log_packet(packet_info, conn):
    """تسجيل الحزمة في قاعدة البيانات."""
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, summary)
        VALUES (?, ?, ?, ?, ?)
    """, (packet_info["timestamp"], packet_info["source_ip"], packet_info["destination_ip"], packet_info["protocol"], packet_info["summary"]))
    conn.commit()

# حفظ الحزم في ملف نصي
def save_packets_to_file(packets, filename, file_type):
    """حفظ الحزم في ملف نصي أو JSON أو CSV."""
    if file_type == "txt":
        with open(filename, "w", encoding="utf-8") as f:
            for packet in packets:
                f.write(json.dumps(packet, indent=4) + "\n")
    elif file_type == "json":
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(packets, f, indent=4)
    elif file_type == "csv":
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=packets[0].keys())
            writer.writeheader()
            writer.writerows(packets)

# واجهة المستخدم الرسومية
class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mem Sheen Dragon - Network Sniffer")
        self.conn = setup_database()

        # إعداد الواجهة
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

        self.packet_display = scrolledtext.ScrolledText(root, width=100, height=20)
        self.packet_display.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        self.sniff_thread = None
        self.running = False
        self.packets = []

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
            scapy.sniff(iface=interface, filter="ip", prn=self.process_packet, store=False, stop_filter=lambda x: not self.running)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def process_packet(self, packet):
        """معالجة الحزمة الملتقطة."""
        if not self.running:
            return
        packet_info = analyze_packet(packet)
        self.packets.append(packet_info)
        log_packet(packet_info, self.conn)
        self.update_packet_display(packet_info)

    def update_packet_display(self, packet_info):
        """تحديث واجهة المستخدم بعرض الحزم."""
        self.packet_display.insert(tk.END, json.dumps(packet_info, indent=4) + "\n")
        self.packet_display.yview(tk.END)

    def export_packets(self):
        """تصدير الحزم إلى ملف."""
        file_types = [("Text Files", "*.txt"), ("JSON Files", "*.json"), ("CSV Files", "*.csv")]
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=file_types)
        if file_path:
            file_type = file_path.split(".")[-1]
            save_packets_to_file(self.packets, file_path, file_type)
            messagebox.showinfo("Success", f"Packets exported to {file_path} successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()