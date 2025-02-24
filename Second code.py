from scapy.all import sniff
from datetime import datetime

# إحصائيات الحزم الملتقطة لكل بروتوكول
packet_stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "ARP": 0,
    "Other": 0
}

def sn(pk):
    packet_type = "Unknown"
    
    if pk.haslayer(TCP):
        packet_type = "TCP"
    elif pk.haslayer(UDP):
        packet_type = "UDP"
    elif pk.haslayer(ICMP):
        packet_type = "ICMP"
    elif pk.haslayer(ARP):
        packet_type = "ARP"

    packet_stats[packet_type] = packet_stats.get(packet_type, 0) + 1

    print("################################")
    print(f"{packet_type} Packet Captured")
    print("Timestamp: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(f"Packet Length: {len(pk)} bytes")
    
    if pk.haslayer(IP):
        print("Source IP: " + pk[IP].src)
        print("Destination IP: " + pk[IP].dst)
    
    if pk.haslayer(Ether):
        print("Source MAC: " + pk[Ether].src)
        print("Destination MAC: " + pk[Ether].dst)
    
    if packet_type in ["TCP", "UDP"]:
        print("Source Port: " + str(pk.sport))
        print("Destination Port: " + str(pk.dport))
    
    if pk.haslayer(Raw):
        print("Raw Data: " + str(pk[Raw].load))
    
    # كتابة الحزمة إلى ملف
    with open("packet_log.txt", "a") as f:
        f.write(f"{packet_type} Packet Captured at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Packet Length: {len(pk)} bytes\n")
        if pk.haslayer(IP):
            f.write(f"Source IP: {pk[IP].src}\n")
            f.write(f"Destination IP: {pk[IP].dst}\n")
        if pk.haslayer(Ether):
            f.write(f"Source MAC: {pk[Ether].src}\n")
            f.write(f"Destination MAC: {pk[Ether].dst}\n")
        if packet_type in ["TCP", "UDP"]:
            f.write(f"Source Port: {pk.sport}\n")
            f.write(f"Destination Port: {pk.dport}\n")
        if pk.haslayer(Raw):
            f.write(f"Raw Data: {pk[Raw].load}\n")
        f.write("################################\n\n")

    if packet_type == "Unknown":
        print("Unknown Packet Type")
        hexdump(pk)

def print_stats():
    print("\n##### Packet Statistics #####")
    for protocol, count in packet_stats.items():
        print(f"{protocol}: {count} packets")
    print("#############################")

def start_sniffing(iface="Wi-Fi", filter=None, count=0):
    try:
        print(f"Starting sniffer on interface: {iface}")
        sniff(iface=iface, prn=sn, filter=filter, count=count)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print_stats()

start_sniffing(iface="Wi-Fi", filter="tcp or udp", count=10)
