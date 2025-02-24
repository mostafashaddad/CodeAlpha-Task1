from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from datetime import datetime

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
    
    if pk.haslayer(HTTPRequest):
        packet_type = "HTTP"
        print("HTTP Request Captured")
        print(f"Host: {pk[HTTPRequest].Host.decode()}")
        print(f"Path: {pk[HTTPRequest].Path.decode()}")
        print(f"Method: {pk[HTTPRequest].Method.decode()}")
    
    with open("packet_log.txt", "a") as f:
        f.write(f"{packet_type} Packet Captured\n")

def print_stats():
    for protocol, count in packet_stats.items():
        print(f"{protocol}: {count} packets")

start_sniffer_background(iface="Wi-Fi", filter="tcp or udp or port 53", count=10)
