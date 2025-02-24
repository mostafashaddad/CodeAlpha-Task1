from scapy.all import sniff

def sn(pk):
    # التحقق من وجود طبقة IP أولاً
    if pk.haslayer(IP):
        if pk.haslayer(TCP):
            print("################################")
            print("TCP packet\n")
            print("___________Src Info___________")
            print("src IP : " + pk[IP].src)  # عرض عنوان الـ IP المصدر
            print("src Mac : " + pk.src)  # عرض الـ MAC المصدر
            print("src port : " + str(pk.sport))  # عرض المنفذ المصدر
            print("___________Dst Info___________")
            print("dst IP : " + pk[IP].dst)  # عرض عنوان الـ IP الوجهة
            print("dst Mac : " + pk.dst)  # عرض الـ MAC الوجهة
            print("dst port : " + str(pk.dport))  # عرض المنفذ الوجهة
            if pk.haslayer(Raw):
                print("Raw data : " + str(pk[Raw].load))  # عرض البيانات الخام

        elif pk.haslayer(UDP):
            print("################################")
            print("UDP packet\n")
            print("___________Src Info___________")
            print("src IP : " + pk[IP].src)
            print("src Mac : " + pk.src)
            print("src port : " + str(pk.sport))
            print("___________Dst Info___________")
            print("dst IP : " + pk[IP].dst)
            print("dst Mac : " + pk.dst)
            print("dst port : " + str(pk.dport))
            if pk.haslayer(Raw):
                print("Raw data : " + str(pk[Raw].load))
    else:
        print("Non-IP packet detected, skipping...")

sniff(iface="Wi-Fi", prn=sn)
