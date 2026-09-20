from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        print("--------------------------------")
        print("Source IP      :", source)
        print("Destination IP :", destination)
        print("Protocol       :", protocol)
        print("Packet Size    :", len(packet), "bytes")

print("Starting Network Sniffer...")
print("Press Ctrl+C to stop.")

sniff(prn=packet_callback, store=False)