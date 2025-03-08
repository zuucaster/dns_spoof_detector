import scapy.all as scapy
from scapy.layers.dns import DNS, DNSRR

trusted_dns = "8.8.8.8"  # Example trusted DNS server

def detect_dns_spoof(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSRR):
        for i in range(packet[DNS].ancount):
            answer = packet[DNSRR][i]
            if answer.rdata != trusted_dns:
                print(f"Possible DNS Spoofing Detected! Fake IP: {answer.rdata}")

scapy.sniff(filter="udp port 53", prn=detect_dns_spoof, store=False)
