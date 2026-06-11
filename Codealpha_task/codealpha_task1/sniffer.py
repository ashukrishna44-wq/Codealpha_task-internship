from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

log_file = "packets.log"

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        timestamp = datetime.now().strftime("%H:%M:%S")

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = "-"
            dst_port = "-"
        else:
            protocol = f"OTHER({proto})"
            src_port = "-"
            dst_port = "-"

        # Payload
        if Raw in packet:
            payload = packet[Raw].load[:50]  # first 50 bytes only
        else:
            payload = None

        log = f"[{timestamp}] [{protocol}] {src_ip}:{src_port} --> {dst_ip}:{dst_port}"
        if payload:
            log += f" | Payload: {payload}"

        print(log)

        with open(log_file, "a") as f:
            f.write(log + "\n")

print("Starting sniffer... Press Ctrl+C to stop")
print(f"Saving to {log_file}\n")
sniff(prn=packet_callback, count=30)