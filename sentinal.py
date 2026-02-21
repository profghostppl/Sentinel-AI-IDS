from scapy.all import sniff

# This function runs every time a packet is "caught"
def process_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        proto = packet["IP"].proto
        print(f"[+] New Packet: {src_ip} -> {dst_ip} | Protocol: {proto}")

print("--- Starting Sentinel-AI Packet Sniffer ---")
# Sniff 10 packets to test (filter for IP packets only)
sniff(prn=process_packet, count=10)

import pandas as pd
from scapy.all import sniff

data_list = []

def collect_data(packet):
    if packet.haslayer("IP"):
        # We extract "Features" that an AI can understand
        feature_row = {
            "src_port": packet.sport if packet.haslayer("TCP") else 0,
            "dst_port": packet.dport if packet.haslayer("TCP") else 0,
            "payload_size": len(packet),
            "protocol": packet.proto
        }
        data_list.append(feature_row)
        print(f"Captured packet {len(data_list)}")

# Sniff 100 packets to create a small dataset
sniff(prn=collect_data, count=200)

# Save to CSV for Week 2 (The AI Phase)
df = pd.DataFrame(data_list)
df.to_csv("network_data.csv", index=False)
print("Data saved to network_data.csv! You are ready for the AI phase.")