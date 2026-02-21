import joblib # You may need to 'pip install joblib' to save/load models
from scapy.all import sniff
from colorama import Fore, Style, init

# Initialize colors
init(autoreset=True)

# 1. Load your 'Brain' (You'll need to save your model in train_ai.py first)
# For this example, let's use a simple detection logic based on your AI's findings
def live_classifier(packet):
    if packet.haslayer("IP"):
        payload = len(packet)
        dst_port = packet.dport if packet.haslayer("TCP") else 0
        
        # This is where your AI 'predicts'
        # Example: AI learned that ports > 1024 + small payloads = Port Scan
        if dst_port > 1024 and payload < 100:
            print(Fore.RED + Style.BRIGHT + f"!! ALERT: Suspicious Scan Detected from {packet['IP'].src} on Port {dst_port} !!")
        else:
            print(Fore.GREEN + f"Normal Traffic: {packet['IP'].src} -> {payload} bytes")

print(Fore.CYAN + "--- Sentinel-AI Live Defender Active ---")
sniff(prn=live_classifier, filter="ip", store=0)