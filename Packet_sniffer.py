import time
from scapy.all import sniff, IP, TCP, UDP, ARP
import requests

# Global variable for duration calculation.
last_packet_time = None

def extract_features(packet):
    """
    Extract the 15 desired features from the packet.
    Features:
      - Rate
      - Source_Bytes
      - Duration
      - Destination_Bytes
      - Destination_Packets
      - Total_Packets
      - Source_Packets
      - State_CON
      - Protocol_udp
      - Protocol_arp
      - State_INT
      - Protocol_tcp
      - State_FIN
      - State_RST
      - State_REQ
    """
    global last_packet_time

    features = {}
    
    # Calculate duration as time difference between current and previous packet.
    current_time = packet.time
    duration = 0 if last_packet_time is None else current_time - last_packet_time
    last_packet_time = current_time
    features["Duration"] = duration

    # Use packet length as a proxy for bytes.
    pkt_length = len(packet)
    features["Source_Bytes"] = pkt_length
    features["Destination_Bytes"] = pkt_length

    # Rate: bytes per second.
    features["Rate"] = pkt_length / duration if duration > 0 else 0

    # As instructed, we assign constant 1 for packet count features.
    features["Source_Packets"] = 1
    features["Destination_Packets"] = 1
    features["Total_Packets"] = 1

    # TCP state features: if a TCP layer exists, check the flags.
    if packet.haslayer(TCP):
        flags = str(packet[TCP].flags)
        features["State_CON"] = 1 if "S" in flags and "A" not in flags else 0
        features["State_INT"] = 1 if "A" in flags else 0
        features["State_FIN"] = 1 if "F" in flags else 0
        features["State_RST"] = 1 if "R" in flags else 0
        features["State_REQ"] = 1 if "P" in flags else 0
    else:
        features["State_CON"] = 0
        features["State_INT"] = 0
        features["State_FIN"] = 0
        features["State_RST"] = 0
        features["State_REQ"] = 0

    # Protocol flags.
    features["Protocol_udp"] = 1 if packet.haslayer(UDP) else 0
    features["Protocol_arp"] = 1 if packet.haslayer(ARP) else 0
    features["Protocol_tcp"] = 1 if packet.haslayer(TCP) else 0

    return features

def process_packet(packet):
    """
    Process each captured packet:
      - Extract features.
      - Retrieve source IP, destination IP, and protocol for display.
      - Send JSON data to the server.
    """
    # Get source and destination IP from the IP layer, if available.
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
    else:
        source_ip = "N/A"
        destination_ip = "N/A"
    
    # Determine protocol string for display.
    if packet.haslayer(TCP):
        protocol_str = "TCP"
    elif packet.haslayer(UDP):
        protocol_str = "UDP"
    elif packet.haslayer(ARP):
        protocol_str = "ARP"
    else:
        protocol_str = "Other"
    
    # Extract the 15 features.
    features = extract_features(packet)
    
    # Add extra fields for display on the server.
    features["source_ip"] = source_ip
    features["destination_ip"] = destination_ip
    features["protocol"] = protocol_str

    print("Extracted features:", features)
    
    try:
        response = requests.post("http://127.0.0.1:5000/predict", json=features)
        print("Server response:", response.json())
    except Exception as e:
        print("Error sending packet data:", e)

# Start sniffing all packets (no filter) or adjust the filter as necessary.
sniff(prn=process_packet, store=0)
