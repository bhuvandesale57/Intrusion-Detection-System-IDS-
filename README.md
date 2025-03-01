# Intrusion Detection System (IDS)

This is a real-time Intrusion Detection System (IDS) implemented using an LSTM-based model with an additional Attention Mechanism on top.

## Overview

The model utilizes a standard LSTM architecture with an Attention Mechanism to enhance performance. It is trained using the NB-15 and IoT Botnet datasets from UNSW University, Australia.

The IDS is integrated with a real-time environment using Python libraries like Scapy and Flask. It has demonstrated over **95% accuracy** in detecting malicious traffic. Additionally, a web interface provides real-time monitoring of IPs and their classification.

---

## How to Run the Model

1. **Start Packet Sniffer**  
   Run the packet sniffer script to capture network traffic:  
   ```sh
   python Packet_sniffer.py
   ```

2. **Start the Server**  
   Run the server to process and display results:  
   ```sh
   python Server.py
   ```

3. **Open the Web Interface**  
   Visit `http://localhost` in your browser to view real-time intrusion detection results.

4. **Ensure Required Dependencies**  
   Install necessary dependencies before running the scripts:
   ```sh
   pip install -r requirements.txt
   ```

---

## File Structure

```
project/
│
├── server.py              # Flask server for real-time monitoring
├── Packet_sniffer.py      # Script to capture network packets
├── attention_model_1.h5   # Pre-trained LSTM + Attention model
├── templates/             # HTML templates for the web interface
   └── index.html         # Main webpage for visualization
```

---

## Dependencies
Make sure to install the required dependencies before running the IDS:


---

## Features
- Real-time intrusion detection with high accuracy.
- Web interface to visualize network activity.
- Uses deep learning (LSTM + Attention) for anomaly detection.
- Trained on benchmark datasets (NB-15 & IoT Botnet).

For any issues or contributions, feel free to create a pull request or open an issue on GitHub.

