# Intrusion Detection System(IDS)-
This is a code base of a real time software used in Intrusion Detection System in Networking. This is LSTM based model software with additional Attention Mechanism on top.

  This model is implemented using standard lstm and Attention Mechanism above lstm. This model is firstly trained using NB-15 and Iot Botnet Dataset of a UNSW University of Australia.
Then this model is integrated with real time environment using python libraries like Scapy,Flask etc.

This model is shown above 95% accuracy in detecting malicious traffic.This project has HTML interface showing runtime IPs involve and their category.

# Procedure to run model

1. Run Packet_sniffer.py first using command :- 
        python Packet_sniffer.py
   
3. Run Server.py first using command :-  python Server.py
   
5. Finally Visit local host webpage to see activity.

