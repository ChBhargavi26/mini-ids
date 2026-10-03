\# Mini Intrusion Detection System (Mini IDS)



A real-time network monitoring and intrusion detection system built using \*\*Python, Scapy, and Flask\*\*. The system captures network packets, detects suspicious activities such as \*\*ARP Spoofing\*\* and \*\*TCP Port Scanning\*\*, and displays security alerts through a real-time web dashboard.



\---



\## 📌 Project Overview



The Mini IDS is designed to monitor network traffic and identify potentially suspicious activities on a local network.



The system continuously captures packets using \*\*Scapy\*\* and analyzes them using two detection mechanisms:



\- ARP Spoofing Detection

\- TCP Port Scan Detection



When suspicious activity is detected, the system generates an alert and displays it on the Flask-based web dashboard.



\### Main Flow



```text

Network Traffic

&#x20;      ↓

Scapy Packet Sniffer

&#x20;      ↓

Detection Engine

&#x20;      ↓

Alert Manager

&#x20;      ↓

Flask Backend

&#x20;      ↓

Web Dashboard

&#x20;      ↓

Wireshark Verification

