# Network interface to sniff on.
# None means Scapy chooses the default interface.
IFACE = IFACE = r"\Device\NPF_{6C8B509E-4B3A-453F-8927-F12D408F47C4}"

# Port scan detection:
# 10 different ports within 5 seconds = possible port scan
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 5

# Prevent the same alert from appearing repeatedly
ALERT_COOLDOWN = 10

# Flask dashboard settings
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
