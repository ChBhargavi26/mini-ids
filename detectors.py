import time
from collections import defaultdict, deque

from scapy.all import ARP, IP, TCP

import alerts
import config


# Remembered IP -> MAC mappings
ip_mac = {}

# Store TCP SYN attempts
# Key = (source IP, destination IP)
# Value = deque of (time, destination port)
syn_log = defaultdict(deque)


def check_arp(pkt):
    """
    Detect possible ARP spoofing.

    If the same IP address is later seen
    with a different MAC address, generate an alert.
    """

    arp = pkt[ARP]

    # 1 = who-has (request)
    # 2 = is-at (reply)
    if arp.op not in (1, 2):
        return

    ip = arp.psrc
    mac = arp.hwsrc.lower()

    # Ignore empty addresses
    if ip in ("", "0.0.0.0"):
        return

    # Have we seen this IP before?
    known = ip_mac.get(ip)

    if known is None:
        # First time seeing this IP.
        # Remember its MAC address.
        ip_mac[ip] = mac

    elif known != mac:
        # Same IP, different MAC = suspicious
        alerts.add_alert(
            "ARP Spoofing",
            ip,
            f"IP {ip} was {known} but MAC {mac} now claims it",
            config.ALERT_COOLDOWN
        )


def check_port_scan(pkt):
    """
    Detect possible TCP port scanning.

    A scan is detected when one source IP
    sends SYN-only packets to at least
    10 different destination ports within 5 seconds.
    """

    ip = pkt[IP]
    tcp = pkt[TCP]

    flags = int(tcp.flags)

    # SYN = 0x02
    # ACK = 0x10

    # We only want SYN packets WITHOUT ACK.
    # This represents a new connection attempt.
    if not (flags & 0x02) or (flags & 0x10):
        return

    key = (ip.src, ip.dst)

    now = time.time()

    log = syn_log[key]

    # Remember this connection attempt
    log.append((now, tcp.dport))

    # Remove attempts older than our time window
    while log and now - log[0][0] > config.PORT_SCAN_WINDOW:
        log.popleft()

    # Get unique destination ports
    ports = {port for _, port in log}

    # Check the threshold
    if len(ports) >= config.PORT_SCAN_THRESHOLD:

        alerts.add_alert(
            "Port Scan",
            ip.src,
            f"{len(ports)} ports probed on "
            f"{ip.dst} in {config.PORT_SCAN_WINDOW}s",
            config.ALERT_COOLDOWN
        )