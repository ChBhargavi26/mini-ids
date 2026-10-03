from scapy.all import ARP, IP, TCP

import alerts
import detectors


# -----------------------------
# Test 1: ARP Spoofing
# -----------------------------

def test_arp():
    # First packet: IP has MAC address 01
    p1 = ARP(
        op=2,
        psrc="192.168.1.1",
        hwsrc="aa:aa:aa:aa:aa:01"
    )

    # Second packet: SAME IP but DIFFERENT MAC
    p2 = ARP(
        op=2,
        psrc="192.168.1.1",
        hwsrc="aa:aa:aa:aa:aa:02"
    )

    detectors.check_arp(p1)
    detectors.check_arp(p2)

    # Check whether an ARP Spoofing alert was generated
    assert any(
        a["type"] == "ARP Spoofing"
        for a in alerts.get_alerts()
    )


# -----------------------------
# Test 2: Port Scan
# -----------------------------

def test_scan():

    # Generate SYN packets to 14 different ports
    for port in range(1, 15):

        pkt = (
            IP(
                src="10.0.0.9",
                dst="10.0.0.1"
            )
            /
            TCP(
                dport=port,
                flags="S"
            )
        )

        detectors.check_port_scan(pkt)

    # Check whether a Port Scan alert was generated
    assert any(
        a["type"] == "Port Scan"
        for a in alerts.get_alerts()
    )


# Run both tests
test_arp()
test_scan()

print("All tests passed")