from scapy.all import sniff
import config
import alerts
import detectors


def handle_packet(pkt):
    alerts.stats["packets"] += 1

    if pkt.haslayer("ARP"):
        detectors.check_arp(pkt)

    if pkt.haslayer("IP") and pkt.haslayer("TCP"):
        detectors.check_port_scan(pkt)


def start_sniffer():
    print("===================================")
    print("       MINI IDS PACKET SNIFFER")
    print("===================================")
    print("Starting packet capture...")
    print("Press Ctrl+C to stop.")
    print()

    sniff(
        iface=config.IFACE,
        filter="arp or tcp",
        prn=handle_packet,
        store=False
    )


if __name__ == "__main__":
    start_sniffer()