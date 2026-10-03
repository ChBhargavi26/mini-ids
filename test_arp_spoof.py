import sys
import time
from scapy.all import ARP, Ether, sendp

# usage:
# python test_arp_spoof.py <victim-ip> <unused-ip-on-your-network>

victim_ip = sys.argv[1]
fake_ip = sys.argv[2]

for mac in ("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"):
    pkt = Ether(
        src=mac,
        dst="ff:ff:ff:ff:ff:ff"
    ) / ARP(
        op=2,
        hwsrc=mac,
        psrc=fake_ip,
        pdst=victim_ip
    )

    sendp(pkt, verbose=False)

    print(
        "sent ARP reply:",
        fake_ip,
        "is-at",
        mac
    )

    time.sleep(1)