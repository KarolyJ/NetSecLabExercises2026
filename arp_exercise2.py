from scapy.all import *
import time

VICTIM_MAC = "02:42:c0:a8:65:0a"
SERVER_IP = "192.168.101.30"
ATTACKER_MAC = "02:42:c0:a8:65:14"

# Complete the script

while True:
    print("Sending malicious ARP packets")
    # Craft a malicious ARP packet to poison the victim ARP table to point to m>
    # broadcast = Ether(dst=...)
    # arp = ARP(...........................................)
    sendp(broadcast / arp, verbose= False)

    time.sleep(1)

