from scapy.all import *

ATTACKER_MAC = "02:42:c0:a8:65:14"
VICTIM_IP = "192.168.101.10"
ATTACKER_IP = "192.168.101.20"

broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

arp = ARP(op=1, pdst=VICTIM_IP, psrc=ATTACKER_IP)
sendp(broadcast / arp, verbose=False)

