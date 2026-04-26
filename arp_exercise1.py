from scapy.all import *

VICTIM_IP = "192.168.101.10"

# A Simple ping request to the Victim
# Packets are built by stacking layers on top of each other
icmp = IP(dst=VICTIM_IP) / ICMP() 

# Send an ICMP request
send(icmp)

