from scapy.all import *

def show_pkt(pkt):
    pkt.show()

sniff(filter="", iface="eth0", prn=show_pkt)

