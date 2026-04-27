from scapy.all import *

def show_pkt(pkt):
    # Packet Inspection
    print("Ethernet src: " + str(pkt[Ether].src))
    print("Ethernet dst: " + str(pkt[Ether].dst))

    print("IP src: " + str(pkt[IP].src))
    print("IP dst: " + str(pkt[IP].dst))

    print("TCP sport: " + str(pkt[TCP].sport))
    print("TCP dport: " + str(pkt[TCP].dport))
    print("TCP flags: " + str(pkt[TCP].flags))
    print("TCP seq: " + str(pkt[TCP].seq))
    print("TCP ack: " + str(pkt[TCP].ack))

# Raw is the payload of the TCP header
    if Raw in pkt:
        print("data: " + str(pkt[Raw].load))
        print("data len: " + str(len(pkt[Raw].load)))
    print("----------------------")

print("----------------------")
sniff(filter="tcp", iface="eth0", prn=show_pkt)
