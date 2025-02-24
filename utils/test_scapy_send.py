from scapy.all import *
import netifaces as ni

def get_mac(target_ip):
    while True:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]
        if result:
            return result[0][1].hwsrc
        
skt2 = conf.L2socket()
skt3 = conf.L3socket()
conf.iface = "ppp0"
iptcp_pkt = IP(src='193.3.191.30', dst='194.59.31.66') / TCP(sport=37001, dport=37001, flags="S", seq=1000)

pkt = iptcp_pkt
pkt.show()
for i in range(10):
    skt3.send(pkt)

