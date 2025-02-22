# -*- coding:utf8 -*-
import time

from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import tqdm
import netifaces as ni

import utils.conf as cf
import utils.measurement as ms
import signals


vps = cf.VPsConfig()

def get_mac(target_ip):
    while True:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]
        if result:
            return result[0][1].hwsrc

#create socket
skt2 = conf.L2socket()
skt3 = conf.L3socket()
#get gateway and mac address
gateway = ni.gateways()['default'][ni.AF_INET][0]
macaddr = get_mac(gateway)
#build packet header
ether_pkt = raw(Ether(dst=macaddr, type=0x0800))
icmp_pkt = raw(ICMP(id=1459, seq=2636) / b'haha')

def ttl_send(measurement: ms.Measurement, target_file):
    #setting
    observer = vps.get_vp_by_id(measurement.observer_id)
    interval = 1/measurement.pps
    #send start signal to observer
    print('tell observer to start sniff...')
    signals.observer_start_sniff(measurement)
    #start sending packets
    print('start sending ICMP packets...')
    with open(target_file) as ifile:
        lines = ifile.readlines()
        for _ in range(3):
            for line in tqdm.tqdm(lines, desc='scan icmp: '):
                start_time = time.time()
                ttl = 64
                target = line.strip()
                #向target发伪造包
                ip_pkt = raw(IP(src=observer.public_addr, dst=target, ttl=ttl, proto=1, len=32))
                packet = ether_pkt + ip_pkt + icmp_pkt
                skt2.send(packet)
                end_time = time.time()
                elapsed = end_time - start_time
                #control the sending speed
                if elapsed < interval:
                    time.sleep(interval - elapsed)
    print('end sending ICMP packets!')
    time.sleep(120)
    #send stop signal to observer
    print('tell observer to stop sniff...')
    signals.observer_stop_sniff(measurement)
    #tell analyzer this measurement is done
