# -*- coding:utf8 -*-
import time
import random

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
        
skt2 = conf.L2socket()
skt3 = conf.L3socket()
gateway = ni.gateways()['default'][ni.AF_INET][0]
macaddr = get_mac(gateway)
etherPkt = raw(Ether(dst=macaddr, type=0x0800))

def tcp_send(measurement: ms.Measurement, target_file):
    observer = vps.get_vp_by_id(measurement.observer_id)
    interval = 1/measurement.pps
    #send start signal to observer
    print('tell observer to start sniff...')
    signals.observer_start_sniff(measurement)
    #start sending packets
    print('start sending TCP packets...')
    with open(target_file) as ifile:
        lines = ifile.readlines()
        random.shuffle(lines)
        for line in tqdm.tqdm(lines):
            line = line.strip()
            target = line.split(',')[0]
            dport = int(line.split(',')[1])
            sample_len = min(cf.get_number_of_ports('tcp'), cf.get_number_of_ports('tcp'))
            port_list = random.sample(cf.get_tcp_port('tcp'), sample_len)
            for sport in port_list:
                start_time = time.time()
                iptcp_pkt = raw(IP(src=observer.public_addr, dst=target) / TCP(sport=sport, dport=dport, flags="S", seq=1000))
                packet = etherPkt + iptcp_pkt
                skt2.send(packet)
                end_time = time.time()
                elapsed = end_time - start_time
                #control the sending speed
                if elapsed < interval:
                    time.sleep(interval - elapsed)
    print('end sending TCP packets!')
    time.sleep(30)
    #send stop signal to observer
    print('tell observer to stop sniff...')
    signals.observer_stop_sniff(measurement)

