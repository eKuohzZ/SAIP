# -*- coding:utf8 -*-
import time

from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import tqdm
import netifaces as ni
import multiprocessing
import random
import argparse

import utils.conf as cf

vps = cf.VPsConfig()
data_path = cf.get_data_path()

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

def tcp_send(observer_id, target_file, pps):
    observer = vps.get_vp_by_id(observer_id)
    interval = 1/pps
    print('start sending TCPa packets...')
    with open(target_file) as ifile:
        lines = ifile.readlines()
        random.shuffle(lines)
        data = b"Hello"
        for line in tqdm.tqdm(lines):
            line = line.strip()
            target = line.split(',')[0]
            dport = int(line.split(',')[1])
            sample_len = min(cf.get_number_of_ports('tcpa'), cf.get_number_of_ports('tcpa'))
            port_list = random.sample(cf.get_tcp_port('tcpa'), sample_len)
            for sport in port_list:
                start_time = time.time()
                iptcpPkt = raw(IP(src=observer.private_addr, dst=target) / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=21324) / Raw(load=data))
                packet = etherPkt + iptcpPkt
                skt2.send(packet)
                end_time = time.time()
                elapsed = end_time - start_time
                if elapsed < interval:
                    time.sleep(interval - elapsed)
    print('end sending TCPa packets!')

def do_tcp_measure():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYMMDD')
    parser.add_argument('--mID', type=int, help='ID of measurement')
    parser.add_argument('--spoofer', type=int, help='ID of spoofer')
    parser.add_argument('--observer', type=int, help='ID of observer')
    parser.add_argument('--pps', type=int, help='Packets per second')
    date = parser.parse_args().date
    measurement_id = parser.parse_args().mID
    spoofer_id = parser.parse_args().spoofer
    observer_id = parser.parse_args().observer
    pps = parser.parse_args().pps
    target_file = '{}/hitlist_tcp-{}-{}.csv'.format(data_path, date, measurement_id)
    send_process = multiprocessing.Process(target=tcp_send, args=(observer_id, target_file, pps))
    send_process.start()
    send_process.join()
