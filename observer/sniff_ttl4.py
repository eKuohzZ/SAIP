# -*- coding:utf8 -*-
import sys
import csv
import socket

from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import netifaces as ni
import dpkt
import  argparse

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

# create socket
skt2 = conf.L2socket()
# get gateway and mac address
gateway = ni.gateways()['default'][ni.AF_INET][0]
macaddr = get_mac(gateway)
# build packet header
data = 'haha'
ether_pkt = raw(Ether(dst=macaddr, type=0x0800))
icmp_pkt = raw(ICMP(id=1599, seq=2496) / data)

def process_ttl():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYMMDD')
    parser.add_argument('--mID', type=int, help='ID of measurement')
    parser.add_argument('--spoofer', type=int, help='ID of spoofer')
    parser.add_argument('--observer', type=int, help='ID of observer')
    date = parser.parse_args().date
    measurement_id = parser.parse_args().mID
    spoofer_id = parser.parse_args().spoofer
    observer_id = parser.parse_args().observer
    observer = vps.get_vp_by_id(observer_id)
    # define output file
    local_ttl_result_file = '{}/ttl_result-{}-{}-{}-{}.csv'.format(data_path, date, measurement_id, spoofer_id, observer_id)
    output_file = open(local_ttl_result_file, 'w', newline='')
    writer = csv.writer(output_file)
    # receive data from tcpdump
    pcap = dpkt.pcap.Reader(sys.stdin.buffer)
    for _, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            icmp = ip.data.data
            
            ip_src = socket.inet_ntoa(ip.src)
            ip_ttl = ip.ttl
            icmp_id = icmp.id
            icmp_seq = icmp.seq
            writer.writerow([ip_src, str(icmp_id), str(icmp_seq), ip_ttl])
            if icmp_id == 1459 or icmp_seq == 2636:
                #ping Target
                ip_pkt = raw(IP(src=observer.private_addr, dst=ip_src, proto=1, len=32, ttl=64))
                packet = ether_pkt + ip_pkt + icmp_pkt
                skt2.send(packet)
        except:
            pass 

    output_file.close()

if __name__ == '__main__':
    process_ttl()
