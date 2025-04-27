# -*- coding:utf8 -*-
import sys
import csv
import socket
import signal

from functools import partial
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import netifaces as ni
import dpkt
import  argparse

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import utils.conf as cf

BUFFER_SIZE = 1000
RING_BUFFER_SIZE = 8*1024*1024

vps = cf.VPsConfig()

def get_mac(target_ip):
    while True:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]
        if result:
            return result[0][1].hwsrc

# create socket
#skt2 = conf.L2socket()
skt3 = conf.L3socket()
# get gateway and mac address
#gateway = ni.gateways()['default'][ni.AF_INET][0]
#macaddr = get_mac(gateway)
# build packet header
#data = 'haha'
#ether_pkt = raw(Ether(dst=macaddr, type=0x0800))
#icmp_pkt = raw(ICMP(id=1599, seq=2496) / data)

def handle_termination_signal(output_file, writer, write_buffer, signum, frame):
    print("Process is terminating. Flushing data...")
    if not output_file.closed:
        if write_buffer:
            writer.writerows(write_buffer)
            write_buffer.clear()
        output_file.flush()
        output_file.close()
    sys.exit(0)

def process_ttl():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYMMDD')
    parser.add_argument('--mID', type=int, help='ID of experiment')
    parser.add_argument('--spoofer', type=int, help='ID of spoofer')
    parser.add_argument('--observer', type=int, help='ID of observer')
    date = parser.parse_args().date
    experiment_id = parser.parse_args().mID
    spoofer_id = parser.parse_args().spoofer
    observer_id = parser.parse_args().observer
    observer = vps.get_vp_by_id(observer_id)
    data_path = cf.get_data_path(date, experiment_id)
    # define output file
    local_ttl_result_dir = '{}/ttl_result'.format(data_path)
    if not os.path.exists(local_ttl_result_dir):
        os.makedirs(local_ttl_result_dir)
    local_ttl_result_file = '{}/ttl_result/{}-{}.csv'.format(data_path, spoofer_id, observer_id)
    
    write_buffer = []

    output_file = open(local_ttl_result_file, 'w', newline='', buffering=RING_BUFFER_SIZE)
    writer = csv.writer(output_file)
    handler_with_file = partial(handle_termination_signal, output_file, writer, write_buffer)
    signal.signal(signal.SIGTERM, handler_with_file)
    signal.signal(signal.SIGINT,  handler_with_file)
    # receive data from tcpdump
    pcap = dpkt.pcap.Reader(sys.stdin.buffer)
    try:
        for _, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                icmp = ip.data.data
                
                ip_src = socket.inet_ntoa(ip.src)
                ip_ttl = ip.ttl
                icmp_id = icmp.id
                icmp_seq = icmp.seq
                #print('Received ICMP packet from {}: id={}, seq={}, ttl={}'.format(ip_src, icmp_id, icmp_seq, ip_ttl))
                write_buffer.append([ip_src, str(icmp_id), str(icmp_seq), ip_ttl])
                #output_file.flush()
                if icmp_id == 1459 or icmp_seq == 2636:
                    #ping Target
                    ip_pkt = IP(src=observer.private_addr, dst=ip_src, proto=1, ttl=64)
                    icmp_pkt = ICMP(type=8, id=1599, seq=2496) 
                    packet = ip_pkt / icmp_pkt / b'haha'
                    skt3.send(packet)
                if len(write_buffer) >= BUFFER_SIZE:
                    writer.writerows(write_buffer)
                    write_buffer.clear()
            except Exception as e:
                continue

    finally:
        if not output_file.closed:
            if write_buffer:
                writer.writerows(write_buffer)
                write_buffer.clear()
            output_file.flush()
            output_file.close()

if __name__ == '__main__':
    process_ttl()
