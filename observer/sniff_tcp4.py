# -*- coding:utf8 -*-
import sys
import csv
import socket

from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import netifaces as ni
import dpkt
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

def tcp_flags_str(flags):
    # define a list of tuples, each containing a flag name and its corresponding bitmask
    flags_names = [
        ('F', dpkt.tcp.TH_FIN),
        ('S', dpkt.tcp.TH_SYN),
        ('R', dpkt.tcp.TH_RST),
        ('P', dpkt.tcp.TH_PUSH),
        ('A', dpkt.tcp.TH_ACK),
        ('U', dpkt.tcp.TH_URG),
        ('E', dpkt.tcp.TH_ECE),
        ('C', dpkt.tcp.TH_CWR)
    ]
    # iterate over the list of tuples and check if the flag is set
    active_flags = [name for name, bitmask in flags_names if flags & bitmask != 0]
    # return a string containing all the flags that are set
    return ''.join(active_flags)

def process_tcp():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYMMDD')
    parser.add_argument('--method', type=str, help='tcp, tcp_s or tcp_a')
    parser.add_argument('--mID', type=int, help='ID of experiment')
    parser.add_argument('--spoofer', type=int, help='ID of spoofer')
    parser.add_argument('--observer', type=int, help='ID of observer')
    date = parser.parse_args().date
    method = parser.parse_args().method
    experiment_id = parser.parse_args().mID
    spoofer_id = parser.parse_args().spoofer
    observer_id = parser.parse_args().observer

    port_list = cf.get_tcp_port(method)
    observer = vps.get_vp_by_id(observer_id)
    # define output file
    local_tcp_result_file = '{}/{}_result-{}-{}-{}-{}.csv'.format(data_path, method, date, experiment_id, spoofer_id, observer_id)
    output_file = open(local_tcp_result_file, 'w', newline='')
    writer = csv.writer(output_file)
    # receive data from tcpdump
    pcap = dpkt.pcap.Reader(sys.stdin.buffer)
    for timestamp, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
                
            ip_src = socket.inet_ntoa(ip.src)
            ip_ttl = ip.ttl
            tcp_dport = tcp.dport
            tcp_sport = tcp.sport
            tcp_ack = tcp.ack
            tcp_seq = tcp.seq
            tcp_flags = tcp_flags_str(tcp.flags)
            if tcp_dport in port_list:
                # send ACK (second handshake)
                if tcp_flags == 'SA' and tcp_ack == 1001:
                    data = (
                        b"Hello"
                    )
                    iptcpPkt = raw(IP(src=observer.private_addr, dst=ip_src) / TCP(sport=tcp_dport, dport=tcp_sport, flags="A", seq=tcp_ack, ack=tcp_seq+1)/Raw(load=data))
                    packet = etherPkt + iptcpPkt    
                    skt2.send(packet)
                writer.writerow([tcp_flags, tcp_seq, tcp_ack, ip_src, tcp_sport, tcp_dport, ip_ttl, timestamp])
        except:
            pass
        
    output_file.close()

if __name__ == '__main__':
    process_tcp()