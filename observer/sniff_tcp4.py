# -*- coding:utf8 -*-
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import time
import sys
import csv
import os
import datetime
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from utils.conf import VPS
from functools import partial
import netifaces as ni
import dpkt
import socket
import argparse
import utils.S3BucketUtil as s3bu

def get_mac(target_ip):
    while True:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]
        if result:
            return result[0][1].hwsrc

user_home = os.path.expanduser('~')
data_path = user_home + '/.saip'
if not os.path.exists(data_path):
    os.makedirs(data_path)

skt2 = conf.L2socket()
skt3 = conf.L3socket()
gateway = ni.gateways()['default'][ni.AF_INET][0]
macaddr = get_mac(gateway)

etherPkt = raw(Ether(dst=macaddr, type=0x0800))

port_list = [i for i in range(40000, 50000)]

def tcp_flags_str(flags):
    # 定义TCP标志名称及其对应的位掩码值
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

    # 遍历所有标志，如果标志位被设置，则将其名称添加到列表中
    active_flags = [name for name, bitmask in flags_names if flags & bitmask != 0]

    # 将标志名称连接为字符串并返回
    return ''.join(active_flags)

def process_tcp():
    #接收参数
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYYY-mm-dd')
    parser.add_argument('--mID', type=str, help='ID of measurement')
    parser.add_argument('--spoofer', type=str, help='name of spoofer')
    parser.add_argument('--observer', type=str, help='name of observer')
    date = parser.parse_args().date
    mID = parser.parse_args().mID
    spoofer = parser.parse_args().spoofer
    observer = parser.parse_args().observer
    #定义输出文件
    output_file = '{}/measurement_result_tcp-{}-{}.csv'.format(data_path, date, mID)
    ofile = open(output_file, 'w', newline='')
    writer = csv.writer(ofile)
    #接收来自tcpdump的输入
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
                #第二次握手
                if tcp_flags == 'SA' and tcp_ack == 1001:
                    data = (
                        b"Hello"
                    )
                    iptcpPkt = raw(IP(src=vpInfo[observer]['privateAddr'], dst=ip_src) / TCP(sport=tcp_dport, dport=tcp_sport, flags="A", seq=tcp_ack, ack=tcp_seq+1)/Raw(load=data))
                    packet = etherPkt + iptcpPkt    
                    skt2.send(packet)
                writer.writerow([tcp_flags, tcp_seq, tcp_ack, ip_src, tcp_sport, tcp_dport, ip_ttl, timestamp])
        except:
            pass
        
    ofile.close()


if __name__ == "__main__":
    process_tcp()
    