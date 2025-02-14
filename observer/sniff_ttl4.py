# -*- coding:utf8 -*-
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import time
import sys
import csv
import os
import datetime
import time
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from conf.conf import vpInfo
from functools import partial
import netifaces as ni
import dpkt
import socket
import  argparse
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
#创建套接字
skt2 = conf.L2socket()
#获取网关ip及mac地址
gateway = ni.gateways()['default'][ni.AF_INET][0]
macaddr = get_mac(gateway)
#预创建以太网帧头部和icmp报文
data = 'haha'
etherPkt = raw(Ether(dst=macaddr, type=0x0800))
icmpPkt = raw(ICMP(id=1599, seq=2496) / data)

def process_ttl():
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
    output_file = '{}/measurement_result_ttl-{}-{}.csv'.format(data_path, date, mID)
    ofile = open(output_file, 'w', newline='')
    writer = csv.writer(ofile)
    #接收来自tcpdump的输入
    pcap = dpkt.pcap.Reader(sys.stdin.buffer)
    for timestamp, buf in pcap:
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
                ipPkt = raw(IP(src=vpInfo[observer]['privateAddr'], dst=ip_src, proto=1, len=32, ttl=64))
                packet = etherPkt + ipPkt + icmpPkt
                skt2.send(packet)
        except:
            pass 

    ofile.close()


if __name__ == "__main__":
    process_ttl()