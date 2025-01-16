# -*- coding:utf8 -*-
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import time
import sys
import csv
import os
import datetime
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from conf import vpInfo
from functools import partial
import threading
import tqdm
import netifaces as ni
import multiprocessing
from signal2observer import start_sniff, stop_sniff

def get_mac(target_ip):#获取mac地址
    while True:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]
        if result:
            return result[0][1].hwsrc

user_home = os.path.expanduser('~')
#创建socket
skt2 = conf.L2socket()
skt3 = conf.L3socket()
#获取网关ip与mac地址
gateway = ni.gateways()['default'][ni.AF_INET][0]
macaddr = get_mac(gateway)
#预先构建以网帧头部和icmp报文
data=b'haha'
etherPkt = raw(Ether(dst=macaddr, type=0x0800))
icmpPkt = raw(ICMP(id=1459, seq=2636) / data)

def TTLsend(date, mID, spoofer, observer, targetFile):
    #向observer发送start信号
    print('Spoofer: tell observer to start sniff...')
    start_sniff('ttl', spoofer, observer, date, mID)
    #开始发包
    print('Spoofer: TTL send start...')
    with open(targetFile) as ifile:
        lines = ifile.readlines()
        for seq in range(0, 3):
            for line in tqdm.tqdm(lines, desc='scan icmp: '):
                ttl = 64
                target = line.strip()
                #向target发伪造包
                ipPkt = raw(IP(src=vpInfo[observer]['publicAddr'], dst=target, ttl=ttl, proto=1, len=32))
                packet = etherPkt + ipPkt + icmpPkt
                skt2.send(packet)
                time.sleep(0.0003)
    print('Spoofer: TTL send end!')
    time.sleep(30)
    #向observer发送stop信号
    print('Spoofer: tell observer to stop sniff...')
    stop_sniff('ttl', spoofer, observer, date, mID)

if __name__ == "__main__":
    TTLsend(date='', mID = '0', spoofer='SAV01', observer='FRA1', targetFile='')