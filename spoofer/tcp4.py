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
import subprocess
import multiprocessing
import random
from signal2observer import start_sniff, stop_sniff

def get_mac(target_ip):
    while True:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]
        if result:
            return result[0][1].hwsrc
        
user_home = os.path.expanduser('~')
skt2 = conf.L2socket()
skt3 = conf.L3socket()
gateway = ni.gateways()['default'][ni.AF_INET][0]
macaddr = get_mac(gateway)

etherPkt = raw(Ether(dst=macaddr, type=0x0800))

def TCPsend(date, mID, spoofer, observer, targetFile):
    #向observer发送start信号
    print('Spoofer: tell observer to start sniff...')
    start_sniff('tcp', spoofer, observer, date, mID)
    #开始发包
    print('Spoofer: TCP send start...')
    with open(targetFile) as ifile:
        lines = ifile.readlines()
        random.shuffle(lines)
        for line in tqdm.tqdm(lines):
            line = line.strip()
            target = line.split(',')[0]
            dport = int(line.split(',')[1])
            port_list = random.sample(range(40000, 50000), 10)
            for sport in port_list:
                iptcpPkt = raw(IP(src=vpInfo[observer]['publicAddr'], dst=target) / TCP(sport=sport, dport=dport, flags="S", seq=1000))
                packet = etherPkt + iptcpPkt
                skt2.send(packet)
                time.sleep(0.004)
                #time.sleep(0.0003)
    print('Spoofer: TCP send end!')
    time.sleep(30)
     #向observer发送stop信号
    print('Spoofer: tell observer to stop sniff...')
    stop_sniff('tcp', spoofer, observer, date, mID)

if __name__ == "__main__":
    TCPsend(date='', mID='1', spoofer='SAV01', observer='HK1', targetFile='')
