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

def get_mac(target_ip):
    while True:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=False)[0]
        if result:
            return result[0][1].hwsrc
        
user_home = os.path.expanduser('~')
nowtime = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
takebreak = 0.01
skt2 = conf.L2socket()
skt3 = conf.L3socket()
gateway = ni.gateways()['default'][ni.AF_INET][0]
macaddr = get_mac(gateway)

etherPkt = raw(Ether(dst=macaddr, type=0x0800))

port_list = []
with open(user_home+'/ipSAD/datasets/port_list.csv') as ifile:
    lines = ifile.readlines()
    for line in lines:
        port = int(line.strip())
        port_list.append(port)

def TCPsend(mID, spoofer, observer, targetFile):
    print('Spoofer: TCP send start...')
    with open(targetFile) as ifile:
        lines = ifile.readlines()
        random.shuffle(lines)
        for line in tqdm.tqdm(lines):
            line = line.strip()
            target = line.split(',')[0]
            port = int(line.split(',')[1])
            for seq in range(0, 1):
                iptcpPkt = raw(IP(src=vpInfo[observer]['privateAddr'], dst=target) / TCP(sport=port_list[2], dport=port, flags="S", seq=1000))
                packet = etherPkt + iptcpPkt
                skt2.send(packet)
                time.sleep(0.002)
                #time.sleep(0.0003)
    print('Spoofer: TCP send end!')

    

def doTCPmeasure(mID, spoofer, observer, targetFile):
    print('Spoofer: TCP measure start...')
    send_process = multiprocessing.Process(target=TCPsend, args=(mID, spoofer, observer, targetFile))
    send_process.start()
    send_process.join()
    print('Spoofer: TCP measure end!')


if __name__ == "__main__":
    doTCPmeasure(mID='1', spoofer='SAV01', observer='HK1', targetFile=user_home+'/ipSAD/datasets/testTarget10K.csv')
