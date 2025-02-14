# -*- coding:utf8 -*-
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import time
import sys
import csv
import os
import datetime
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from utils.conf import vpInfo
from functools import partial
import subprocess
import argparse

user_home = os.path.expanduser('~')
data_path = user_home + '/.saip'
if not os.path.exists(data_path):
    os.makedirs(data_path)

def TCPsniff():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYYY-mm-dd')
    parser.add_argument('--mID', type=str, help='ID of measurement')
    parser.add_argument('--spoofer', type=str, help='name of spoofer')
    parser.add_argument('--observer', type=str, help='name of observer')
    date = parser.parse_args().date
    mID = parser.parse_args().mID
    spoofer = parser.parse_args().spoofer
    observer = parser.parse_args().observer
    print('Observer: TCP measure start...')
    #tcpdump
    command_tcpdump = "tcpdump -i {} -nn src not {} and tcp -w -".format(vpInfo[observer]['netInterface'], vpInfo[observer]['privateAddr'])
    #tcp包处理脚本
    command_process = "python3 sniff_tcp4.py --date {} --mID {} --spoofer {} --observer {}".format(date, mID, spoofer, observer)
    #tcpdump抓包并输送至处理脚本进行处理
    process_tcpdump = subprocess.Popen(command_tcpdump, shell=True, stdout=subprocess.PIPE)
    process_process = subprocess.Popen(command_process, shell=True, stdin=process_tcpdump.stdout)
    process_process.wait()
    print('Observer: TCP measure end!')


if __name__ == "__main__":
    TCPsniff()