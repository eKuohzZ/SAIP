# -*- coding:utf8 -*-
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR
import subprocess
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import utils.conf as cf

vps = cf.VPsConfig()

def tcp_sniff():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYYY-mm-dd')
    parser.add_argument('--method', type=str, help='tcp, tcp_s or tcp_a')
    parser.add_argument('--mID', type=int, help='ID of experiment')
    parser.add_argument('--spoofer', type=int, help='ID of spoofer')
    parser.add_argument('--observer', type=int, help='ID of observer')
    date = parser.parse_args().date
    method = parser.parse_args().method
    experiment_id = parser.parse_args().mID
    spoofer_id = parser.parse_args().spoofer
    observer_id = parser.parse_args().observer
    print('start sniffing TCP packets...')
    observer = vps.get_vp_by_id(observer_id)
    #tcpdump
    command_tcpdump = "tcpdump -i {} -nn 'src not {} and (dst {} or dst {}) and tcp' -w - -U".format(
    observer.network_interface, 
    observer.private_addr, 
    observer.public_addr, 
    observer.private_addr
)
    #tcp packet process script
    command_process = "python3 {} --date {} --method {} --mID {} --spoofer {} --observer {}".format(os.path.join(current_dir, 'sniff_tcp4.py'), date, method, experiment_id, spoofer_id, observer_id)
    #tcpdump sniffing and send to process script
    process_tcpdump = subprocess.Popen(command_tcpdump, shell=True, stdout=subprocess.PIPE)
    process_process = subprocess.Popen(command_process, shell=True, stdin=process_tcpdump.stdout)
    process_process.wait()
    print('end sniffing TCP packets!')

if __name__ == '__main__':
    tcp_sniff()
