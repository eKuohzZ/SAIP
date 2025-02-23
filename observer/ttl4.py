# -*- coding:utf8 -*-
import argparse
import subprocess
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR

import utils.conf as cf

vps = cf.VPsConfig()
current_dir = os.path.dirname(os.path.abspath(__file__))

def ttl_sniff():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYMMDD')
    parser.add_argument('--mID', type=int, help='ID of experiment')
    parser.add_argument('--spoofer', type=int, help='ID of spoofer')
    parser.add_argument('--observer', type=int, help='ID of observer')
    date = parser.parse_args().date
    experiment_id = parser.parse_args().mID
    spoofer_id = parser.parse_args().spoofer
    observer_id = parser.parse_args().observer
    print('start sniffing ICMP packets...')
    observer = vps.get_vp_by_id(observer_id)
    #tcpdump
    command_tcpdump = "tcpdump -i {} -nn src not {} and (dst {} or dst {}) and icmp[icmptype] == 0 and icmp[icmpcode] == 0 -w -".format(
    observer.network_interface, 
    observer.private_addr, 
    observer.public_addr, 
    observer.private_addr
    )
    #icmp packet process script
    command_process_script = "python3 {} --date {} --mID {} --spoofer {} --observer {}".format(os.path.join(current_dir, 'sniff_ttl4.py'), date, experiment_id, spoofer_id, observer_id)
    #tcpdump sniffing and send to process script
    process_tcpdump = subprocess.Popen(command_tcpdump, shell=True, stdout=subprocess.PIPE)
    process_process_script = subprocess.Popen(command_process_script, shell=True, stdin=process_tcpdump.stdout)
    process_process_script.wait()
    print('end sniffing ICMP packets!')

if __name__ == '__main__':
    ttl_sniff()
