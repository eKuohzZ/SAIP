# -*- coding:utf8 -*-
import argparse
import subprocess
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import utils.vps as vpcf

vps = vpcf.VPsConfig()

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
    print('Start sniffing ICMPv6 packets...')
    observer = vps.get_vp_by_id(observer_id)
    # tcpdump command for IPv6 ICMPv6 packets
    # Filter: IPv6 ICMPv6 echo reply packets (type 129) not from observer itself
    command_tcpdump = "tcpdump -i {} -B 4096 -nn 'ip6 and src not {} and icmp6 and icmp6[0] == 129' -w - -U".format(
        observer.network_interface_6, 
        observer.private_addr_6
    )
    
    # ICMPv6 packet process script
    command_process_script = "python3 {} --date {} --mID {} --spoofer {} --observer {}".format(
        os.path.join(current_dir, 'sniff_ttl6.py'), 
        date, experiment_id, spoofer_id, observer_id
    )
    
    # tcpdump sniffing and send to process script
    process_tcpdump = subprocess.Popen(command_tcpdump, shell=True, stdout=subprocess.PIPE)
    process_process_script = subprocess.Popen(command_process_script, shell=True, stdin=process_tcpdump.stdout)
    process_process_script.wait()
    print('End sniffing ICMPv6 packets!')

if __name__ == '__main__':
    ttl_sniff() 