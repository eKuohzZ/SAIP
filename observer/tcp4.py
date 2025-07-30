#!/usr/bin/env python3
# -*- coding:utf8 -*-
import argparse
import os
import subprocess
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import utils.vps as vpcf
import utils.conf as cf

RING_BUFFER_MIB = 8192   # tcpdump -B value
SNAPLEN = 96             # tcpdump -s value (enough for TCP header)

def tcp_sniff():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', required=True)
    parser.add_argument('--method', required=True, choices=['tcp', 'tcps', 'tcpa'])
    parser.add_argument('--mID', required=True, type=int)
    parser.add_argument('--spoofer', required=True, type=int)
    parser.add_argument('--observer', required=True, type=int)
    args = parser.parse_args()

    vps = vpcf.VPsConfig()
    observer = vps.get_vp_by_id(args.observer)

    # Build BPF: src not <private_ip> and (dst port p1 or dst port p2 …) and tcp
    port_list = cf.get_tcp_port(args.method)
    port_expr = ' or '.join(f'dst port {p}' for p in port_list)
    bpf = f"src not {observer.private_addr_4} and ({port_expr}) and tcp"

    print('start sniffing TCP packets...')
    #tcpdump
    tcpdump_cmd = [
        'tcpdump', '-i', observer.network_interface_4,
        '-nn', f'-B{RING_BUFFER_MIB}', f'-s{SNAPLEN}', '-U',
        bpf, '-w', '-',
    ]

    #tcp packet process script
    process_cmd = [
        'python3', os.path.join(current_dir, 'sniff_tcp4.py'),
        '--date', args.date,
        '--method', args.method,
        '--mID', str(args.mID),
        '--spoofer', str(args.spoofer),
        '--observer', str(args.observer),
    ]
    #tcpdump sniffing and send to process script
    with subprocess.Popen(tcpdump_cmd, stdout=subprocess.PIPE) as pcap_proc, subprocess.Popen(process_cmd, stdin=pcap_proc.stdout) as worker_proc:
        worker_proc.wait()
    print('end sniffing TCP packets!')

if __name__ == '__main__':
    tcp_sniff()
