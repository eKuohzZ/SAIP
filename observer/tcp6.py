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
SNAPLEN = 128            # tcpdump -s value (increased for IPv6 header + TCP header)

def tcp6_sniff():
    parser = argparse.ArgumentParser(description='IPv6 TCP packet sniffer')
    parser.add_argument('--date', required=True, help='Date in YYMMDD format')
    parser.add_argument('--method', required=True, choices=['tcp', 'tcps', 'tcpa'], help='TCP scanning method')
    parser.add_argument('--mID', required=True, type=int, help='Measurement ID')
    parser.add_argument('--spoofer', required=True, type=int, help='Spoofer VPS ID')
    parser.add_argument('--observer', required=True, type=int, help='Observer VPS ID')
    args = parser.parse_args()

    vps = vpcf.VPsConfig()
    observer = vps.get_vp_by_id(args.observer)

    # Build BPF filter for IPv6: ip6 and src not <private_ipv6> and (dst port p1 or dst port p2 …) and tcp
    # Get port list based on method (assuming similar port configuration for IPv6)
    port_list = cf.get_tcp_port(args.method)
    port_expr = ' or '.join(f'dst port {p}' for p in port_list)
    bpf = f"ip6 and src not {observer.private_addr_6} and ({port_expr}) and tcp"

    print('Start sniffing IPv6 TCP packets...')
    # tcpdump command for IPv6
    tcpdump_cmd = [
        'tcpdump', '-i', observer.network_interface_6,
        '-nn', f'-B{RING_BUFFER_MIB}', f'-s{SNAPLEN}', '-U',
        bpf, '-w', '-',
    ]

    # IPv6 TCP packet process script
    process_cmd = [
        'python3', os.path.join(current_dir, 'sniff_tcp6.py'),
        '--date', args.date,
        '--method', args.method,
        '--mID', str(args.mID),
        '--spoofer', str(args.spoofer),
        '--observer', str(args.observer),
    ]
    
    #tcpdump sniffing and send to process script
    with subprocess.Popen(tcpdump_cmd, stdout=subprocess.PIPE) as pcap_proc, subprocess.Popen(process_cmd, stdin=pcap_proc.stdout) as worker_proc:
        worker_proc.wait()
    print('End sniffing IPv6 TCP packets!')

if __name__ == '__main__':
    tcp6_sniff()
