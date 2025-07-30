# -*- coding:utf8 -*-
import argparse
import csv
import dpkt
from functools import partial
import os
from scapy.all import raw, IP, ICMP, Raw
import signal
import socket
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import utils.vps as vpcf
import utils.conf as cf
BUFFER_SIZE = 1000
RING_BUFFER_SIZE = 8*1024*1024

vps = vpcf.VPsConfig()

def handle_termination_signal(output_file, writer, write_buffer, signum, frame):
    print("Process is terminating. Flushing data...")
    if not output_file.closed:
        if write_buffer:
            writer.writerows(write_buffer)
            write_buffer.clear()
        output_file.flush()
        output_file.close()
    sys.exit(0)

def send_icmp_bytes(sock, template, dst_ip, ttl):
    buf = bytearray(template)      # 切记先复制！
    buf[8] = ttl                   # TTL
    buf[16:20] = socket.inet_aton(dst_ip)   # 目的地址

    # 重新计算校验和（IP + ICMP）
    pkt = IP(bytes(buf))           # 让 Scapy 重新解析
    del pkt[IP].chksum
    del pkt[ICMP].chksum
    buf = bytearray(bytes(pkt))    # 平展成新的原始字节

    sock.sendto(buf, (dst_ip, 0))

def process_ttl():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYMMDD')
    parser.add_argument('--mID', type=int, help='ID of experiment')
    parser.add_argument('--spoofer', type=int, help='ID of spoofer')
    parser.add_argument('--observer', type=int, help='ID of observer')
    date = parser.parse_args().date
    experiment_id = parser.parse_args().mID
    spoofer_id = parser.parse_args().spoofer
    observer_id = parser.parse_args().observer
    observer = vps.get_vp_by_id(observer_id)
    data_path = cf.get_data_path(date, experiment_id, 'ipv4')
    # define output file
    local_ttl_result_dir = '{}/ttl_result'.format(data_path)
    if not os.path.exists(local_ttl_result_dir):
        os.makedirs(local_ttl_result_dir)
    local_ttl_result_file = '{}/ttl_result/{}-{}.csv'.format(data_path, spoofer_id, observer_id)
    
    write_buffer = []

    output_file = open(local_ttl_result_file, 'w', newline='', buffering=RING_BUFFER_SIZE)
    writer = csv.writer(output_file)

    handler_with_file = partial(handle_termination_signal, output_file, writer, write_buffer)
    signal.signal(signal.SIGTERM, handler_with_file)
    signal.signal(signal.SIGINT,  handler_with_file)

     # --- build one raw socket & ICMP template ---
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    base = (
        IP(src=observer.private_addr_4, dst="0.0.0.0", ttl=64, proto=1) /
        ICMP(type=8, id=1599, seq=2496) /
        b'zknb'
    )
    template = bytearray(raw(base))

    # receive data from tcpdump
    pcap = dpkt.pcap.Reader(sys.stdin.buffer)
    try:
        for _, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                icmp = ip.data.data
                
                ip_src = socket.inet_ntoa(ip.src)
                ip_ttl = ip.ttl
                icmp_id = icmp.id
                icmp_seq = icmp.seq

                write_buffer.append([ip_src, str(icmp_id), str(icmp_seq), ip_ttl])

                if icmp_id == 1459 or icmp_seq == 2636:
                   send_icmp_bytes(sock, template, ip_src, ttl=64)
                if len(write_buffer) >= BUFFER_SIZE:
                    writer.writerows(write_buffer)
                    write_buffer.clear()
            except Exception as e:
                continue

    finally:
        if sock:
            sock.close()
        if not output_file.closed:
            if write_buffer:
                writer.writerows(write_buffer)
                write_buffer.clear()
            output_file.flush()
            output_file.close()

if __name__ == '__main__':
    process_ttl()
