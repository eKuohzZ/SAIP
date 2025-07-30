#!/usr/bin/env python3
# -*- coding:utf8 -*-
import argparse
import csv
import dpkt
from functools import partial
import os
from scapy.all import raw, IP, TCP, Raw
import signal
import socket
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import utils.conf as cf
import utils.vps as vpcf

BUFFER_SIZE = 1000
RING_BUFFER_SIZE = 8*1024*1024

vps = vpcf.VPsConfig()


def tcp_flags_str(flags):
    # define a list of tuples, each containing a flag name and its corresponding bitmask
    flags_names = [
        ('F', dpkt.tcp.TH_FIN),
        ('S', dpkt.tcp.TH_SYN),
        ('R', dpkt.tcp.TH_RST),
        ('P', dpkt.tcp.TH_PUSH),
        ('A', dpkt.tcp.TH_ACK),
        ('U', dpkt.tcp.TH_URG),
        ('E', dpkt.tcp.TH_ECE),
        ('C', dpkt.tcp.TH_CWR)
    ]
    # iterate over the list of tuples and check if the flag is set
    active_flags = [name for name, bitmask in flags_names if flags & bitmask != 0]
    # return a string containing all the flags that are set
    return ''.join(active_flags)

def handle_termination_signal(output_file, writer, write_buffer, signum, frame):
    print("Process is terminating. Flushing data...")
    if not output_file.closed:
        if write_buffer:
            writer.writerows(write_buffer)
            write_buffer.clear()
        output_file.flush()
        output_file.close()
    sys.exit(0)

def update_checksums(buf):
    pkt = IP(buf)      # 把字节流重新解析成 Scapy 包
    del pkt[IP].chksum # 删掉旧校验和字段
    del pkt[TCP].chksum
    return bytearray(bytes(pkt))

def send_response_bytes(sock, template, dst_ip, sport, dport, seq, ack):
    buf = bytearray(template)  # copy template
    # IP dst
    buf[16:20] = socket.inet_aton(dst_ip)
    # TCP sport, dport
    buf[20:22] = sport.to_bytes(2, 'big')
    buf[22:24] = dport.to_bytes(2, 'big')
    # TCP seq, ack
    buf[24:28] = seq.to_bytes(4, 'big')
    buf[28:32] = ack.to_bytes(4, 'big')
    buf = update_checksums(buf)
    sock.sendto(bytes(buf), (dst_ip, 0))

def process_tcp():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYMMDD')
    parser.add_argument('--method', type=str, help='tcp, tcp_s or tcp_a')
    parser.add_argument('--mID', type=int, help='ID of experiment')
    parser.add_argument('--spoofer', type=int, help='ID of spoofer')
    parser.add_argument('--observer', type=int, help='ID of observer')
    date = parser.parse_args().date
    method = parser.parse_args().method
    experiment_id = parser.parse_args().mID
    spoofer_id = parser.parse_args().spoofer
    observer_id = parser.parse_args().observer
    port_list = cf.get_tcp_port(method)
    observer = vps.get_vp_by_id(observer_id)
    data_path = cf.get_data_path(date, experiment_id, 'ipv4')
    # define output file
    local_tcp_result_dir = '{}/{}_result'.format(data_path, method)
    if not os.path.exists(local_tcp_result_dir):
        os.makedirs(local_tcp_result_dir)
    local_tcp_result_file = '{}/{}_result/{}-{}.csv'.format(data_path, method, spoofer_id, observer_id)
    
    # 使用批量写入缓存
    write_buffer = []
    
    # 创建文件时设置更大的缓冲区
    output_file = open(local_tcp_result_file, 'w', newline='', buffering=RING_BUFFER_SIZE)
    writer = csv.writer(output_file)

    handler_with_file = partial(handle_termination_signal, output_file, writer, write_buffer)
    signal.signal(signal.SIGTERM, handler_with_file)
    signal.signal(signal.SIGINT,  handler_with_file)

    # build raw socket for responses
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # pre-build response template with payload "Hello"
    base_resp = (
        IP(src=observer.private_addr_4, dst="0.0.0.0", proto=6) /
        TCP(sport=0, dport=0, flags="A", seq=0, ack=0) /
        Raw(load=b"Hello")
    )
    template_resp = raw(base_resp)
    
    pcap = dpkt.pcap.Reader(sys.stdin.buffer)
    
    try:
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                    
                ip_src = socket.inet_ntoa(ip.src)
                ip_ttl = ip.ttl
                tcp_dport = tcp.dport
                tcp_sport = tcp.sport
                tcp_ack = tcp.ack
                tcp_seq = tcp.seq
                tcp_flags = tcp_flags_str(tcp.flags)
                
                if tcp_dport in port_list:
                    write_buffer.append([tcp_flags, tcp_seq, tcp_ack, ip_src, tcp_sport, tcp_dport, ip_ttl, timestamp])
                    
                    if tcp_flags == 'SA' and tcp_ack == 1001:
                        send_response_bytes(
                            sock,
                            template_resp,
                            ip_src,
                            sport=tcp_dport,
                            dport=tcp_sport,
                            seq=tcp_ack,
                            ack=(tcp_seq + 1)
                        )
                    if len(write_buffer) >= BUFFER_SIZE:
                        writer.writerows(write_buffer)
                        write_buffer.clear()
                        
            except Exception as e:
                continue
                
    finally:
        if sock:
            sock.close()
        # 确保剩余数据被写入
        if not output_file.closed:
            if write_buffer:
                writer.writerows(write_buffer)
                write_buffer.clear()
            output_file.flush()
            output_file.close()

if __name__ == '__main__':
    process_tcp()