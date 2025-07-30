#!/usr/bin/env python3
# -*- coding:utf8 -*-
import argparse
import csv
import dpkt
from functools import partial
import os
from scapy.all import raw, IPv6, TCP, Raw
import signal
import socket
import struct
import sys

# Define IPV6_HDRINCL constant if not available in socket module
if not hasattr(socket, 'IPV6_HDRINCL'):
    socket.IPV6_HDRINCL = 36  # Standard value for IPv6_HDRINCL

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import utils.conf as cf
import utils.vps as vpcf

BUFFER_SIZE = 1000
RING_BUFFER_SIZE = 8*1024*1024

vps = vpcf.VPsConfig()


def tcp_flags_str(flags):
    """
    Convert TCP flags to string representation
    """
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
    active_flags = [name for name, bitmask in flags_names if flags & bitmask != 0]
    return ''.join(active_flags)

def handle_termination_signal(output_file, writer, write_buffer, signum, frame):
    """
    Handle termination signals and flush remaining data
    """
    print("Process is terminating. Flushing data...")
    if not output_file.closed:
        if write_buffer:
            writer.writerows(write_buffer)
            write_buffer.clear()
        output_file.flush()
        output_file.close()
    sys.exit(0)

def update_checksums_ipv6(buf):
    pkt = IPv6(buf)      # 把字节流重新解析成 Scapy 包
    del pkt[TCP].chksum  # 删掉旧的TCP校验和字段
    return bytearray(bytes(pkt))

def send_response_bytes_ipv6(sock, template, dst_ip, sport, dport, seq, ack):
    buf = bytearray(template)  # copy template
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    buf[24:40] = dst_bytes
    buf[40:42] = sport.to_bytes(2, 'big')
    buf[42:44] = dport.to_bytes(2, 'big')
    buf[44:48] = seq.to_bytes(4, 'big')
    buf[48:52] = ack.to_bytes(4, 'big')
    buf = update_checksums_ipv6(buf)
    
    sock.sendto(bytes(buf), (dst_ip, 0))

def process_tcp6():
    parser = argparse.ArgumentParser(description='IPv6 TCP packet processor')
    parser.add_argument('--date', type=str, required=True, help='Date in YYMMDD format')
    parser.add_argument('--method', type=str, required=True, help='tcp, tcps or tcpa')
    parser.add_argument('--mID', type=int, required=True, help='Measurement ID')
    parser.add_argument('--spoofer', type=int, required=True, help='Spoofer VPS ID')
    parser.add_argument('--observer', type=int, required=True, help='Observer VPS ID')
    args = parser.parse_args()
    
    date = args.date
    method = args.method
    experiment_id = args.mID
    spoofer_id = args.spoofer
    observer_id = args.observer
    # Get configuration
    port_list = cf.get_tcp_port(method)
    observer = vps.get_vp_by_id(observer_id)
    data_path = cf.get_data_path(date, experiment_id, 'ipv6')
    # Define output file
    local_tcp_result_dir = '{}/{}_result'.format(data_path, method)
    if not os.path.exists(local_tcp_result_dir):
        os.makedirs(local_tcp_result_dir)
    local_tcp_result_file = '{}/{}_result/{}-{}.csv'.format(data_path, method, spoofer_id, observer_id)
    
    # Use batch writing buffer
    write_buffer = []
    
    # Create file with larger buffer
    output_file = open(local_tcp_result_file, 'w', newline='', buffering=RING_BUFFER_SIZE)
    writer = csv.writer(output_file)

    handler_with_file = partial(handle_termination_signal, output_file, writer, write_buffer)
    signal.signal(signal.SIGTERM, handler_with_file)
    signal.signal(signal.SIGINT, handler_with_file)

    # Build raw IPv6 socket for responses
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # Try to set IPV6_HDRINCL option
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HDRINCL, 1)
        except (AttributeError, OSError) as e:
            print(f"Warning: Cannot set IPV6_HDRINCL option: {e}")
    except Exception as e:
        print(f"Error creating IPv6 raw socket: {e}")
        sock = None

    # Pre-build response template with payload "Hello"
    base_resp = (
        IPv6(src=observer.private_addr_6, dst="::", nh=6, hlim=64) /
        TCP(sport=0, dport=0, flags="A", seq=0, ack=0) /
        Raw(load=b"Hello")
    )
    template_resp = raw(base_resp)
    
    pcap = dpkt.pcap.Reader(sys.stdin.buffer)
    
    try:
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip6 = eth.data
                tcp = ip6.data
                    
                ip_src = socket.inet_ntop(socket.AF_INET6, ip6.src)
                ip_hlim = ip6.hlim  # Hop limit (equivalent to TTL in IPv4)
                tcp_dport = tcp.dport
                tcp_sport = tcp.sport
                tcp_ack = tcp.ack
                tcp_seq = tcp.seq
                tcp_flags = tcp_flags_str(tcp.flags)
                
                if tcp_dport in port_list:
                    write_buffer.append([tcp_flags, tcp_seq, tcp_ack, ip_src, tcp_sport, tcp_dport, ip_hlim, timestamp])
                    
                    if sock and tcp_flags == 'SA' and tcp_ack == 1001:
                        send_response_bytes_ipv6(
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
        # Ensure remaining data is written
        if not output_file.closed:
            if write_buffer:
                writer.writerows(write_buffer)
                write_buffer.clear()
            output_file.flush()
            output_file.close()
        

if __name__ == '__main__':
    process_tcp6() 