# -*- coding:utf8 -*-
import argparse
import csv
import dpkt
from functools import partial
import os
from scapy.all import raw, IPv6, ICMPv6EchoRequest
import signal
import socket
import struct
import sys

# Define IPV6_HDRINCL constant if not available in socket module
if not hasattr(socket, 'IPV6_HDRINCL'):
    socket.IPV6_HDRINCL = 36  # Standard value for IPv6_HDRINCL

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

def send_icmpv6_bytes(sock, template, dst_ip, hop_limit):
    buf = bytearray(template)
    buf[7] = hop_limit
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    buf[24:40] = dst_bytes
    recalculate_icmpv6_checksum(buf)
    
    sock.sendto(buf, (dst_ip, 0))

def recalculate_icmpv6_checksum(buf):
    buf[42:44] = b'\x00\x00'  # ICMPv6 checksum is at offset 42-43
    src_addr = buf[8:24]      # Source address
    dst_addr = buf[24:40]     # Destination address
    payload_len = struct.unpack('!H', buf[4:6])[0]  # Payload length
    next_header = buf[6]      # Next header (ICMPv6 = 58)
    pseudo_header = src_addr + dst_addr + struct.pack('!I', payload_len) + b'\x00\x00\x00' + struct.pack('!B', next_header)
    icmpv6_data = buf[40:40+payload_len]
    checksum_data = pseudo_header + icmpv6_data
    checksum = calculate_checksum(checksum_data)
    # Set checksum
    buf[42:44] = struct.pack('!H', checksum)

def calculate_checksum(data):
    # Pad data to even length
    if len(data) % 2:
        data += b'\x00'
    # Sum all 16-bit words
    checksum = 0
    for i in range(0, len(data), 2):
        word = struct.unpack('!H', data[i:i+2])[0]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    # One's complement
    return (~checksum) & 0xFFFF

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
    data_path = cf.get_data_path(date, experiment_id, 'ipv6')
    # Define output file
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

    # Build one raw IPv6 socket & ICMPv6 template
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        # Try to set IPV6_HDRINCL option
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HDRINCL, 1)
            print("Successfully set IPV6_HDRINCL option")
        except (AttributeError, OSError) as e:
            print(f"Warning: Cannot set IPV6_HDRINCL option: {e}")
            print("Continuing without this option - packet may work anyway")
    except Exception as e:
        print(f"Error creating IPv6 raw socket: {e}")
        return

    base = (
        IPv6(src=observer.private_addr_6, dst="::", hlim=64) /
        ICMPv6EchoRequest(id=1599, seq=2496, data=b'zknb')
    )
    template = bytearray(raw(base))

    # Receive data from tcpdump
    pcap = dpkt.pcap.Reader(sys.stdin.buffer)
    try:
        for _, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip6 = eth.data
                icmpv6 = ip6.data
                
                ip_src = socket.inet_ntop(socket.AF_INET6, ip6.src)
                ip_hlim = ip6.hlim  # Hop limit (equivalent to TTL in IPv4)
                icmpv6_data = bytes(icmpv6.data)
                if len(icmpv6_data) >= 4:
                    icmpv6_id = struct.unpack('!H', icmpv6_data[0:2])[0]
                    icmpv6_seq = struct.unpack('!H', icmpv6_data[2:4])[0]
                else:
                    icmpv6_id = 0
                    icmpv6_seq = 0

                write_buffer.append([ip_src, str(icmpv6_id), str(icmpv6_seq), ip_hlim])

                if icmpv6_id == 1459 or icmpv6_seq == 2636:
                    send_icmpv6_bytes(sock, template, ip_src, hop_limit=64)
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