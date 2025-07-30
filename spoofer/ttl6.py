# -*- coding:utf8 -*-
import random
import socket
import struct
from scapy.all import raw, IPv6, ICMPv6EchoRequest
import time
import tqdm

import utils.vps as vpcf
import utils.measurement as ms
import spoofer.signals as signals

# Define IPV6_HDRINCL constant if not available in socket module
if not hasattr(socket, 'IPV6_HDRINCL'):
    socket.IPV6_HDRINCL = 36  # Standard value for IPv6_HDRINCL

vps = vpcf.VPsConfig()

def send_icmpv6_bytes(sock, template, dst_ip, hop_limit):
    buf = bytearray(template)
    buf[7] = hop_limit
    buf[24:40] = socket.inet_pton(socket.AF_INET6, dst_ip)
    recalculate_icmpv6_checksum(buf)
    
    sock.sendto(buf, (dst_ip, 0))

def recalculate_icmpv6_checksum(buf):
    # Clear existing checksum
    buf[42:44] = b'\x00\x00'  # ICMPv6 checksum is at offset 42-43
    src_addr = buf[8:24]      
    dst_addr = buf[24:40]     
    payload_len = struct.unpack('!H', buf[4:6])[0]
    next_header = buf[6]     
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

def ttl_send(measurement: ms.Measurement, target_file):
    # Get observer configuration
    observer = vps.get_vp_by_id(measurement.observer_id)
    interval = 1 / measurement.pps 
        
    base = IPv6(src=observer.public_addr_6, dst="::", hlim=64) / ICMPv6EchoRequest(id=1459, seq=2636, data=b'zknb')
    template = bytearray(raw(base))

    # Create raw IPv6 socket
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        # Try to set IPV6_HDRINCL option
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HDRINCL, 1)
            print("Successfully set IPV6_HDRINCL option")
        except (AttributeError, OSError) as e:
            print(f"Warning: Cannot set IPV6_HDRINCL option: {e}")
            print("Continuing without this option - packet may work anyway")
    except PermissionError:
        print("Error: Raw socket requires root privileges")
        return
    except Exception as e:
        print(f"Error creating IPv6 raw socket: {e}")
        return

    try:
        # Send start signal to observer
        print('Tell observer to start sniffing IPv6...')
        signals.observer_start_sniff(measurement)
        time.sleep(10)

        # Start sending ICMPv6 packets
        print('Start sending ICMPv6 packets...')
        for round_num in range(3):
            with open(target_file) as ifile:
                lines = ifile.readlines()
                random.shuffle(lines)
                for line in tqdm.tqdm(lines, desc=f'Scan ICMPv6 round {round_num + 1}: '):
                    start_time = time.time()
                    target = line.strip()
                    send_icmpv6_bytes(sock, template, target, 64)
                    end_time = time.time()
                    elapsed = end_time - start_time
                    #control the sending speed
                    if elapsed < interval:
                        time.sleep(interval - elapsed)
    except Exception as e:
        print(f"Error during packet sending: {e}")
    finally:
        sock.close()
        print('End sending ICMPv6 packets!')
        time.sleep(120)
        print('Tell observer to stop sniffing...')
        signals.observer_stop_sniff(measurement)

