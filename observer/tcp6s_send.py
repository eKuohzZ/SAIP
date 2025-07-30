# -*- coding:utf8 -*-
import argparse
import multiprocessing
import os
import random
from scapy.all import IPv6, TCP, raw
import socket
import sys
import time
import tqdm

# Define IPV6_HDRINCL constant if not available in socket module
if not hasattr(socket, 'IPV6_HDRINCL'):
    socket.IPV6_HDRINCL = 36  # Standard value for IPv6_HDRINCL

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import utils.conf as cf
import utils.vps as vpcf

vps = vpcf.VPsConfig()

def update_checksums_ipv6(buf):
    pkt = IPv6(buf)      # 把字节流重新解析成 Scapy 包
    del pkt[TCP].chksum  # 删掉旧的TCP校验和字段
    return bytearray(bytes(pkt))

def send_tcp6_bytes(sock, template, dst_ip, sport, dport):
    buf = bytearray(template)  # make a fresh copy
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    buf[24:40] = dst_bytes
    buf[40:42] = sport.to_bytes(2, 'big')
    buf[42:44] = dport.to_bytes(2, 'big')
    buf = update_checksums_ipv6(buf)
    
    sock.sendto(bytes(buf), (dst_ip, 0))

def tcp6_send(observer_id, target_file, pps):
    observer = vps.get_vp_by_id(observer_id)
    interval = 1 / pps * 20
    # Create raw IPv6 socket
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
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

    # Pre-build an "empty" IPv6/TCP SYN packet template
    base = (
        IPv6(src=observer.private_addr_6, dst="::", nh=6, hlim=64) /
        TCP(sport=0, dport=0, flags="S", seq=1000)
    )
    template = raw(base)  # bytes

    try:
        print('Start sending IPv6 TCPs packets...')
        with open(target_file) as ifile:
            lines = ifile.readlines()
            random.shuffle(lines)
            for line in tqdm.tqdm(lines, desc='Scan IPv6 TCPs: '):
                line = line.strip()
                target = line.split(',')[0].strip()
                dport = int(line.split(',')[1].strip())
                # Get random source ports for scanning
                sample_len = min(cf.get_number_of_ports('tcps'), len(cf.get_tcp_port('tcps')))
                port_list = random.sample(cf.get_tcp_port('tcps'), sample_len)
                
                for sport in port_list:
                    start_time = time.time()
                    send_tcp6_bytes(sock, template, target, sport, dport)
                    end_time = time.time()
                    elapsed = end_time - start_time
                    # Control the sending speed
                    if elapsed < interval:
                        time.sleep(interval - elapsed)
    except Exception as e:
        print(f"Error during packet sending: {e}")
    finally:
        sock.close()
        print('End sending IPv6 TCPs packets!')

def do_tcp6_measure():
    """
    Main function to handle IPv6 TCP measurement
    """
    parser = argparse.ArgumentParser(description='IPv6 TCP SYN packet sender')
    parser.add_argument('--date', type=str, required=True, help='Date in YYMMDD format')
    parser.add_argument('--mID', type=int, required=True, help='Measurement ID')
    parser.add_argument('--spoofer', type=int, required=True, help='Spoofer VPS ID')
    parser.add_argument('--observer', type=int, required=True, help='Observer VPS ID')
    parser.add_argument('--pps', type=int, required=True, help='Packets per second')
    args = parser.parse_args()
    date = args.date
    experiment_id = args.mID
    spoofer_id = args.spoofer
    observer_id = args.observer
    pps = args.pps
    data_path = cf.get_data_path(date, experiment_id, 'ipv6')
    target_file = '{}/hitlist_tcp.csv'.format(data_path)
    send_process = multiprocessing.Process(
        target=tcp6_send, 
        args=(observer_id, target_file, pps)
    )
    send_process.start()
    send_process.join()

if __name__ == '__main__':
    do_tcp6_measure() 