# -*- coding:utf8 -*-
import argparse
import multiprocessing
import os
import random
from scapy.all import IP, TCP, raw
import socket
import sys
import time
import tqdm

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import utils.conf as cf
import utils.vps as vpcf

vps = vpcf.VPsConfig()

def update_checksums(buf):
    pkt = IP(buf)      # 把字节流重新解析成 Scapy 包
    del pkt[IP].chksum # 删掉旧校验和字段
    del pkt[TCP].chksum
    return bytearray(bytes(pkt))

def send_tcp_bytes(sock, template, dst_ip, sport, dport):
    # IP dst @ offset 16–19
    # TCP sport @ 20–21, dport @ 22–23
    buf = bytearray(template)  # make a fresh copy
    buf[16:20] = socket.inet_aton(dst_ip)
    buf[20:22] = sport.to_bytes(2, 'big')
    buf[22:24] = dport.to_bytes(2, 'big')
    buf = update_checksums(buf)  # 更新校验和
    sock.sendto(bytes(buf), (dst_ip, 0))

def tcp_send(observer_id, target_file, pps):
    observer = vps.get_vp_by_id(observer_id)
    interval = 1 / pps * 20

     # open raw socket once
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # pre-build an “empty” IP/TCP SYN packet
    base = (
        IP(src=observer.private_addr_4, dst="0.0.0.0", proto=6) /
        TCP(sport=0, dport=0, flags="S", seq=1000)
    )
    template = raw(base)  # bytes

    print('start sending TCPs packets...')
    with open(target_file) as ifile:
        lines = ifile.readlines()
        random.shuffle(lines)
        for line in tqdm.tqdm(lines, desc='scan tcps: '):
            line = line.strip()
            target = line.split(',')[0]
            dport = int(line.split(',')[1])
            sample_len = min(cf.get_number_of_ports('tcps'), len(cf.get_tcp_port('tcps')))
            port_list = random.sample(cf.get_tcp_port('tcps'), sample_len)
            for sport in port_list:
                start_time = time.time()
                send_tcp_bytes(sock, template, target, sport, dport)
                end_time = time.time()
                elapsed = end_time - start_time
                if elapsed < interval:
                    time.sleep(interval - elapsed)
    sock.close()
    print('end sending TCPs packets!')

def do_tcp_measure():
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYMMDD')
    parser.add_argument('--mID', type=int, help='ID of experiment')
    parser.add_argument('--spoofer', type=int, help='ID of spoofer')
    parser.add_argument('--observer', type=int, help='ID of observer')
    parser.add_argument('--pps', type=int, help='packet per second')
    date = parser.parse_args().date
    experiment_id = parser.parse_args().mID
    spoofer_id = parser.parse_args().spoofer
    observer_id = parser.parse_args().observer
    pps = parser.parse_args().pps
    data_path = cf.get_data_path(date, experiment_id)
    target_file = '{}/hitlist_tcp.csv'.format(data_path)
    send_process = multiprocessing.Process(target=tcp_send, args=(observer_id, target_file, pps))
    send_process.start()
    send_process.join()

if __name__ == '__main__':
    do_tcp_measure()
