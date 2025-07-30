# -*- coding:utf8 -*-
import time
import socket
from scapy.all import raw, IP, TCP
import random
import tqdm

import utils.conf as cf
import utils.vps as vpcf
import utils.measurement as ms
import spoofer.signals as signals

vps = vpcf.VPsConfig()

def update_checksums(buf):
    pkt = IP(buf)   
    del pkt[IP].chksum
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

def tcp_send(measurement: ms.Measurement, target_file):
    #setting
    observer = vps.get_vp_by_id(measurement.observer_id)
    interval = 1 / measurement.pps * 20

    base = IP(src=observer.public_addr_4, dst="0.0.0.0", proto=6) / TCP(sport=0, dport=0, flags="S", seq=1000)
    template = bytearray(raw(base))

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    #send start signal to observer
    print('tell observer to start sniff...')
    signals.observer_start_sniff(measurement)
    time.sleep(10)

    #start sending packets
    print('start sending TCP packets...')
    with open(target_file) as ifile:
        lines = ifile.readlines()
        random.shuffle(lines)
        for line in tqdm.tqdm(lines, desc='scan tcp: '):
            line = line.strip()
            target = line.split(',')[0]
            dport = int(line.split(',')[1])
            sample_len = min(cf.get_number_of_ports('tcp'), len(cf.get_tcp_port('tcp')))
            port_list = random.sample(cf.get_tcp_port('tcp'), sample_len)
            for sport in port_list:
                start_time = time.time()
                send_tcp_bytes(sock, template, target, sport, dport)
                end_time = time.time()
                elapsed = end_time - start_time
                #control the sending speed
                if elapsed < interval:
                    time.sleep(interval - elapsed)
    sock.close()
    print('end sending TCP packets!')
    time.sleep(120)
    #send stop signal to observer
    print('tell observer to stop sniff...')
    signals.observer_stop_sniff(measurement)

