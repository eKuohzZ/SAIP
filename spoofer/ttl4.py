# -*- coding:utf8 -*-
import random
import socket
from scapy.all import raw, IP, ICMP
import time
import tqdm

import utils.vps as vpcf
import utils.measurement as ms
import spoofer.signals as signals


vps = vpcf.VPsConfig()

def send_icmp_bytes(sock, template, dst_ip, ttl):
    buf = bytearray(template)  
    buf[8] = ttl                  
    buf[16:20] = socket.inet_aton(dst_ip) 
    pkt = IP(bytes(buf))           
    del pkt[IP].chksum
    del pkt[ICMP].chksum
    buf = bytearray(bytes(pkt))   

    sock.sendto(buf, (dst_ip, 0))


def ttl_send(measurement: ms.Measurement, target_file):
    #Get observer configuration
    observer = vps.get_vp_by_id(measurement.observer_id)
    interval = 1 / measurement.pps 

    base = IP(src=observer.public_addr_4, dst="0.0.0.0", ttl=64, proto=1, len=32) /ICMP(id=1459, seq=2636) / b'zknb'
    template = bytearray(raw(base))

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    #send start signal to observer
    print('tell observer to start sniff...')
    signals.observer_start_sniff(measurement)
    time.sleep(10)

    #start sending packets
    print('start sending ICMP packets...')
    for round_num in range(3):
        with open(target_file) as ifile:
            lines = ifile.readlines()
            random.shuffle(lines)
            for line in tqdm.tqdm(lines, desc=f'Scan ICMP round {round_num + 1}: '):
                start_time = time.time()
                target = line.strip()
                send_icmp_bytes(sock, template, target, 64)
                end_time = time.time()
                elapsed = end_time - start_time
                #control the sending speed
                if elapsed < interval:
                    time.sleep(interval - elapsed)
    sock.close()
    print('end sending ICMP packets!')
    time.sleep(120)
    #send stop signal to observer
    print('tell observer to stop sniff...')
    signals.observer_stop_sniff(measurement)
