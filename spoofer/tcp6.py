# -*- coding:utf8 -*-
import time
import socket
from scapy.all import raw, IPv6, TCP
import random
import tqdm

import utils.conf as cf
import utils.vps as vpcf
import utils.measurement as ms
import spoofer.signals as signals

# Define IPV6_HDRINCL constant if not available in socket module
if not hasattr(socket, 'IPV6_HDRINCL'):
    socket.IPV6_HDRINCL = 36  # Standard value for IPv6_HDRINCL

vps = vpcf.VPsConfig()

def update_checksums_ipv6(buf):
    pkt = IPv6(buf)     
    del pkt[TCP].chksum  
    return bytearray(bytes(pkt))

def send_tcp6_bytes(sock, template, dst_ip, sport, dport):
    buf = bytearray(template)  # make a fresh copy
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    buf[24:40] = dst_bytes
    buf[40:42] = sport.to_bytes(2, 'big')
    buf[42:44] = dport.to_bytes(2, 'big')
    buf = update_checksums_ipv6(buf)
    sock.sendto(bytes(buf), (dst_ip, 0))

def tcp_send(measurement: ms.Measurement, target_file):
    # Setting
    observer = vps.get_vp_by_id(measurement.observer_id)
    interval = 1 / measurement.pps * 20

    base = IPv6(src=observer.public_addr_6, dst="::", nh=6, hlim=64) / TCP(sport=0, dport=0, flags="S", seq=1000)
    template = bytearray(raw(base))

    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
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
        print('Tell observer to start sniffing IPv6 TCP...')
        signals.observer_start_sniff(measurement)
        time.sleep(10)

        # Start sending TCP packets
        print('Start sending IPv6 TCP packets...')       
        with open(target_file) as ifile:
            lines = ifile.readlines()
            random.shuffle(lines)
            for line in tqdm.tqdm(lines, desc='Scan IPv6 TCP: '):
                line = line.strip()
                target = line.split(',')[0].strip()
                dport = int(line.split(',')[1].strip())    
                sample_len = min(cf.get_number_of_ports('tcp'), len(cf.get_tcp_port('tcp')))
                port_list = random.sample(cf.get_tcp_port('tcp'), sample_len)                
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
        print('End sending IPv6 TCP packets!')
        time.sleep(120) 
        # Send stop signal to observer
        print('Tell observer to stop sniffing...')
        signals.observer_stop_sniff(measurement)

