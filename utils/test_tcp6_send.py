# -*- coding:utf8 -*-
import time
import socket
import struct
from scapy.all import raw, IPv6, TCP
import random
import tqdm

# Define IPV6_HDRINCL constant if not available in socket module
if not hasattr(socket, 'IPV6_HDRINCL'):
    socket.IPV6_HDRINCL = 36  # Standard value for IPv6_HDRINCL


def update_checksums_ipv6(buf):
    """
    Update TCP checksum for IPv6 packet
    IPv6 TCP checksum includes pseudo-header
    """
    pkt = IPv6(buf)      # 把字节流重新解析成 Scapy 包
    del pkt[TCP].chksum  # 删掉旧的TCP校验和字段
    return bytearray(bytes(pkt))

def send_tcp6_bytes(sock, template, dst_ip, sport, dport):
    buf = bytearray(template)  # make a fresh copy
    
    # Set destination IPv6 address (bytes 24-39)
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    buf[24:40] = dst_bytes
    
    # Set TCP source port (bytes 40-41)
    buf[40:42] = sport.to_bytes(2, 'big')
    
    # Set TCP destination port (bytes 42-43)
    buf[42:44] = dport.to_bytes(2, 'big')
    
    # Update TCP checksum
    buf = update_checksums_ipv6(buf)
    
    sock.sendto(bytes(buf), (dst_ip, 0))

def tcp_send():
    # Create IPv6 TCP SYN packet template
    base = IPv6(src='2001:da8:24c::7:3', dst="::", nh=6, hlim=64) / TCP(sport=0, dport=0, flags="S", seq=1000)
    template = bytearray(raw(base))

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
            
   
    for sport in [80, 90, 100]:
        send_tcp6_bytes(sock, template, '240b:4001:21b:1501:5b7a:abd3:5e30:4158', sport, 36017)


if __name__ == '__main__':
    tcp_send()
