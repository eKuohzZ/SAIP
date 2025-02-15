"""
Configuration file for SAIP
"""

import csv
import os
import random
import datetime

# Input data path
if_download_data = True

# S3 configuration
S3_CONFIG = {
            "ACCESS_KEY": "siKlxRVrztiXqVgJ",
            "SECRET_KEY": "5rGL7ds3xclIHaSnfoUiT1RU4V9fom4L",
            "BUCKET_NAME": "kdp",
            "ENDPOINT_URL": "http://166.111.121.63:59000/",
        }

# Vantage points configuration
class VPInfo:
    def __init__(self, id, name, role, public_addr, private_addr, network_interface, pps, port):
        self.id = id
        self.name = name
        self.role = role
        self.public_addr = public_addr
        self.private_addr = private_addr
        self.network_interface = network_interface
        self.pps = pps
        self.port = port

class VPsConfig:
    def __init__(self):
        self.spoofers = []
        self.observers = []
        self.vps = []

        with open("config/vps.csv", 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            id = 0
            for row in reader:
                if row['ROLE'] == 'analyzer':
                    vp = VPInfo(0, row['NAME'], row['ROLE'], row['PUBLIC_IP_ADDRESS'], row['PRIVATE_IP_ADDRESS'], row['NETWORK_INTERFACE'], row['PACKETS_PER_SECOND'], row['HTTP_PORT'])
                    self.vps = [vp] + self.vps
                    self.analyzer = vp
                else:
                    id += 1
                    vp = VPInfo(id, row['NAME'], row['ROLE'], row['PUBLIC_IP_ADDRESS'], row['PRIVATE_IP_ADDRESS'], row['NETWORK_INTERFACE'], row['PACKETS_PER_SECOND'], row['HTTP_PORT'])
                    self.vps.append(vp)
                    if vp.role == 'spoofer':
                        self.spoofers.append(vp)
                    elif vp.role == 'observer':
                        self.observers.append(vp)       
    
    @property
    def get_spoofers(self) -> list[VPInfo]:
        return self.spoofers
    
    @property
    def get_observers(self) -> list[VPInfo]:
        return self.observers
    
    @property
    def get_analyzer(self) -> VPInfo:
        return self.analyzer
    
    @property
    def get_vps(self) -> list[VPInfo]:
        return self.vps
    
    def get_vp_by_id(self, id) -> VPInfo:
        return self.vps[id]

def get_experiment_id():
    id_file = "config/latest_experiment_id.csv"
    try:
        with open(id_file, 'r') as f:
            current_id = int(f.read().strip())
        new_id = current_id + 1
        with open(id_file, 'w') as f:
            f.write(str(new_id))
        return new_id
    except FileNotFoundError:
        with open(id_file, 'w') as f:
            f.write('1')
        return 1
    except ValueError:
        with open(id_file, 'w') as f:
            f.write('1')
        return 1
    
def get_data_path():
    work_dir = os.getcwd()
    data_dir = os.path.join(work_dir, 'data')
    abs_path = os.path.abspath(data_dir)
    if not os.path.exists(abs_path):
        os.makedirs(abs_path)
    return abs_path

def if_download_data():
    return if_download_data

def get_tcp_port(method):
    port_file = "config/port_list.csv"
    try:
        with open(port_file, 'r') as f:
            ports = [int(port.strip()) for port in f.readlines()]
        random.shuffle(ports)

        group_size = len(ports) // 3
        tcp_ports = ports[:group_size]
        tcps_ports = ports[group_size:2*group_size]
        tcpa_ports = ports[2*group_size:]
        
        if method == 'tcp':
            return tcp_ports
        elif method == 'tcps':
            return tcps_ports
        elif method == 'tcpa':
            return tcpa_ports
        else:
            return []
    except FileNotFoundError:
        print(f"Error: {port_file} not found")
        return []
    except ValueError:
        print(f"Error: Invalid port number in {port_file}")
        return []
    
def get_number_of_ports(method):
    if method == 'tcp':
        return 10
    elif method == 'tcps':
        return 10
    elif method == 'tcpa':
        return 10

def get_date():
    now = datetime.datetime.now()
    date = now.strftime("%y%m%d")   
    return date