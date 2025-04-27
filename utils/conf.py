"""
Configuration file for SAIP
"""

import csv
import os
import random
import datetime

# Input data path
if_download_data_ans = False

# S3 configuration
S3_CONFIG = {
            "ACCESS_KEY": "Xu8R1VjptPxb0tQb",
            "SECRET_KEY": "36V4ojbvCUhCdyPzlqswarF0YUrqFSNN",
            "BUCKET_NAME": "kdp",
            "ENDPOINT_URL": "http://166.111.121.63:59000/",
            #"ENDPOINT_URL": "https://minio.ki3.org.cn",
        }

# Vantage points configuration
class VPInfo:
    def __init__(self, id: int, name: str, role: str, public_addr: str, private_addr: str, network_interface: str, spoofer_pps: int, observer_pps: int, spoofer_port: str, observer_port: str):
        self.id = id
        self.name = name
        self.role = role
        self.public_addr = public_addr
        self.private_addr = private_addr
        self.network_interface = network_interface
        self.spoofer_pps = spoofer_pps 
        self.observer_pps = observer_pps
        self.spoofer_port = spoofer_port
        self.observer_port = observer_port

class VPsConfig:
    def __init__(self):
        self.spoofers = []
        self.non_spoofers = []
        self.vps = []

        with open("config/vps.csv", 'r', encoding='utf-8') as f:
            lines = [line for line in f if not line.strip().startswith('#')]
            reader = csv.DictReader(lines)
            id = 0
            for row in reader:
                if row['PROPERTY'] == 'analyzer':
                    vp = VPInfo(-1, row['NAME'], row['PROPERTY'], row['PUBLIC_IP_ADDRESS'], row['PRIVATE_IP_ADDRESS'], row['NETWORK_INTERFACE'], int(row['SPOOFER_PPS']), int(row['OBSERVER_PPS']), row['SPOOFER_PORT'], row['OBSERVER_PORT'])
                    self.analyzer = vp
                elif row['PROPERTY'] == 'scanner':
                    vp = VPInfo(-2, row['NAME'], row['PROPERTY'], row['PUBLIC_IP_ADDRESS'], row['PRIVATE_IP_ADDRESS'], row['NETWORK_INTERFACE'], int(row['SPOOFER_PPS']), int(row['OBSERVER_PPS']), row['SPOOFER_PORT'], row['OBSERVER_PORT'])
                    self.scanner = vp
                else:
                    vp = VPInfo(id, row['NAME'], row['PROPERTY'], row['PUBLIC_IP_ADDRESS'], row['PRIVATE_IP_ADDRESS'], row['NETWORK_INTERFACE'], int(row['SPOOFER_PPS']), int(row['OBSERVER_PPS']), row['SPOOFER_PORT'], row['OBSERVER_PORT'])
                    self.vps.append(vp)
                    if vp.role == 'spoofer':
                        self.spoofers.append(vp)
                    elif vp.role == 'non_spoofer':
                        self.non_spoofers.append(vp)     
                    id += 1
    
    @property
    def get_spoofers(self) -> list[VPInfo]:
        return self.spoofers
    
    @property
    def get_non_spoofers(self) -> list[VPInfo]:
        return self.non_spoofers
    
    @property
    def get_analyzer(self) -> VPInfo:
        return self.analyzer

    @property
    def get_scanner(self) -> VPInfo:
        return self.scanner
    
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
    
def get_data_path(date, experiment_id):
    work_dir = os.getcwd()
    data_dir = os.path.join(work_dir, 'data', date, str(experiment_id))
    abs_path = os.path.abspath(data_dir)
    os.makedirs(abs_path, exist_ok=True)
    return abs_path

def if_download_data():
    return if_download_data_ans

def get_tcp_port(method):
    port_file = "config/port_list.csv"
    try:
        with open(port_file, 'r') as f:
            ports = [int(port.strip()) for port in f.readlines()]

        group_size = len(ports) // 2
        tcp_ports = ports[:group_size]
        tcps_ports = ports[group_size:]
        #tcpa_ports = ports[2*group_size:]
        
        if method == 'tcp':
            #print(tcp_ports)
            return tcp_ports
        elif method == 'tcps':
            #print(tcps_ports)
            return tcps_ports
        #elif method == 'tcpa':
            #return tcpa_ports
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
    #elif method == 'tcpa':
        #return 10

def get_date():
    now = datetime.datetime.now()
    date = now.strftime("%y%m%d")   
    return date
