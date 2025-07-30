import csv

from typing import Dict
from . import conf as cf


# Vantage point
class VP:
    def __init__(self, id: int, name: str, role: str, public_addr_4: str, public_addr_6: str, private_addr_4: str, private_addr_6: str, network_interface_4: str, network_interface_6: str, spoofer_pps: int, observer_pps: int, spoofer_port: str, observer_port: str):
        self.id = id
        self.name = name
        self.role = role
        self.public_addr_4 = public_addr_4
        self.public_addr_6 = public_addr_6
        self.private_addr_4 = private_addr_4
        self.private_addr_6 = private_addr_6
        self.network_interface_4 = network_interface_4
        self.network_interface_6 = network_interface_6
        self.spoofer_pps = spoofer_pps 
        self.observer_pps = observer_pps
        self.spoofer_port = spoofer_port
        self.observer_port = observer_port


# Vantage points configuration
class VPsConfig:
    def __init__(self):
        self.vps = []
        self.spoofers = {'ipv4': [], 'ipv6': []}
        self.non_spoofers = {'ipv4': [], 'ipv6': []}
        self.analyzer = None
        self.scanner = None

        with open(cf.VPS_FILE, 'r', encoding='utf-8') as f:
            lines = [line for line in f if not line.strip().startswith('#')]
            reader = csv.DictReader(lines)
            id = 0
            for row in reader:
                if row['PROPERTY'] == 'analyzer':
                    vp = VP(-1, row['NAME'], row['PROPERTY'], row['PUBLIC_IP_ADDRESS_4'], row['PUBLIC_IP_ADDRESS_6'], row['PRIVATE_IP_ADDRESS_4'], row['PRIVATE_IP_ADDRESS_6'], row['NETWORK_INTERFACE_4'], row['NETWORK_INTERFACE_6'], int(row['SPOOFER_PPS']), int(row['OBSERVER_PPS']), row['SPOOFER_PORT'], row['OBSERVER_PORT'])
                    self.analyzer = vp
                elif row['PROPERTY'] == 'scanner':
                    vp = VP(-2, row['NAME'], row['PROPERTY'], row['PUBLIC_IP_ADDRESS_4'], row['PUBLIC_IP_ADDRESS_6'], row['PRIVATE_IP_ADDRESS_4'], row['PRIVATE_IP_ADDRESS_6'], row['NETWORK_INTERFACE_4'], row['NETWORK_INTERFACE_6'], int(row['SPOOFER_PPS']), int(row['OBSERVER_PPS']), row['SPOOFER_PORT'], row['OBSERVER_PORT'])
                    self.scanner = vp
                else:
                    vp = VP(id, row['NAME'], row['PROPERTY'], row['PUBLIC_IP_ADDRESS_4'], row['PUBLIC_IP_ADDRESS_6'], row['PRIVATE_IP_ADDRESS_4'], row['PRIVATE_IP_ADDRESS_6'], row['NETWORK_INTERFACE_4'], row['NETWORK_INTERFACE_6'], int(row['SPOOFER_PPS']), int(row['OBSERVER_PPS']), row['SPOOFER_PORT'], row['OBSERVER_PORT'])
                    self.vps.append(vp)
                    if vp.role == 'spoofer':
                        if vp.public_addr_4 != '':
                            self.spoofers['ipv4'].append(vp)
                        if vp.public_addr_6 != '':
                            self.spoofers['ipv6'].append(vp)
                    elif vp.role == 'non_spoofer':
                        if vp.public_addr_4 != '':
                            self.non_spoofers['ipv4'].append(vp)
                        if vp.public_addr_6 != '':
                            self.non_spoofers['ipv6'].append(vp)     
                    id += 1
    
    @property
    def get_spoofers(self) -> Dict[str, list[VP]]:
        return self.spoofers
    
    @property
    def get_non_spoofers(self) -> Dict[str, list[VP]]:
        return self.non_spoofers
    
    @property
    def get_analyzer(self) -> VP:
        return self.analyzer

    @property
    def get_scanner(self) -> VP:
        return self.scanner
    
    @property
    def get_vps(self) -> list[VP]:
        return self.vps
    
    def get_vp_by_id(self, id) -> VP:
        return self.vps[id]