"""
Configuration file for SAIP
"""

import os
import datetime
import requests
import re
from urllib.parse import urljoin


########################################################
# configuration
IF_DOWNLOAD = False
ID_FILE = "config/latest_experiment_id.csv"
PORT_FILE = "config/port_list.csv"
NUMBER_OF_PORTS = 10
VPS_FILE = "config/vps.csv"
S3_CONFIG = {
            "ACCESS_KEY": "Xu8R1VjptPxb0tQb",
            "SECRET_KEY": "36V4ojbvCUhCdyPzlqswarF0YUrqFSNN",
            "BUCKET_NAME": "kdp",
            #"ENDPOINT_URL": "http://166.111.121.63:59000/",
            "ENDPOINT_URL": "https://minio.ki3.org.cn",
            "VERIFY_SSL": False, 
        }

IPV6_HITLIST_BASE_ROOT = "https://alcatraz.net.in.tum.de/ipv6-hitlist-service/registered/output/"
IPV6_HITLIST_USERNAME = "ruifeng-li-at-tsinghua-edu-cn"
IPV6_HITLIST_PASSWORD = "9402106ffd3e"
PORT_RANK_FILE = "config/port_rank.csv"
########################################################


def download_latest_icmp6(local_filename) -> str:
    base_root = IPV6_HITLIST_BASE_ROOT
    username = IPV6_HITLIST_USERNAME
    password = IPV6_HITLIST_PASSWORD
    
    session = requests.Session()
    session.auth = (username, password)
    
    try:
        # 1. Get all available months
        resp = session.get(base_root, timeout=30)
        resp.raise_for_status()
        months = re.findall(r'href="(\d{4}-\d{2})/', resp.text)
        if not months:
            raise Exception("No month directories found")
        
        latest_month = sorted(set(months))[-1]
        month_url = urljoin(base_root, f"{latest_month}/")

        # 2. Get ICMP file list from the latest month
        resp = session.get(month_url, timeout=30)
        resp.raise_for_status()
        pattern = rf'href="({latest_month}-\d{{2}}-icmp\.csv\.xz)"'
        files = re.findall(pattern, resp.text)
        if not files:
            raise Exception(f"No ICMP files found in {latest_month} directory")
        
        latest_file = sorted(files)[-1]

        # 3. Download the latest file
        download_url = urljoin(month_url, latest_file)
        
        print(f"Downloading: {download_url}")
        with session.get(download_url, stream=True, timeout=60) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))
            
            with open(local_filename, 'wb') as f:
                downloaded = 0
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        # Optional: show download progress
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"Download progress: {progress:.1f}%", end='\r', flush=True)

        print(f"\nDownload completed: {local_filename}")
        return local_filename
        
    except requests.RequestException as e:
        raise Exception(f"Network error during download: {e}")
    except Exception as e:
        print(f"Download failed: {e}")
        # Clean up incomplete file if download failed
        if local_filename and os.path.exists(local_filename):
            os.remove(local_filename)
        raise
    finally:
        session.close()

def get_experiment_id():
    try:
        with open(ID_FILE, 'r') as f:
            current_id = int(f.read().strip())
        new_id = current_id + 1
        with open(ID_FILE, 'w') as f:
            f.write(str(new_id))
        return new_id
    except FileNotFoundError:
        with open(ID_FILE, 'w') as f:
            f.write('1')
        return 1
    except ValueError:
        with open(ID_FILE, 'w') as f:
            f.write('1')
        return 1
    
def get_data_path(date, experiment_id, ip_type):
    work_dir = os.getcwd()
    data_dir = os.path.join(work_dir, 'data', ip_type, date, str(experiment_id))
    abs_path = os.path.abspath(data_dir)
    os.makedirs(abs_path, exist_ok=True)
    return abs_path

def if_download_data():
    return IF_DOWNLOAD

def get_tcp_port(method):
    try:
        with open(PORT_FILE, 'r') as f:
            ports = [int(port.strip()) for port in f.readlines()]

        group_size = len(ports) // 2
        tcp_ports = ports[:group_size]
        tcps_ports = ports[group_size:]
        
        if method == 'tcp':
            return tcp_ports
        elif method == 'tcps':
            return tcps_ports
        else:
            return []
    except FileNotFoundError:
        print(f"Error: {PORT_FILE} not found")
        return []
    except ValueError:
        print(f"Error: Invalid port number in {PORT_FILE}")
        return []
    
def get_number_of_ports(method):
    if method == 'tcp':
        return max(NUMBER_OF_PORTS, len(get_tcp_port(method)))
    elif method == 'tcps':
        return max(NUMBER_OF_PORTS, len(get_tcp_port(method)))

def get_date():
    now = datetime.datetime.now()
    date = now.strftime("%y%m%d")   
    return date

def extract_ipv6_48_prefix(ipv6_addr):
    """
    Extract /48 prefix from IPv6 address using string manipulation
    
    Args:
        ipv6_addr: IPv6 address string
    
    Returns:
        str: /48 prefix or None if invalid
    """
    # Remove any leading/trailing whitespace
    addr = ipv6_addr.strip()
    # Handle compressed notation (::)
    if '::' in addr:
        addr = expand_ipv6_address(addr)
    if not addr:
        return None
    # Split by colons and ensure we have 8 groups
    groups = addr.split(':')
    if len(groups) != 8:
        return None
    # Validate each group (should be hex digits, max 4 chars)
    for group in groups:
        if not group or len(group) > 4:
            return None
        try:
            int(group, 16)
        except ValueError:
            return None
    # Extract first 3 groups (48 bits = 3 * 16 bits)
    prefix_groups = groups[:3]
    prefix = ':'.join(prefix_groups) + '::/48'
    return prefix

def expand_ipv6_address(addr):
    """
    Expand compressed IPv6 address (handle ::)
    
    Args:
        addr: IPv6 address with possible :: compression
    
    Returns:
        str: Fully expanded IPv6 address
    """
    if '::' not in addr:
        return addr
    # Split on ::
    parts = addr.split('::')
    if len(parts) != 2:
        return None
    left_part = parts[0]
    right_part = parts[1] 
    # Count existing groups
    left_groups = left_part.split(':') if left_part else []
    right_groups = right_part.split(':') if right_part else []
    # Remove empty strings
    left_groups = [g for g in left_groups if g]
    right_groups = [g for g in right_groups if g]
    # Calculate how many zero groups to insert
    missing_groups = 8 - len(left_groups) - len(right_groups)
    # Pad with leading zeros for each group
    left_groups = [g.zfill(4) for g in left_groups]
    right_groups = [g.zfill(4) for g in right_groups]
    # Insert zero groups
    zero_groups = ['0000'] * missing_groups
    # Combine all groups
    all_groups = left_groups + zero_groups + right_groups
    return ':'.join(all_groups)

def get_port_by_rank():
    with open(PORT_RANK_FILE, 'r') as f:
        lines = f.readlines()
        ports = []
        for line in lines:
            ports.append(line.strip())
    return ports