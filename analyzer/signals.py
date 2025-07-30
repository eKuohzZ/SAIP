import requests

import utils.measurement as ms
import utils.vps as vpcf

vps = vpcf.VPsConfig()

def spoofer_start(measurement: ms.Measurement):
    vp = vps.get_vp_by_id(measurement.spoofer_id)
    try:
        response = requests.post(
            'http://{}:{}/start_measurement'.format(vp.public_addr_4, vp.spoofer_port), 
            json=measurement.dict,
            timeout=10
            )
        response.raise_for_status()
    except Exception as e:
        print(f"Error starting measurement: {e}")

def spoofer_stop(measurement: ms.Measurement):
    vp = vps.get_vp_by_id(measurement.spoofer_id)
    try:
        response = requests.post(
            'http://{}:{}/stop_measurement'.format(vp.public_addr_4, vp.spoofer_port), 
            json=measurement.dict,
            timeout=10
            )
        response.raise_for_status()
    except Exception as e:
        print(f"Error stopping measurement: {e}")

def scanner_start(measurement: ms.Measurement):
    vp = vps.get_scanner
    try:
        response = requests.post(
            'http://{}:{}/start_scan'.format(vp.public_addr_4, vp.spoofer_port), 
            json=measurement.dict,
            timeout=10
            )
        response.raise_for_status()
    except Exception as e:
        print(f"Error starting scan: {e}")

def scanner_end(date: str, experiment_id: int, ip_type: str):
    vp = vps.get_scanner
    date = {'date': date, 'experiment_id': experiment_id, 'ip_type': ip_type}
    try:
        response = requests.post(
            'http://{}:{}/end_experiment'.format(vp.public_addr_4, vp.spoofer_port), 
            json=date,
            timeout=10
            )
        response.raise_for_status()
    except Exception as e:
        print(f"Error ending experiment: {e}")

def observer_end(date: str, experiment_id: int, observer_id: int, ip_type: str):
    vp = vps.get_vp_by_id(observer_id)
    date = {'date': date, 'experiment_id': experiment_id, 'ip_type': ip_type}
    try:
        response = requests.post(
            'http://{}:{}/end_experiment'.format(vp.public_addr_4, vp.observer_port), 
            json=date,
            timeout=10
            )
        response.raise_for_status()
    except Exception as e:
        print(f"Error ending experiment: {e}")

def spoofer_end(date: str, experiment_id: int, spoofer_id: int, ip_type: str):
    vp = vps.get_vp_by_id(spoofer_id)
    date = {'date': date, 'experiment_id': experiment_id, 'ip_type': ip_type}
    try:
        response = requests.post(
            'http://{}:{}/end_experiment'.format(vp.public_addr_4, vp.spoofer_port), 
            json=date,
            timeout=10
            )
        response.raise_for_status()
    except Exception as e:
        print(f"Error ending experiment: {e}")
  

def observer_get_status(observer_id: int):
    vp = vps.get_vp_by_id(observer_id)
    try:
        response = requests.get('http://{}:{}/get_status'.format(vp.public_addr_4, vp.observer_port), timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"Error getting observer status: {e}")
        return None
    return response.json()

def scanner_get_status():
    vp = vps.get_scanner
    try:
        response = requests.get('http://{}:{}/get_status'.format(vp.public_addr_4, vp.spoofer_port), timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"Error getting scanner status: {e}")
        return None
    return response.json()
