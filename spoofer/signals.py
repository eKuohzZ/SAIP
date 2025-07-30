import requests

import utils.measurement as ms
import utils.vps as vpcf

vps = vpcf.VPsConfig()

def observer_start_sniff(measurement: ms.Measurement):
    vp = vps.get_vp_by_id(measurement.observer_id)
    try:
        response = requests.post('http://{}:{}/start_measurement'.format(vp.public_addr_4, vp.observer_port), json=measurement.dict)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error starting sniff: {e}")

def observer_stop_sniff(measurement: ms.Measurement):
    vp = vps.get_vp_by_id(measurement.observer_id)
    try:
        response = requests.post('http://{}:{}/stop_measurement'.format(vp.public_addr_4, vp.observer_port), json=measurement.dict)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error stopping sniff: {e}")
