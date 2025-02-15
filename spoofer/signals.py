import requests

import utils.measurement as ms
import utils.conf as cf

vps = cf.VPsConfig()

def observer_start_sniff(measurement: ms.Measurement):
    vp = vps.get_vp_by_id(measurement.observer_id)
    response = requests.post('http://{}:{}/start_measurement'.format(vp.public_addr, vp.port), json=measurement.dict)

def observer_stop_sniff(measurement: ms.Measurement):
    vp = vps.get_vp_by_id(measurement.observer_id)
    response = requests.post('http://{}:{}/stop_measurement'.format(vp.public_addr, vp.port), json=measurement.dict)
