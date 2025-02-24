import requests

import utils.measurement as ms
import utils.conf as cf

vps = cf.VPsConfig()

def spoofer_start(measurement: ms.Measurement):
    vp = vps.get_vp_by_id(measurement.spoofer_id)
    response = requests.post('http://{}:{}/start_measurement'.format(vp.public_addr, vp.spoofer_port), json=measurement.dict)

def spoofer_stop(measurement: ms.Measurement):
    vp = vps.get_vp_by_id(measurement.spoofer_id)
    response = requests.post('http://{}:{}/stop_measurement'.format(vp.public_addr, vp.spoofer_port), json=measurement.dict)

def scanner_start(measurement: ms.Measurement):
    vp = vps.get_scanner
    response = requests.post('http://{}:{}/start_scan'.format(vp.public_addr, vp.spoofer_port), json=measurement.dict)

def scanner_end(date: str, experiment_id: int):
    vp = vps.get_scanner
    date = {'date': date, 'experiment_id': experiment_id}
    response = requests.post('http://{}:{}/end_experiment'.format(vp.public_addr, vp.spoofer_port), json=date)

def observer_end(date: str, experiment_id: int, observer_id: int):
    vp = vps.get_vp_by_id(observer_id)
    date = {'date': date, 'experiment_id': experiment_id}
    response = requests.post('http://{}:{}/end_experiment'.format(vp.public_addr, vp.observer_port), json=date)

def spoofer_end(date: str, experiment_id: int, spoofer_id: int):
    vp = vps.get_vp_by_id(spoofer_id)
    date = {'date': date, 'experiment_id': experiment_id}
    response = requests.post('http://{}:{}/end_experiment'.format(vp.public_addr, vp.spoofer_port), json=date)