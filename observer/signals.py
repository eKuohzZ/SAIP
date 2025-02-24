import requests

import utils.measurement as ms
import utils.conf as cf

vps = cf.VPsConfig()

def analyzer_measurment_end(measurement: ms.Measurement):
    vp = vps.get_analyzer
    response = requests.post('http://{}:{}/end_measurement'.format(vp.public_addr, vp.spoofer_port), json=measurement.dict)