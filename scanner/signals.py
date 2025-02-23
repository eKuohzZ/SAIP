import requests

import utils.measurement as ms
import utils.conf as cf

vps = cf.VPsConfig()

def analyzer_scan_end(measurement: ms.Measurement):
    vp = vps.get_analyzer
    response = requests.post('http://{}:{}/end_scan'.format(vp.public_addr, vp.http_port), json=measurement.dict)