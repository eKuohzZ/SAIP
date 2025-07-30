import requests
import utils.measurement as ms
import utils.vps as vpcf

vps = vpcf.VPsConfig()

def analyzer_measurment_end(measurement: ms.Measurement):
    vp = vps.get_analyzer
    response = requests.post('http://{}:{}/end_measurement'.format(vp.public_addr_4, vp.spoofer_port), json=measurement.dict)