import requests
import utils.measurement as ms
import utils.vps as vpcf

vps = vpcf.VPsConfig()

def analyzer_scan_end(measurement: ms.Measurement):
    vp = vps.get_analyzer
    try:
        response = requests.post(
            'http://{}:{}/end_scan'.format(vp.public_addr_4, vp.spoofer_port), 
                json=measurement.dict
                )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error ending scan: {e}")
