import os
import threading

from flask import Flask, request

import scanner.build_tcp_hitlist as bth
import utils.S3BucketUtil as s3bu
import utils.conf as cf
import utils.measurement as ms
import signals

vps = cf.VPsConfig()

class Scanner:
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()
    
    def setup_routes(self):
        self.app.route('/start_scan', methods=['POST'])(self.start_scan)

    def run_scan_task(self, measurement: ms.Measurement):
        scanner = vps.get_scanner
        bth.build_tcp_hitlist_vp(measurement.date, measurement.experiment_id, scanner.pps, scanner.network_interface)
        signals.analyzer_scan_end(measurement)
    
    def start_scan(self):
        measurement = ms.Measurement.from_dict(request.get_json())
        threading.Thread(target=self.run_scan_task, args=(measurement)).start()
        return 'Task started successfully: date={}, id={}, method={}, spoofer={}, observer={}'\
            .format(measurement.date, measurement.experiment_id, measurement.method,\
                    vps.get_vp_by_id(measurement.spoofer_id).name, vps.get_vp_by_id(measurement.observer_id).name)

    def run(self, port):
        self.app.run(host='0.0.0.0', port=port)

def main(port):
    scanner = Scanner()
    scanner.run(port)