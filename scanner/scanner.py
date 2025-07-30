import os
import threading
import subprocess

from flask import Flask, request, jsonify

import scanner.build_tcp_hitlist as bth
import utils.conf as cf
import utils.measurement as ms
import utils.vps as vpcf

class Scanner:
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()
        self.vps = vpcf.VPsConfig()
        self.status = "initialized"
        self.lock = threading.Lock()
        self.measurement = None
        
    
    def setup_routes(self):
        self.app.route('/start_scan', methods=['POST'])(self.start_scan)
        self.app.route('/end_experiment', methods=['POST'])(self.end_experiment)
        self.app.route('/get_status', methods=['GET'])(self.get_status)

    def run_scan_task(self, measurement: ms.Measurement):
        scanner = self.vps.get_scanner
        if measurement.ip_type == 'ipv4':
            bth.build_tcp_hitlist_vp(measurement.date, measurement.experiment_id, scanner.spoofer_pps, scanner.network_interface_4, measurement.ip_type)
        elif measurement.ip_type == 'ipv6':
            bth.build_tcp_hitlist_vp(measurement.date, measurement.experiment_id, scanner.spoofer_pps, scanner.network_interface_6, measurement.ip_type)
        with self.lock:
            self.status = 'finished'
    
    def start_scan(self):
        measurement = ms.Measurement.from_dict(request.get_json())
        with self.lock:
            self.status = 'running'
            self.measurement = measurement
        threading.Thread(target=self.run_scan_task, args=(measurement,)).start()
        return 'Task started successfully: date={}, id={}, method={}, spoofer={}, observer={}'\
            .format(measurement.date, measurement.experiment_id, measurement.method,\
                    self.vps.get_vp_by_id(measurement.spoofer_id).name, self.vps.get_vp_by_id(measurement.observer_id).name)
    
    def end_experiment(self):
        data = request.get_json()
        date = data['date']
        experiment_id = data['experiment_id']
        ip_type = data['ip_type']
        data_path = cf.get_data_path(date, experiment_id, ip_type)
        with self.lock:
            self.status = 'initialized'
            self.measurement = None
        if os.path.exists(data_path):
            subprocess.run(['rm', '-r', data_path])
        return 'Experiment ended successfully'
    
    def get_status(self):
        with self.lock:
            return jsonify({"status": self.status, "measurement": self.measurement.dict if self.measurement else None})

    def run(self, port):
        self.app.run(host='0.0.0.0', port=port)
