# -*- coding: utf-8 -*-
import os
import threading
import subprocess

from flask import Flask, request

import tcp4, ttl4
import utils.S3BucketUtil as s3bu
import utils.conf as cf
import utils.measurement as ms

#sys.path.append(os.path.dirname(os.path.dirname(__file__)))

class Spoofer:
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()
        self.vps = cf.VPsConfig()

    def setup_routes(self):
        self.app.route('/start_measurement', methods=['POST'])(self.start_measurement)
        self.app.route('/end_experiment', methods=['POST'])(self.end_experiment)
        
    def run_task(self, measurement: ms.Measurement):
        #download hitlist from s3
        data_path = cf.get_data_path(measurement.date, measurement.experiment_id)
        s3_buket = s3bu.S3Bucket()
        if 'ttl' in measurement.method:
            s3_hitlist_file = 'saip/{}/{}/hitlist_icmp.csv'.format(measurement.date, measurement.experiment_id)
            local_hitlist_file = '{}/hitlist_icmp.csv'.format(data_path)
        elif 'tcp' in measurement.method:
            s3_hitlist_file = 'saip/{}/{}/hitlist_tcp.csv'.format(measurement.date, measurement.experiment_id)
            local_hitlist_file = '{}/hitlist_tcp.csv'.format(data_path)
        if os.path.exists(local_hitlist_file):
            print('hitlist file already exist!')
        else:
            print('download hitlist [{}] to [{}]...'.format(s3_hitlist_file, local_hitlist_file))
            s3_buket.download_file(s3_hitlist_file, local_hitlist_file)
        target_file = local_hitlist_file
        #run task
        if measurement.method == 'tcp':
            tcp4.tcp_send(measurement, target_file)
        elif measurement.method == 'ttl':
            ttl4.ttl_send(measurement, target_file)
        return

    def start_measurement(self):
        measurement = ms.Measurement.from_dict(request.get_json())
        threading.Thread(target=self.run_task, args=(measurement)).start()
        return 'Task started successfully: date={}, id={}, method={}, spoofer={}, observer={}'\
            .format(measurement.date, measurement.experiment_id, measurement.method,\
                    self.vps.get_vp_by_id(measurement.spoofer_id).name, self.vps.get_vp_by_id(measurement.observer_id).name)
    
    def end_experiment(self):
        data = request.get_json()
        date = data['date']
        experiment_id = data['experiment_id']
        data_path = cf.get_data_path(date, experiment_id)
        if os.path.exists(data_path):
            subprocess.run(['rm', '-r', data_path])
        return 'Experiment ended successfully'

    def run(self, port):
        self.app.run(host='0.0.0.0', port=port)
