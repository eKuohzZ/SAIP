# -*- coding: utf-8 -*-
import os
from multiprocessing import Process, Lock
import subprocess

from flask import Flask, request

import spoofer.tcp4 as tcp4
import spoofer.ttl4 as ttl4
import spoofer.tcp6 as tcp6
import spoofer.ttl6 as ttl6
import utils.S3BucketUtil as s3bu
import utils.conf as cf
import utils.measurement as ms
import utils.vps as vpcf
#sys.path.append(os.path.dirname(os.path.dirname(__file__)))

class Spoofer:
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()
        self.vps = vpcf.VPsConfig()
        self.lock = Lock()

    def setup_routes(self):
        self.app.route('/start_measurement', methods=['POST'])(self.start_measurement)
        self.app.route('/end_experiment', methods=['POST'])(self.end_experiment) 
        
    def run_task(self, measurement: ms.Measurement):
        #download hitlist from s3
        with self.lock:
            data_path = cf.get_data_path(measurement.date, measurement.experiment_id, measurement.ip_type)
            s3_buket = s3bu.S3Bucket()
            if 'ttl' in measurement.method:
                s3_hitlist_file = 'saip/{}/{}/{}/hitlist_icmp.csv'.format(measurement.ip_type, measurement.date, measurement.experiment_id)
                local_hitlist_file = '{}/hitlist_icmp.csv'.format(data_path)
            elif 'tcp' in measurement.method:
                s3_hitlist_file = 'saip/{}/{}/{}/hitlist_tcp.csv'.format(measurement.ip_type, measurement.date, measurement.experiment_id)
                local_hitlist_file = '{}/hitlist_tcp.csv'.format(data_path)
            if os.path.exists(local_hitlist_file):
                print('hitlist file already exist!')
            else:
                print('download hitlist [{}] to [{}]...'.format(s3_hitlist_file, local_hitlist_file))
                s3_buket.download_file(s3_hitlist_file, local_hitlist_file)
            target_file = local_hitlist_file

        if measurement.method == 'tcp':
            if measurement.ip_type == 'ipv4':
                target_fn = tcp4.tcp_send
            elif measurement.ip_type == 'ipv6':
                target_fn = tcp6.tcp_send
        elif measurement.method == 'ttl':
            if measurement.ip_type == 'ipv4':
                target_fn = ttl4.ttl_send
            elif measurement.ip_type == 'ipv6':
                target_fn = ttl6.ttl_send
        else:
            raise ValueError(f"Unsupported method {measurement.method}")
        try:
            target_fn(measurement, target_file)
            #print("Probe completed successfully")
        except Exception as e:
            print(f"Error during probe: {e}")
            raise
        return

    def start_measurement(self):
        measurement = ms.Measurement.from_dict(request.get_json())
        #threading.Thread(target=self.run_task, args=(measurement,)).start()
        p = Process(target=self.run_task, args=(measurement,))
        p.daemon = True
        p.start()
        return 'Task started successfully: date={}, id={}, ip_type={}, method={}, spoofer={}, observer={}'\
            .format(measurement.date, measurement.experiment_id, measurement.ip_type, measurement.method,\
                    self.vps.get_vp_by_id(measurement.spoofer_id).name, self.vps.get_vp_by_id(measurement.observer_id).name)
    
    def end_experiment(self):
        data = request.get_json()
        date = data['date']
        experiment_id = data['experiment_id']
        ip_type = data['ip_type']
        data_path = cf.get_data_path(date, experiment_id, ip_type)
        if os.path.exists(data_path):
            subprocess.run(['rm', '-r', data_path])
        return 'Experiment ended successfully'

    def run(self, port):
        self.app.run(host='0.0.0.0', port=port)
