# -*- coding: utf-8 -*-
import os
import threading

from flask import Flask, request

import tcp4, ttl4
import utils.S3BucketUtil as s3bu
import utils.conf as cf
import utils.measurement as ms

#sys.path.append(os.path.dirname(os.path.dirname(__file__)))
data_path = cf.get_data_path()
vps = cf.VPsConfig()

class Spoofer:
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        self.app.route('/start_measurement', methods=['POST'])(self.start_measurement)
        
    def run_task(self, measurement: ms.Measurement):
        #download hitlist from s3
        s3_buket = s3bu.S3Bucket()
        if 'ttl' in measurement.method:
            s3_hitlist_file = 'saip/{}/{}/hitlist_icmp.csv'.format(measurement.date, measurement.experiment_id)
            local_hitlist_file = '{}/hitlist_icmp-{}-{}.csv'.format(data_path, measurement.date, measurement.experiment_id)
        elif 'tcp' in measurement.method:
            s3_hitlist_file = 'saip/{}/{}/hitlist_tcp.csv'.format(measurement.date, measurement.experiment_id)
            local_hitlist_file = '{}/hitlist_tcp-{}-{}.csv'.format(data_path, measurement.date, measurement.experiment_id)
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
                    vps.get_vp_by_id(measurement.spoofer_id).name, vps.get_vp_by_id(measurement.observer_id).name)

    def run(self, port):
        self.app.run(host='0.0.0.0', port=port)

def main(port):
    spoofer = Spoofer()
    spoofer.run(port)