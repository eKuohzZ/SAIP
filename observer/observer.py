# -*- coding: utf-8 -*-
import os
import threading
import time

from flask import Flask, request, jsonify
import subprocess

import utils.S3BucketUtil as s3bu
import utils.conf as cf    
import utils.measurement as ms
import signals
import scanner.build_tcp_hitlist as bth

class Observer:
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()
        self.measurement_process = None
        self.measurement = None
        self.status = "initialized"
        self.vps = cf.VPsConfig()
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.lock = threading.Lock()

        ban_script = os.path.join(self.current_dir, 'ban.sh')
        subprocess.run(['chmod', '+x', ban_script])
        subprocess.run([ban_script])

    def setup_routes(self):
        self.app.route('/start_measurement', methods=['POST'])(self.start_measurement)
        self.app.route('/stop_measurement', methods=['POST'])(self.stop_measurement)
        self.app.route('/end_experiment', methods=['POST'])(self.end_experiment)
        self.app.route('/get_status', methods=['GET'])(self.get_status)
        
    def post_measurement(self, measurement: ms.Measurement):
        data_path = cf.get_data_path(measurement.date, measurement.experiment_id)
        if measurement.method == 'ttl':
            local_measurement_result_file = '{}/ttl_result/{}-{}.csv'.format(data_path, measurement.spoofer_id, measurement.observer_id)
            s3_measurement_result_file = 'saip/{}/{}/ttl_result/{}-{}.csv.xz'.format(measurement.date, measurement.experiment_id, measurement.spoofer_id, measurement.observer_id)
            #compress file
            compress_file = local_measurement_result_file + '.xz'
            if os.path.exists(compress_file):
                print('file already exist!')
            else:
                subprocess.run(['xz', local_measurement_result_file])
            #upload file to s3
            s3_buket = s3bu.S3Bucket()
            print('upload measurement result [{}] to [{}]...'.format(compress_file, s3_measurement_result_file))
            s3_buket.upload_files(s3_measurement_result_file, compress_file)

        if measurement.method == 'tcp':
            '''
            args = ['python', os.path.join(current_dir, 'tcp4.py'), '--date', measurement.date, '--method', 'tcpa', '--mID', measurement.experiment_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id]
            task_tcpa_sniff = subprocess.Popen(args)
            args = ['python', os.path.join(current_dir, 'tcp4a_send.py'), '--date', measurement.date, '--mID', measurement.experiment_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id, '--pps', measurement.pps]
            task_tcpa_send = subprocess.Popen(args)
            task_tcpa_send.wait()
            time.sleep(120)
            task_tcpa_sniff.terminate()
            '''

            s3_buket = s3bu.S3Bucket()
            s3_hitlist_file = 'saip/{}/{}/hitlist_tcp.csv'.format(measurement.date, measurement.experiment_id)
            local_hitlist_file = '{}/hitlist_tcp.csv'.format(data_path)
            if not os.path.exists(local_hitlist_file):
                s3_buket.download_file(s3_hitlist_file, local_hitlist_file)

            args = ['python', os.path.join(self.current_dir, 'tcp4.py'), '--date', measurement.date, '--method', 'tcps', '--mID', measurement.experiment_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id]
            task_tcps_sniff = subprocess.Popen(args)
            args = ['python', os.path.join(self.current_dir, 'tcp4s_send.py'), '--date', measurement.date, '--mID', measurement.experiment_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id, '--pps', measurement.pps//2]
            task_tcps_send = subprocess.Popen(args)
            task_tcps_send.wait()
            time.sleep(120)
            task_tcps_sniff.terminate()

            for flag in ["", 's']:
                local_measurement_result_file = '{}/tcp{}_result/{}-{}.csv'.format(data_path, flag, measurement.spoofer_id, measurement.observer_id)
                s3_measurement_result_file = 'saip/{}/{}/tcp{}_result/{}-{}.csv.xz'.format(measurement.date, measurement.experiment_id, flag, measurement.spoofer_id, measurement.observer_id)
                #compress file
                compress_file = local_measurement_result_file + '.xz'
                if os.path.exists(compress_file):
                    print('file already exist!')
                else:
                    subprocess.run(['xz', local_measurement_result_file])
                #upload file to s3
                s3_buket = s3bu.S3Bucket()
                print('upload measurement result [{}] to [{}]...'.format(compress_file, s3_measurement_result_file))
                s3_buket.upload_files(s3_measurement_result_file, compress_file)

        with self.lock:
            self.status = 'finished'

    def start_measurement(self):
        if self.measurement_process is None or self.measurement_process.poll() is not None:
            measurement = ms.Measurement.from_dict(request.get_json())
            if measurement is None:
                return 'No data provided in request', 400
            with self.lock:
                self.status = 'running'
                self.measurement = measurement
            if measurement.method == 'ttl':
                args = ['python', os.path.join(self.current_dir, 'ttl4.py'), '--date', measurement.date, '--mID', measurement.experiment_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id]
            elif measurement.method == 'tcp':
                args = ['python', os.path.join(self.current_dir, 'tcp4.py'), '--date', measurement.date, '--method', 'tcp', '--mID', measurement.experiment_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id]
            self.measurement_process = subprocess.Popen(args)
            return 'Task started successfully: date={}, id={}, method={}, spoofer={}, observer={}'\
            .format(measurement.date, measurement.experiment_id, measurement.method,\
                    self.vps.get_vp_by_id(measurement.spoofer_id).name, self.vps.get_vp_by_id(measurement.observer_id).name)
        else:
            return 'Task is already running!'
        
    def stop_measurement(self):
        if self.measurement_process and self.measurement_process.poll() is None:
            measurement = ms.Measurement.from_dict(request.get_json())
            self.measurement_process.terminate()
            self.measurement_process = None
            threading.Thread(target=self.post_measurement, args=(measurement)).start()
            return 'Task stopped successfully'
        else:
            return 'No task is running'
        
    def end_experiment(self):
        date = request.get_json()['date']
        experiment_id = request.get_json()['experiment_id']
        data_path = cf.get_data_path(date, experiment_id)
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
       


