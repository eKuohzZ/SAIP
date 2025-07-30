# -*- coding: utf-8 -*-
import os
import psutil
import threading
import time

from flask import Flask, request, jsonify
import subprocess

import utils.S3BucketUtil as s3bu
import utils.conf as cf    
import utils.measurement as ms
import utils.vps as vpcf


class Observer:
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()
        self.measurement = None
        self.status = "initialized"
        self.measurement_process = None
        self.vps = vpcf.VPsConfig()
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
        try:
            data_path = cf.get_data_path(measurement.date, measurement.experiment_id, measurement.ip_type)
            if measurement.method == 'ttl':
                local_measurement_result_file = '{}/ttl_result/{}-{}.csv'.format(data_path, measurement.spoofer_id, measurement.observer_id)
                s3_measurement_result_file = 'saip/{}/{}/{}/ttl_result/{}-{}.csv.xz'.format(measurement.ip_type, measurement.date, measurement.experiment_id, measurement.spoofer_id, measurement.observer_id)
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
                s3_buket = s3bu.S3Bucket()
                s3_hitlist_file = 'saip/{}/{}/{}/hitlist_tcp.csv'.format(measurement.ip_type, measurement.date, measurement.experiment_id)
                local_hitlist_file = '{}/hitlist_tcp.csv'.format(data_path)
                if not os.path.exists(local_hitlist_file):
                    s3_buket.download_file(s3_hitlist_file, local_hitlist_file)
                if measurement.ip_type == 'ipv4':
                    args_sniff = ['python3', os.path.join(self.current_dir, 'tcp4.py'), '--date', measurement.date, '--method', 'tcps', '--mID', str(measurement.experiment_id), '--spoofer', str(measurement.spoofer_id), '--observer', str(measurement.observer_id)]
                    args_send = ['python3', os.path.join(self.current_dir, 'tcp4s_send.py'), '--date', measurement.date, '--mID', str(measurement.experiment_id), '--spoofer', str(measurement.spoofer_id), '--observer', str(measurement.observer_id), '--pps', str(measurement.pps//2)]
                elif measurement.ip_type == 'ipv6':
                    args_sniff = ['python3', os.path.join(self.current_dir, 'tcp6.py'), '--date', measurement.date, '--method', 'tcps', '--mID', str(measurement.experiment_id), '--spoofer', str(measurement.spoofer_id), '--observer', str(measurement.observer_id)]
                    args_send = ['python3', os.path.join(self.current_dir, 'tcp6s_send.py'), '--date', measurement.date, '--mID', str(measurement.experiment_id), '--spoofer', str(measurement.spoofer_id), '--observer', str(measurement.observer_id), '--pps', str(measurement.pps//2)]
                task_tcps_sniff = subprocess.Popen(args_sniff)
                time.sleep(10)
                task_tcps_send = subprocess.Popen(args_send)
                task_tcps_send.wait()
                time.sleep(120)
                proc = psutil.Process(task_tcps_sniff.pid)
                for child in proc.children(recursive=True):
                    child.terminate()
                proc.terminate()
                while True:
                    if task_tcps_sniff and task_tcps_sniff.poll() is None:
                        time.sleep(1)
                    else:
                        break
                #task_tcps_sniff.terminate()

                for flag in ["", 's']:
                    local_measurement_result_file = '{}/tcp{}_result/{}-{}.csv'.format(data_path, flag, measurement.spoofer_id, measurement.observer_id)
                    s3_measurement_result_file = 'saip/{}/{}/{}/tcp{}_result/{}-{}.csv.xz'.format(measurement.ip_type, measurement.date, measurement.experiment_id, flag, measurement.spoofer_id, measurement.observer_id)
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
                
        finally:
            # 无论是否发生异常，都要更新状态
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
                if measurement.ip_type == 'ipv4':
                    args = ['python3', os.path.join(self.current_dir, 'ttl4.py'), '--date', measurement.date, '--mID', str(measurement.experiment_id), '--spoofer', str(measurement.spoofer_id), '--observer', str(measurement.observer_id)]
                elif measurement.ip_type == 'ipv6':
                    args = ['python3', os.path.join(self.current_dir, 'ttl6.py'), '--date', measurement.date, '--mID', str(measurement.experiment_id), '--spoofer', str(measurement.spoofer_id), '--observer', str(measurement.observer_id)]
            elif measurement.method == 'tcp':
                if measurement.ip_type == 'ipv4':
                    args = ['python3', os.path.join(self.current_dir, 'tcp4.py'), '--date', measurement.date, '--method', 'tcp', '--mID', str(measurement.experiment_id), '--spoofer', str(measurement.spoofer_id), '--observer', str(measurement.observer_id)]
                elif measurement.ip_type == 'ipv6':
                    args = ['python3', os.path.join(self.current_dir, 'tcp6.py'), '--date', measurement.date, '--method', 'tcp', '--mID', str(measurement.experiment_id), '--spoofer', str(measurement.spoofer_id), '--observer', str(measurement.observer_id)]
            self.measurement_process = subprocess.Popen(args)
            return 'Task started successfully: date={}, id={}, ip_type={}, method={}, spoofer={}, observer={}'\
            .format(measurement.date, measurement.experiment_id, measurement.ip_type, measurement.method,\
                    self.vps.get_vp_by_id(measurement.spoofer_id).name, self.vps.get_vp_by_id(measurement.observer_id).name)
        else:
            return 'Task is already running!'
        
    def stop_measurement(self):
        if self.measurement_process and self.measurement_process.poll() is None:
            measurement = ms.Measurement.from_dict(request.get_json())
            #self.measurement_process.kill()
            #os.kill(self.measurement_process.pid, signal.SIGKILL)
            proc = psutil.Process(self.measurement_process.pid)
            for child in proc.children(recursive=True):
                child.terminate()
            proc.terminate()
            while True:
                if self.measurement_process and self.measurement_process.poll() is None:
                    time.sleep(1)
                else:
                    break
            self.measurement_process = None
            threading.Thread(target=self.post_measurement, args=(measurement,)).start()
            return 'Task stopped successfully'
        else:
            return 'No task is running'
        
    def end_experiment(self):
        date = request.get_json()['date']
        experiment_id = request.get_json()['experiment_id']
        ip_type = request.get_json()['ip_type']
        data_path = cf.get_data_path(date, experiment_id, ip_type)
        with self.lock:
            self.status = 'initialized'
            self.measurement = None
        #if os.path.exists(data_path):
            #subprocess.run(['rm', '-r', data_path])
        return 'Experiment ended successfully'

    def get_status(self):
        with self.lock:
            return jsonify({"status": self.status, "measurement": self.measurement.dict if self.measurement else None})
        
    def run(self, port):
        self.app.run(host='0.0.0.0', port=port)
       


