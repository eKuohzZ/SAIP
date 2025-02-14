# -*- coding: utf-8 -*-
import os
import sys
import threading
import time

from flask import Flask, request
import subprocess

import utils.S3BucketUtil as s3bu
import utils.conf as cf    
import utils.measurement as ms

data_path = cf.get_data_path()
vps = cf.VPsConfig()
current_dir = os.path.dirname(os.path.abspath(__file__))

def post_measurement(measurement: ms.Measurement):
    if measurement.method == 'ttl':
        local_measurement_result_file = '{}/ttl_result-{}-{}-{}-{}.csv'.format(data_path, measurement.date, measurement.measurement_id, measurement.spoofer_id, measurement.observer_id)
        s3_measurement_result_file = 'saip/{}/{}/ttl_result/{}-{}.csv.xz'.format(measurement.date, measurement.measurement_id, measurement.spoofer_id, measurement.observer_id)
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
        args = ['python', os.path.join(current_dir, 'tcp4.py'), '--date', measurement.date, '--method', 'tcpa', '--mID', measurement.measurement_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id]
        task_tcpa_sniff = subprocess.Popen(args)
        args = ['python', os.path.join(current_dir, 'tcp4a_send.py'), '--date', measurement.date, '--mID', measurement.measurement_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id, '--pps', measurement.pps]
        task_tcpa_send = subprocess.Popen(args)
        task_tcpa_send.wait()
        time.sleep(120)
        task_tcpa_sniff.terminate()

        args = ['python', os.path.join(current_dir, 'tcp4.py'), '--date', measurement.date, '--method', 'tcps', '--mID', measurement.measurement_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id]
        task_tcps_sniff = subprocess.Popen(args)
        args = ['python', os.path.join(current_dir, 'tcp4s_send.py'), '--date', measurement.date, '--mID', measurement.measurement_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id, '--pps', measurement.pps//2]
        task_tcps_send = subprocess.Popen(args)
        task_tcps_send.wait()
        time.sleep(120)
        task_tcps_sniff.terminate()

        for flag in ["", 'a', 's']:
            local_measurement_result_file = '{}/tcp{}_result-{}-{}-{}-{}.csv'.format(data_path, flag, measurement.date, measurement.measurement_id, measurement.spoofer_id, measurement.observer_id)
            s3_measurement_result_file = 'saip/{}/{}/tcp{}_result/{}-{}.csv.xz'.format(measurement.date, measurement.measurement_id, flag, measurement.spoofer_id, measurement.observer_id)
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

app = Flask(__name__)
app.measurement_process = None

@app.route('/start_measurement', methods=['POST'])
def start_measurement():
    if app.measurement_process is None or app.measurement_process.poll() is not None:
        measurement = ms.Measurement.from_dict(request.get_json())
        if measurement is None:
            return 'No data provided in request', 400
        if measurement.method == 'ttl':
            args = ['python', os.path.join(current_dir, 'ttl4.py'), '--date', measurement.date, '--mID', measurement.measurement_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id]
        elif measurement.method == 'tcp':
            args = ['python', os.path.join(current_dir, 'tcp4.py'), '--date', measurement.date, '--method', 'tcp', '--mID', measurement.measurement_id, '--spoofer', measurement.spoofer_id, '--observer', measurement.observer_id]
        app.measurement_process = subprocess.Popen(args)
        return 'Task started successfully: date={}, id={}, method={}, spoofer={}, observer={}'\
        .format(measurement.date, measurement.measurement_id, measurement.method,\
                vps.get_vp_by_id(measurement.spoofer_id).name, vps.get_vp_by_id(measurement.observer_id).name)
    else:
        return 'Task is already running!'

@app.route('/stop_measurement', methods=['POST'])
def stop_measurement():
    if app.measurement_process and app.measurement_process.poll() is None:
        measurement = ms.Measurement.from_dict(request.get_json())
        app.measurement_process.terminate()
        app.measurement_process = None
        threading.Thread(target=post_measurement, args=(measurement)).start()
        return 'Task stopped successfully'
    else:
        return 'No task is running'
    
def run(port):
    # ban the output TCP traffic on the selective ports
    current_dir = os.path.dirname(os.path.abspath(__file__))
    ban_script = os.path.join(current_dir, 'ban.sh')
    subprocess.run(['chmod', '+x', ban_script])
    subprocess.run([ban_script])
    # run the app
    app.run(host='0.0.0.0', port=port)

