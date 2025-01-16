# -*- coding: utf-8 -*-
from flask import Flask, request
import subprocess
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import S3BucketUtil as s3bu

user_home = os.path.expanduser('~')
data_path = user_home + '/.saip'
if not os.path.exists(data_path):
    os.makedirs(data_path)

app = Flask(__name__)
task_process = None

@app.route('/start_task', methods=['POST'])
def start_task():
    global task_process
    if task_process is None or task_process.poll() is not None:
        # 从 POST 请求中读取参数
        data = request.get_json()
        if data is None:
            return 'No data provided in request', 400
        # 构造参数列表
        if data.get('method') == 'ttl':
            args = ['python', 'ttl4.py', '--date', data.get('date'), '--mID', data.get('mID'), '--spoofer', data.get('spoofer'), '--observer', data.get('observer')]
        elif data.get('method') == 'tcp':
            args = ['python', 'tcp4.py', '--date', data.get('date'), '--mID', data.get('mID'), '--spoofer', data.get('spoofer'), '--observer', data.get('observer')]
        task_process = subprocess.Popen(args)
        return 'Task {} started successfully'.format(data.get('method'))
    else:
        return 'Task is already running'

@app.route('/stop_task', methods=['POST'])
def stop_task():
    global task_process
    if task_process and task_process.poll() is None:
        data = request.get_json()
        date = data.get('date')
        mID = data.get('mID')
        task_process.terminate()
        task_process = None
        if data.get('method') == 'ttl':
            output_file = '{}/measurement_result_ttl-{}-{}.csv'.format(data_path, date, mID)
            up_s3_file = 'saip/measurement_result_ttl/{}/{}.csv.xz'.format(date, mID)
        elif data.get('method') == 'tcp':
            output_file = '{}/measurement_result_tcp-{}-{}.csv'.format(data_path, date, mID)
            up_s3_file = 'saip/measurement_result_tcp/{}/{}.csv.xz'.format(date, mID)
        #压缩
        compress_file = output_file + '.xz'
        if os.path.exists(compress_file):
            print('Observer: file already exist!')
        else:
            subprocess.run(['xz', output_file])
        #上传到s3
        s3_buket = s3bu.S3Bucket()
        print('Analyzer: upload measurement_result [{}] to s3...'.format(up_s3_file))
        s3_buket.upload_files(up_s3_file, compress_file)
        subprocess.run(['rm', compress_file])
        return 'Task stopped successfully'
    else:
        return 'No task is running'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=39999)

