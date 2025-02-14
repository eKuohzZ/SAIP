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

def run_task(measurement: ms.Measurement):
    #download hitlist from s3
    s3_buket = s3bu.S3Bucket()
    if 'ttl' in measurement.method:
        s3_hitlist_file = 'saip/hitlist_icmp/{}-{}csv'.format(measurement.date, measurement.measurement_id)
        local_hitlist_file = '{}/hitlist_icmp-{}-{}.csv'.format(data_path, measurement.date, measurement.measurement_id)
    elif 'tcp' in measurement.method:
        s3_hitlist_file = 'saip/hitlist_tcp/{}-{}.csv'.format(measurement.date)
        local_hitlist_file = '{}/hitlist_tcp-{}-{}.csv'.format(data_path, measurement.date)
    if os.path.exists(local_hitlist_file):
        print('hitlist file already exist!')
    else:
        print('download hitlist [{}] to [{}]...'.format(s3_hitlist_file, local_hitlist_file))
        s3_buket.download_file(s3_hitlist_file, local_hitlist_file)
    target_file = local_hitlist_file
    #run task
    if measurement.method == 'tcp':
        tcp4.TCPsend(measurement, target_file)
    elif measurement.method == 'ttl':
        ttl4.TTLsend(measurement, target_file)

# app definition
app = Flask(__name__)

@app.route('/start_measurement', methods=['POST'])
def start_task():
    measurement = ms.Measurement.from_dict(request.get_json())
    threading.Thread(target=run_task, args=(measurement)).start()
    return 'Task started successfully: date={}, id={}, method={}, spoofer={}, observer={}'\
        .format(measurement.date, measurement.measurement_id, measurement.method,\
                vps.get_vp_by_id(measurement.spoofer_id).name, vps.get_vp_by_id(measurement.observer_id).name)

def run(port):
     app.run(host='0.0.0.0', port=port)
     return


if __name__ == "__main__":
    run()