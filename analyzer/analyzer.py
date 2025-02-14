import datetime
import threading

from flask import Flask, request

import build_icmp_hitlist
import utils.conf as cf
import signals
import utils.measurement as ms

now = datetime.datetime.now()
date = now.strftime("%y%m%d")
measurement_id = cf.get_measurement_id()
vps = cf.VPsConfig()

def get_schedule(VPS: cf.VPsConfig):
    return []

# app definition
app = Flask(__name__)
app.ttl_progress = 0
app.tcp_progress = 0
app.progress = 0
app.is_running = False

def start_measurement_task():
    build_icmp_hitlist.build_hitlist(date, measurement_id)
    measurements = get_schedule(vps)
    for measurement in measurements:
        signals.spoofer_start(measurement)
        app.ttl_progress += 100/len(measurements)

@app.route('/start_measurement', methods=['POST'])
def start_measurement():
    if app.is_running:
        return 'Measurement is already running'
    app.is_running = True
    threading.Thread(target=start_measurement_task).start()
    return 'Measurement started successfully'

@app.route('/end_measurement', methods=['POST'])
def end_measurement():
    measurement = ms.Measurement.from_dict(request.get_json())
    return 'Measurement ended successfully'


def run(port):
    app.run(host='0.0.0.0', port=port)


