import threading
import subprocess

from flask import Flask, g, request
from dataclasses import dataclass, field
from typing import List, Dict

import utils.measurement as ms
import utils.conf as cf
import signals
import build_icmp_hitlist
import get_candidate
import get_anycast
import analyzer.experiment as ex


@dataclass
class ExperimentsState:
    is_running: bool = False
    latest_experiment_id: int = 0
    experiments: Dict[int, ex.Experiment] = field(default_factory=dict)
    experiments_status_lock: threading.Lock = field(default_factory=threading.Lock)
    vps_status: Dict[str, Dict[int, int]] = field(default_factory=dict)

class Analyzer:
    def __init__(self):
        self.state = ExperimentsState()
        #self.app = Flask(__name__)
        #self.setup_routes()
        self.vps = cf.VPsConfig()

        self.vps_status = {'spoofer': {}, 'observer': {}}
        for spoofer in self.vps.get_spoofers:
            self.vps_status['spoofer'][spoofer.id] = spoofer.spoofer_pps
            self.vps_status['observer'][spoofer.id] = spoofer.observer_pps
        for non_spoofer in self.vps.get_non_spoofers:
            self.vps_status['observer'][non_spoofer.id] = non_spoofer.observer_pps
        
    #def setup_routes(self):
        #self.app.route('/start_experiment', methods=['POST'])(self.start_experiment)
        #self.app.route('/end_measurement', methods=['POST'])(self.end_measurement)
        #self.app.route('/end_scan', methods=['POST'])(self.end_scan)

    def start_measurement(self, experiment_id):
        experiment = self.state.experiments[experiment_id]
        with experiment.lock:
            for observer_id, measurements in experiment.measurements.items():
                if self.state.vps_status['observer'][observer_id] == 0:
                    continue
                for k in range(1, len(measurements)+1):
                    measurement = experiment.find_kth_max_pps_measurement(observer_id, k)
                    with self.state.experiments_status_lock:
                        if self.state.vps_status['spoofer'][measurement.spoofer_id] < measurement.pps:
                            continue
                        self.state.vps_status['spoofer'][measurement.spoofer_id] -= measurement.pps
                        self.state.vps_status['observer'][observer_id] = 0
                    signals.spoofer_start(measurement)
                    break
            
    def start_experiment_task(self):
        with self.state.experiments_status_lock:
            self.state.is_running = True
            self.state.latest_experiment_id = cf.get_experiment_id()
            date = cf.get_date()
            self.state.experiments[self.state.latest_experiment_id] = ex.Experiment(self.vps, self.state.latest_experiment_id, date)
        experiment_id = self.state.latest_experiment_id
        build_icmp_hitlist.build_hitlist(date, experiment_id)
        self.start_measurement(experiment_id)

    def end_measurement_task(self, measurement: ms.Measurement):
        with self.state.experiments_status_lock:
            self.state.vps_status['spoofer'][measurement.spoofer_id] += measurement.pps
            self.state.vps_status['observer'][measurement.observer_id] = self.vps.get_vp_by_id(measurement.observer_id).observer_pps
        experiment = self.state.experiments[measurement.experiment_id]
        with experiment.lock:
            is_finished = experiment.remove_measurement(measurement.observer_id, measurement.measurement_id)
            if not is_finished:
                self.start_measurement(experiment.id)
                return
        if measurement.method == 'ttl':
            get_candidate.get_candidate_vps(measurement.date, measurement.experiment_id)
            signals.scanner_start(measurement)
        if measurement.method == 'tcp':
            get_anycast.get_anycast_vps(measurement.date, measurement.experiment_id)
            for spoofer in self.vps.get_spoofers:
                signals.spoofer_end(measurement.date, measurement.experiment_id, spoofer.id)
            for non_spoofer in self.vps.get_non_spoofers:
                signals.observer_end(measurement.date, measurement.experiment_id, non_spoofer.id)
            signals.scanner_end(measurement.date, measurement.experiment_id)
            subprocess.run(['rm', '-r', cf.get_data_path(measurement.date, measurement.experiment_id)])
            self.state.is_running = False
            with self.state.experiments_status_lock:
                self.state.experiments.pop(measurement.experiment_id, None)
        
    
    def end_scan_task(self, experiment_id):
        experiment = self.state.experiments[experiment_id]
        with experiment.lock:
            experiment.init_tcp_measurement(self.vps)
        self.start_measurement(experiment_id)
        
    def start_experiment(self):
        if self.state.is_running:
            return 'Experiment is already running'
        threading.Thread(target=self.start_experiment_task, args=()).start()
        return 'Experiment started successfully'

    def end_measurement(self):
        measurement = ms.Measurement.from_dict(request.get_json())
        threading.Thread(target=self.end_measurement_task, args=(measurement,)).start()
        return 'Measurement ended successfully'
    
    def end_scan(self):
        measurement = ms.Measurement.from_dict(request.get_json())
        threading.Thread(target=self.end_scan_task, args=(measurement.experiment_id)).start()
        return 'Scan ended successfully'
        
    def run(self, port):
        
