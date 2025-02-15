import threading

from flask import Flask, g, request
from dataclasses import dataclass, field
from typing import List, Dict

import utils.measurement as ms
import utils.conf as cf
import signals
import build_icmp_hitlist
import get_candidate


@dataclass
class ExperimentsState:
    is_running: bool = False
    latest_experiment_id: int = 0
    experiments: Dict[int, ms.Experiment] = field(default_factory=dict)
    experiments_status_lock: threading.Lock = field(default_factory=threading.Lock)

class Analyzer:
    def __init__(self):
        self.state = ExperimentsState()
        self.app = Flask(__name__)
        self.setup_routes()
        self.vps = cf.VPsConfig()
        
    def setup_routes(self):
        self.app.route('/start_experiment', methods=['POST'])(self.start_experiment)
        self.app.route('/end_measurement', methods=['POST'])(self.end_measurement)
    
    def get_schedule(self, vps) -> List[ms.Measurement]:
        measurements = []
        for spoofer in vps.spoofer_vps:
            for observer in vps.observer_vps:
                measurements.append(ms.Measurement(spoofer.id, observer.id))
        return measurements

    def start_experiment_task(self, date, experiment_id):
        build_icmp_hitlist.build_hitlist(date, experiment_id)
        measurements = self.get_schedule(self.vps)
        with self.state.experiments_status_lock:
            for measurement in measurements:
                self.state.experiments[experiment_id].add_measurement(measurement)
        for measurement in measurements:
            with self.state.experiments[experiment_id].lock:
                id = measurement.measurement_id
                with self.state.experiments_status_lock:
                    self.state.experiments[experiment_id].measurements[id].status = 'running'
            signals.spoofer_start(measurement)


    def end_measurement_task(self, measurement: ms.Measurement):
        with self.state.experiments[measurement.experiment_id].lock:
            id = measurement.measurement_id
            with self.state.experiments_status_lock:
                self.state.experiments[measurement.experiment_id].measurements[id].status = 'ended'
                measurements = self.state.experiments[measurement.experiment_id].measurements
                for m in measurements.values():
                    if m.status != 'ended':
                        return
        get_candidate.get_candidate_vps(measurement.measurement_id)

    def start_experiment(self):
        if self.state.is_running:
            return 'Experiment is already running'
        self.state.is_running = True
        self.state.latest_experiment_id = cf.get_experiment_id()
        with self.state.experiments_status_lock:
            self.state.experiments[self.state.latest_experiment_id] = ms.Experiment(self.state.latest_experiment_id, cf.get_date())
        threading.Thread(target=self.start_experiment_task, args=(self.state.latest_experiment_id,)).start()
        return 'Experiment started successfully'

    def end_measurement(self):
        measurement = ms.Measurement.from_dict(request.get_json())
        threading.Thread(target=self.end_measurement_task, args=(measurement,)).start()
        return 'Measurement ended successfully'

    def run(self, port):
        self.app.run(host='0.0.0.0', port=port)

def main(port):
    analyzer = Analyzer()
    analyzer.run(port)