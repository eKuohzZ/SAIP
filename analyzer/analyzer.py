import threading
import time
import subprocess

from flask import Flask, g, request
from dataclasses import dataclass, field
from typing import List, Dict

import utils.measurement as ms
import utils.conf as cf
import analyzer.signals as signals
import analyzer.build_icmp_hitlist as build_icmp_hitlist
import analyzer.get_candidate as get_candidate
import analyzer.get_anycast as get_anycast
import analyzer.experiment as ex


class Analyzer:
    def __init__(self):
        self.vps = cf.VPsConfig()
        self.lock = threading.Lock()
        self.experiment = None
        self.stop_event = threading.Event()
        self.is_scan_finished = False
        self.vps_status = {'spoofer': {}, 'observer': {}}
        for spoofer in self.vps.get_spoofers:
            self.vps_status['spoofer'][spoofer.id] = spoofer.spoofer_pps
            self.vps_status['observer'][spoofer.id] = spoofer.observer_pps
        for non_spoofer in self.vps.get_non_spoofers:
            self.vps_status['observer'][non_spoofer.id] = non_spoofer.observer_pps

    def start_measurement(self):
        experiment = self.experiment
        for observer_id, measurements in experiment.measurements.items():
            if self.vps_status['observer'][observer_id] == 0:
                continue
            for k in range(1, len(measurements)+1):
                measurement = experiment.find_kth_max_pps_measurement(observer_id, k)
                if self.vps_status['spoofer'][measurement.spoofer_id] < measurement.pps:
                    continue
                self.vps_status['spoofer'][measurement.spoofer_id] -= measurement.pps
                self.vps_status['observer'][observer_id] = 0
                signals.spoofer_start(measurement)
                break
        return

    def end_measurement(self, measurement: ms.Measurement, if_download: bool) -> bool:
        with self.lock:
            experiment = self.experiment
            if experiment.id != measurement.experiment_id:
                return False
            if not experiment.is_exist_measurement(measurement.observer_id, measurement.measurement_id):
                return False
            self.vps_status['spoofer'][measurement.spoofer_id] += measurement.pps
            self.vps_status['observer'][measurement.observer_id] = self.vps.get_vp_by_id(measurement.observer_id).observer_pps
            is_finished = experiment.remove_measurement(measurement.observer_id, measurement.measurement_id)
            if not is_finished:
                self.start_measurement()
                return False
            if measurement.method == 'ttl':
                get_candidate.get_candidate_vps(measurement.date, measurement.experiment_id, if_download)
                signals.scanner_start(measurement)
                return True
            if measurement.method == 'tcp':
                get_anycast.get_anycast_vps(measurement.date, measurement.experiment_id)
                for spoofer in self.vps.get_spoofers:
                    signals.spoofer_end(measurement.date, measurement.experiment_id, spoofer.id)
                for non_spoofer in self.vps.get_non_spoofers:
                    signals.observer_end(measurement.date, measurement.experiment_id, non_spoofer.id)
                signals.scanner_end(measurement.date, measurement.experiment_id)
                #subprocess.run(['rm', '-r', cf.get_data_path(measurement.date, measurement.experiment_id)])
                self.experiment = None
                self.is_scan_finished = False
                print('Experiment is finished!')
                return True
        return True
    
    def end_scan(self, measurement: ms.Measurement)-> bool:
        with self.lock:
            if self.is_scan_finished:
                return False
            experiment = self.experiment
            if experiment.id != measurement.experiment_id:
                return False
            experiment.init_tcp_measurement(self.vps)
            self.start_measurement()
        return True
        
    def start_experiment(self, if_download: bool):
        with self.lock:
            experiment_id = cf.get_experiment_id()
            date = cf.get_date()
            self.experiment = ex.Experiment(self.vps, experiment_id, date)
        build_icmp_hitlist.build_hitlist(self.experiment.date, self.experiment.id, if_download)
        return

    def get_status(self, is_scan: bool, if_download: bool):
        while True:
            if is_scan:
                response = signals.scanner_get_status()
                if response['status'] == 'finished':
                    if self.end_scan(ms.Measurement.from_dict(response['measurement'])):
                        return
            else:
                for oberver_id in self.vps_status['observer']:
                    response = signals.observer_get_status(oberver_id)
                    if response['status'] == 'finished':
                        if self.end_measurement(ms.Measurement.from_dict(response['measurement']), if_download):
                            return
            time.sleep(10)
            
        
    def run(self, if_download: bool):
        self.start_experiment(if_download)
        with self.lock:
            self.start_measurement()
        self.get_status(False, if_download)
        self.get_status(True, if_download)
        self.get_status(False, if_download)
