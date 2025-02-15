# Description: This file contains the class definition for the Measurement object.
import threading

from typing import Dict

class Measurement:
    def __init__(self, experiment_id, measurement_id, spoofer_id, observer_id, method, date, pps):
        self.experiment_id = int(experiment_id)
        self.measurement_id = int(measurement_id)
        self.spoofer_id = int(spoofer_id)
        self.observer_id = int(observer_id)
        self.method = method
        self.date = date
        self.pps = int(pps)
        self.status = "initialized"

    @classmethod
    def from_dict(cls, data):
        experiment_id = int(data["experiment_id"]) if isinstance(data["experiment_id"], (str, float)) else data["experiment_id"]
        measurement_id = int(data["measurement_id"]) if isinstance(data["measurement_id"], (str, float)) else data["measurement_id"]
        pps = int(data["pps"]) if isinstance(data["pps"], (str, float)) else data["pps"]
        spoofer_id = int(data["spoofer_id"]) if isinstance(data["spoofer_id"], (str, float)) else data["spoofer_id"]
        observer_id = int(data["observer_id"]) if isinstance(data["observer_id"], (str, float)) else data["observer_id"]
        return cls(
            experiment_id,
            measurement_id,
            spoofer_id,
            observer_id,
            data["method"],
            data["date"],
            pps,
            data["status"]
        )
    
    @property
    def dict(self):
        return {
            "experiment_id": self.experiment_id,
            "measurement_id": self.measurement_id,
            "spoofer_id": self.spoofer_id,
            "observer_id": self.observer_id,
            "method": self.method,
            "date": self.date,
            "pps": self.pps,
            "status": self.status
        }

class Experiment:
    def __init__(self, id, date):
        self.id = int(id)
        self.date = date
        self.measurements: Dict[int, Measurement] = {}
        self.lock = threading.Lock()
    
    def add_measurement(self, measurement: Measurement):
        self.measurements[measurement.measurement_id] = measurement

