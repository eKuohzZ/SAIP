# Description: This file contains the class definition for the Measurement object.

class Measurement:
    def __init__(self, measurement_id, spoofer_id, observer_id, method, date, pps):
        self.measurement_id = int(measurement_id)
        self.spoofer_id = int(spoofer_id)
        self.observer_id = int(observer_id)
        self.method = method
        self.date = date
        self.pps = int(pps)

    @classmethod
    def from_dict(cls, data):
        measurement_id = int(data["measurement_id"]) if isinstance(data["measurement_id"], (str, float)) else data["measurement_id"]
        pps = int(data["pps"]) if isinstance(data["pps"], (str, float)) else data["pps"]
        spoofer_id = int(data["spoofer_id"]) if isinstance(data["spoofer_id"], (str, float)) else data["spoofer_id"]
        observer_id = int(data["observer_id"]) if isinstance(data["observer_id"], (str, float)) else data["observer_id"]
        return cls(
            measurement_id,
            spoofer_id,
            observer_id,
            data["method"],
            data["date"],
            pps
        )
    
    @property
    def dict(self):
        return {
            "measurement_id": self.measurement_id,
            "spoofer_id": self.spoofer_id,
            "observer_id": self.observer_id,
            "method": self.method,
            "date": self.date,
            "pps": self.pps
        }
    
