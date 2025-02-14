# Description: This file contains the class definition for the Measurement object.

class Measurement:
    def __init__(self, measurement_id, spoofer_id, observer_id, method, date, pps):
        self.measurement_id = measurement_id
        self.spoofer_id = spoofer_id
        self.observer_id = observer_id
        self.method = method
        self.date = date
        self.pps = int(pps)

    @classmethod
    def from_dict(cls, data):
        pps = int(data["pps"]) if isinstance(data["pps"], (str, float)) else data["pps"]
        return cls(
            data["measurement_id"],
            data["spoofer_id"],
            data["observer_id"],
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
    
