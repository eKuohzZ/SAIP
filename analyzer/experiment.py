import threading
from typing import List
from typing import Dict

import utils.measurement as ms 
import utils.conf as cf

class Experiment:
    def __init__(self, vps: cf.VPsConfig, id: int, date: str):
        self.id = int(id)
        self.date = date
        self.measurements: Dict[int, Dict[int, ms.Measurement]] = {}
        self.lock = threading.Lock()
        self.init_measurement('ttl', vps)

    def init_measurement(self, method: str, vps: cf.VPsConfig):
            self.measurements = {}
            measurement_id = 0
            #spoofer to observer
            for spoofer in vps.get_spoofers:
                for observer in vps.get_observers:
                    pps = min(spoofer.pps, observer.pps)
                    measurement = ms.Measurement(self.id, measurement_id, spoofer.id, observer.id, method, self.date, pps)
                    measurement_id += 1
                    if observer.id not in self.measurements:
                        self.measurements[observer.id] = {}
                    self.measurements[observer.id][measurement_id] = measurement
            #spoofer to spoofer
            ids = []
            for spoofer in vps.get_spoofers:
                ids.append(spoofer.id)
            n = len(ids) 
            out_degrees = {id: 0 for id in ids}
            in_degrees = {id: 0 for id in ids}
            graph = {}
            for i in range(n):
                current_id = ids[i]
                graph[current_id] = []

                for j in range(1, (n // 2) + 1):
                    target_id = ids[(i + j) % n]
                    if out_degrees[current_id] < (n - 1) // 2 and in_degrees[target_id] < (n - 1) // 2:
                        graph[current_id].append(target_id)
                        out_degrees[current_id] += 1
                        in_degrees[target_id] += 1
            for spoofer_id, observer_ids in graph.items():
                for observer_id in observer_ids:
                    pps = min(vps.get_vp_by_id(spoofer_id).pps, vps.get_vp_by_id(observer_id).pps)
                    measurement = ms.Measurement(self.id, measurement_id, spoofer_id, observer_id, method, self.date, pps)
                    measurement_id += 1
                    if observer_id not in self.measurements:
                        self.measurements[observer_id] = {}
                    self.measurements[observer_id][measurement_id] = measurement

    def remove_measurement(self, observer_id: int, measurement_id: int):
        if observer_id not in self.measurements:
            return False
        if measurement_id in self.measurements[observer_id]:
            del self.measurements[observer_id][measurement_id]
        if not self.measurements[observer_id]:
            del self.measurements[observer_id]
        return len(self.measurements) == 0
    
    def find_kth_max_pps_measurement(self, observer_id: int, k: int):
        if observer_id not in self.measurements:
            return None
        measurements = list(self.measurements[observer_id].values())
        measurements.sort(key=lambda x: x.pps, reverse=True)
        if k > len(measurements) or k <= 0:
            return None
        return measurements[k - 1]
    
    def init_tcp_measurement(self, vps: cf.VPsConfig):
        self.init_measurement('tcp', vps)
    


                


        


    
    
        
    
    

