import threading

from typing import Dict

import utils.measurement as ms 
import utils.vps as vpcf

class Experiment:
    def __init__(self, vps: vpcf.VPsConfig, id: int, date: str, ip_type: str):
        self.id = int(id)
        self.date = date
        self.measurements: Dict[int, Dict[int, ms.Measurement]] = {}
        self.lock = threading.Lock()
        self.measurement_id = 0
        self.ip_type = ip_type

    def init_measurement(self, method: str, vps: vpcf.VPsConfig):
            self.measurements = {}
            measurement_id = self.measurement_id
            #spoofer to non-spoofer
            for spoofer in vps.get_spoofers[self.ip_type]:
                for non_spoofer in vps.get_non_spoofers[self.ip_type]:
                    pps = min(spoofer.spoofer_pps, non_spoofer.observer_pps)
                    measurement = ms.Measurement(self.id, measurement_id, spoofer.id, non_spoofer.id, method, self.date, pps, self.ip_type)
                    measurement_id += 1
                    self.measurement_id = measurement_id
                    if non_spoofer.id not in self.measurements:
                        self.measurements[non_spoofer.id] = {}
                    self.measurements[non_spoofer.id][measurement.measurement_id] = measurement
            
            #spoofer to spoofer
            ids = []
            for spoofer in vps.get_spoofers[self.ip_type]:
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
            if n == 2:
                graph[ids[0]].append(ids[1])
            for spoofer_id, observer_ids in graph.items():
                for observer_id in observer_ids:
                    pps = min(vps.get_vp_by_id(spoofer_id).spoofer_pps, vps.get_vp_by_id(observer_id).observer_pps)
                    measurement = ms.Measurement(self.id, measurement_id, spoofer_id, observer_id, method, self.date, pps, self.ip_type)
                    measurement_id += 1
                    self.measurement_id = measurement_id
                    if observer_id not in self.measurements:
                        self.measurements[observer_id] = {}
                    self.measurements[observer_id][measurement.measurement_id] = measurement
            for observer_id in self.measurements:
                for measurement_id in self.measurements[observer_id]:
                    print(self.measurements[observer_id][measurement_id].dict)
        

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
    
    def init_ttl_measurement(self, vps: vpcf.VPsConfig):
        self.init_measurement('ttl', vps)

    def init_tcp_measurement(self, vps: vpcf.VPsConfig):
        self.init_measurement('tcp', vps)

    def is_exist_measurement(self, observer_id: int, measurement_id: int):
        return observer_id in self.measurements and measurement_id in self.measurements[observer_id]
    


                


        


    
    
        
    
    

