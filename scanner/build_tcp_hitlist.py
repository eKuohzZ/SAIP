# -*- coding: utf-8 -*-
import time
import os

import subprocess
import random

import utils.S3BucketUtil as s3bu
import utils.conf as cf

LEN_RECENT_RATE_CHANGES = 10

def select_random_percentage(array, percentage):
    # calculate the number of elements to select
    num_elements_to_select = max(1, int(len(array) * percentage / 100))
    # select the elements
    selected_elements = random.sample(array, num_elements_to_select)
    
    return selected_elements

def get_common_port(date, experiment_id, rate, interface):
    data_path = cf.get_data_path(date, experiment_id)
    #download candidate file
    s3_buket = s3bu.S3Bucket()
    s3_candidate_file = 'saip/{}/{}/candidate_vps.csv'.format(date, experiment_id)
    local_candidate_file = '{}/candidate_vps.csv'.format(data_path)
    print('download candidate file [{}]to [{}]'.format(s3_candidate_file, local_candidate_file))
    s3_buket.download_file(s3_candidate_file, local_candidate_file)
    # get sample candidate
    candidates = []
    with open(local_candidate_file) as ifile:
        lines = ifile.readlines()
        for line in lines:
            candidates.append(line.strip())
    sample_candidate = select_random_percentage(candidates,1)
    sample_candidate_file = '{}/sample_candidate.csv'.format(data_path)
    with open(sample_candidate_file, 'w') as ofile:
        for sample in sample_candidate:
            print(sample, file=ofile)
    #port scan
    sample_port_scan_result_file = '{}/sample_port_scan_result.csv'.format(data_path)
    command = 'zmap -s 47000-50000 -p 0-65535 --output-filter="success = 1 && repeat = 0 && classification = synack" -r {} -i {} -f "saddr,sport" --allowlist-file={} -o {}'.format(rate, interface, sample_candidate_file, sample_port_scan_result_file)
    #command = 'zmap -p 80 --output-filter="success = 1 && repeat = 0 && classification = synack" -r {} -i {} -f "saddr,sport" --allowlist-file={} -o {}'.format(rate, interface, down_local_file, sample_port_scan_result_file)
    subprocess.run(command, shell=True)
    #获取port的出现频率
    port2feq = {}
    with open(sample_port_scan_result_file) as ifile:
        while True:
            lines = ifile.readlines(1000000)
            if not lines: break
            for line in lines:
                line = line.strip()
                ll = line.split(',')
                if len(ll) == 1: continue
                target  = ll[0]
                port = ll[1]
                if port == '' or port == 'sport': continue
                if port not in port2feq:
                    port2feq[port] = 1
                else:
                    port2feq[port] += 1
    port2feq = sorted(port2feq.items(), key=lambda item: item[1], reverse=True)
    port2feq = dict(port2feq)
    ports_by_rank = []
    port_rank_file = '{}/port_rank.csv'.format(data_path)
    with open(port_rank_file, 'w') as ofile:
        for port in port2feq:
            ports_by_rank.append(port)
            output = port + ',' + str(port2feq[port])
            print(output, file = ofile)
    return ports_by_rank

def build_tcp_hitlist_vp(date, experiment_id, rate, interface):
    data_path = cf.get_data_path(date, experiment_id)
    ports_by_rank = get_common_port(date, experiment_id, rate, interface)
    #download port2scan file
    s3_buket = s3bu.S3Bucket()
    s3_ip2scan_file = 'saip/{}/{}/ip2do_port_scan.csv'.format(date, experiment_id)
    local_ip2scan_file = '{}/ip2do_port_scan.csv'.format(data_path)
    print('download ip2do_port_scan file [{}] to [{}]'.format(s3_ip2scan_file, local_ip2scan_file))
    s3_buket.download_file(s3_ip2scan_file, local_ip2scan_file)
    #port scan
    port_scan_result_file = '{}/port_scan_result.csv'.format(data_path)
    tcp_hitlist_file = '{}/hitlist_tcp.csv'.format(data_path)
    hitlist = []
    active_prefix = set()
    record_file = '{}/port_scan_record.csv'.format(data_path)
    recent_rate_changes = []
    for port in ports_by_rank:
        command = 'zmap -s 47000-50000 -p {} --output-filter="success = 1 && repeat = 0 && classification = synack" -r {} -i {} -f "saddr,sport" --allowlist-file={} -o {}'.format(port, rate, interface, local_ip2scan_file, port_scan_result_file)
        #command = 'zmap -p {} --output-filter="success = 1 && repeat = 0 && classification = synack" -r {} -i {} -f "saddr,sport" --allowlist-file={} -o {}'.format(port2sacn, rate, interface, down_local_file, port_scan_result_file)
        subprocess.run(command, shell=True)
        new_ip2scan = set()
        old_hitlist_len = len(hitlist)
        with open(port_scan_result_file) as ifile:
            while True:
                lines = ifile.readlines(1000000)
                if not lines: break
                for line in lines:
                    ll = line.strip().split(',')
                    if len(ll) == 1: continue
                    target  = ll[0]
                    port = ll[1]
                    if port == '' or port == 'sport': continue
                    lll = target.split('.')
                    prefix = lll[0] + '.' + lll[1] + '.' + lll[2]
                    if prefix not in active_prefix:
                        active_prefix.add(prefix)
                        hitlist.append((target, port))

        with open(local_ip2scan_file) as ifile:
            while True:
                lines = ifile.readlines(1000000)
                if not lines: break
                for line in lines:
                    target = line.strip()
                    ll = line.strip().split('.')
                    prefix = ll[0] + '.' + ll[1] + '.' + ll[2]
                    if prefix not in active_prefix:
                        new_ip2scan.add(target)

        with open(local_ip2scan_file, 'w') as ofile:
            for ip in new_ip2scan:
                print(ip, file = ofile)
        
        with open(record_file, 'a') as ofile:
            output = str(len(active_prefix))+','+str(time.time())
            print(output, file = ofile)
        
        if len(hitlist) > old_hitlist_len:
            change_rate = (len(hitlist) - old_hitlist_len) / len(hitlist)
        else:
            change_rate = 0
        recent_rate_changes.append(change_rate)
        if len(recent_rate_changes) > LEN_RECENT_RATE_CHANGES:
            recent_rate_changes.pop(0)
        avg_change_rate = sum(recent_rate_changes) / len(recent_rate_changes)
        if avg_change_rate < 0.01:
            break
        
    with open(tcp_hitlist_file, 'w') as ofile:
        for elm in hitlist:
            output = elm[0] + ',' + elm[1]
            print(output, file = ofile)
    
    #上传s3
    s3_tcp_hitlist_file = 'saip/{}/{}/hitlist_tcp.csv'.format(date, experiment_id)
    print('upload tcp_hitlist file [{}] to [{}]...'.format(tcp_hitlist_file, s3_tcp_hitlist_file))
    s3_buket.upload_files(s3_tcp_hitlist_file, tcp_hitlist_file)
