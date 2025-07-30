# -*- coding: utf-8 -*-
import os

import subprocess
import tqdm

import utils.S3BucketUtil as s3bu
import utils.conf as cf

def get_candidate_vp(input_file_dir, input_file_name, date, experiment_id, hitlist, ip_type):
    data_path = cf.get_data_path(date, experiment_id, ip_type)
    target2ttl = {}
    received_target = set()
    with open(os.path.join(input_file_dir, input_file_name)) as ifile:
        lines = ifile.readlines()
        for line in tqdm.tqdm(lines):
            line = line.strip('\n').split(',')
            target = line[0]
            id = int(line[1])
            seq = int(line[2])
            ttl = int(line[3])
            if target not in hitlist:# not in hitlist
                if target not in received_target: received_target.add(target)
                continue
            if not (id == 1459 or seq == 2636 or id == 1599 or seq == 2496):
                if target not in received_target: received_target.add(target)
                continue
            if 64<ttl<=128: ttl -= 64 
            elif 128<ttl<=255: ttl -= 191
            if target not in target2ttl:
                target2ttl[target] = {'sent_by_spoofer': -1, 'sent_by_observer': -1}
            if id == 1459 or seq == 2636:# targetping
                target2ttl[target]['sent_by_spoofer'] = ttl
            else:
                target2ttl[target]['sent_by_observer'] = ttl
    #chcek and write to file
    candidate_dir = '{}/candidate_vp'.format(data_path)
    if not os.path.exists(candidate_dir):
        os.makedirs(candidate_dir)
    candidate_file = '{}/{}'.format(candidate_dir, input_file_name)
    with open(candidate_file, 'w') as ofile: 
        for target in hitlist:
            if target in target2ttl and target2ttl[target]['sent_by_spoofer'] == target2ttl[target]['sent_by_observer']: continue
            print(target, file=ofile)
    #upload to s3
    s3_candidate_vp_file = 'saip/{}/{}/{}/candidate_vp/{}'.format(ip_type, date, experiment_id, input_file_name)
    print('upload candidate_vp file [{}] to [{}]...'.format(candidate_file, s3_candidate_vp_file))
    s3_buket = s3bu.S3Bucket()
    s3_buket.upload_files(s3_candidate_vp_file, candidate_file)


def get_candidate_vps(date, experiment_id, if_download, ip_type):
    data_path = cf.get_data_path(date, experiment_id, ip_type)
    print('filter anycast candidate by saip-ttl...')
    #get icmp hitlist
    s3_icmp_hitlist_file = 'saip/{}/{}/{}/hitlist_icmp.csv'.format(ip_type, date, experiment_id)
    local_icmp_hitlist_file = '{}/hitlist_icmp.csv'.format(data_path)
    if not os.path.exists(local_icmp_hitlist_file):
        print('download icmp hitlist [{}] to [{}]...'.format(s3_icmp_hitlist_file, local_icmp_hitlist_file))
        s3_buket = s3bu.S3Bucket()
        s3_buket.download_file(s3_icmp_hitlist_file, local_icmp_hitlist_file)
    icmp_hitlist = set()
    with open(local_icmp_hitlist_file) as ifile:
        lines = ifile.readlines()
        for line in lines:
            line = line.strip()
            icmp_hitlist.add(line)
    #download ttl measurement result from s3
    print('download ttl measurement result from s3...')
    s3_buket = s3bu.S3Bucket()
    s3_ttl_result_files = s3_buket.get_list_s3('saip/{}/{}/{}/ttl_result'.format(ip_type, date, experiment_id))
    local_ttl_result_dir = '{}/ttl_result'.format(data_path)
    if not os.path.exists(local_ttl_result_dir):
        os.makedirs(local_ttl_result_dir)
    for file_name in s3_ttl_result_files:
        local_ttl_result_file = '{}/ttl_result/{}'.format(data_path, file_name)
        s3_ttl_result_file = 'saip/{}/{}/{}/ttl_result/{}'.format(ip_type, date, experiment_id, file_name)
        s3_buket.download_file(s3_ttl_result_file, local_ttl_result_file)
        if not os.path.exists(local_ttl_result_file[:-3]):
            subprocess.run(['xz', '-d', local_ttl_result_file])
    # get candidate
    print('start to filter candidate by saip-ttl...')
    for root, _, files in os.walk(local_ttl_result_dir):
        for file_name in files:
            get_candidate_vp(root, file_name, date, experiment_id, icmp_hitlist, ip_type)
    # get total candidate
    candidate_vps = set()
    candidate_dir = '{}/candidate_vp'.format(data_path)
    for filename in os.listdir(candidate_dir):
        with open(os.path.join(candidate_dir, filename)) as ifile:
            lines = ifile.readlines()
            for line in lines:
                line = line.strip()
                if line not in candidate_vps: candidate_vps.add(line)
    local_candidate_vps_file = '{}/candidate_vps.csv'.format(data_path)
    with open(local_candidate_vps_file, 'w') as ofile:
        for candidate in candidate_vps: print(candidate, file = ofile)
    #get all active ip of candidate prefix
    candidate_prefix = set()
    for candidate in candidate_vps:
        if ip_type == 'ipv4':
            ll = candidate.split('.')
            prefix = ll[0] + '.' + ll[1] + '.' + ll[2]
        else:
            prefix = cf.extract_ipv6_48_prefix(candidate)
        candidate_prefix.add(prefix)
    if if_download:
        active_ip_data_file = '{}/active_ip.txt'.format(data_path)
    else:
        if ip_type == 'ipv4':
            active_ip_data_file = './config/target.csv'
        else:
            active_ip_data_file = './config/target6.csv'
    local_ip2do_port_scan_file = '{}/ip2do_port_scan.csv'.format(data_path)
    with open(local_ip2do_port_scan_file, 'w') as ofile:
        with open(active_ip_data_file) as ifile:
            if ip_type == 'ipv4':
                while True:
                    lines = ifile.readlines(1000000)
                    if not lines: break
                    for line in lines:
                        line = line.strip()
                        ll = line.split('.')
                        prefix = ll[0] + '.' + ll[1] + '.' + ll[2]
                        if prefix in candidate_prefix: print(line, file = ofile)
            else:
                while True:
                    lines = ifile.readlines(1000000)
                    if not lines: break
                    for line in lines:
                        line = line.strip()
                        prefix = cf.extract_ipv6_48_prefix(line)
                        if prefix in candidate_prefix: print(line, file = ofile)

    #upload to s3
    print('upload candidate_vps file and ip2do_port_scan file to s3...')
    s3_candidate_vps_file = 'saip/{}/{}/{}/candidate_vps.csv'.format(ip_type, date, experiment_id)
    s3_buket.upload_files(s3_candidate_vps_file, local_candidate_vps_file)
    s3_ip2do_port_scan_file = 'saip/{}/{}/{}/ip2do_port_scan.csv'.format(ip_type, date, experiment_id)
    s3_buket.upload_files(s3_ip2do_port_scan_file, local_ip2do_port_scan_file)

