# -*- coding: utf-8 -*-
import os

import subprocess
import tqdm

import utils.conf as cf
import utils.S3BucketUtil as s3bu

def validate_tcp_connection(tcps_result_file, date, experiment_id):
    data_path = cf.get_data_path(date, experiment_id)
    target2stat = {}
    with open(os.path.join(data_path, tcps_result_file)) as ifile:
        lines = ifile.readlines()
        for line in tqdm.tqdm(lines):
            line = line.strip('').split(',')
            flag = line[0]
            seq = line[1]
            ack = line[2]
            target = line[3]
            dport = line[4]
            sport = line[5]
            ttl = line[6]

            if target not in target2stat:
                target2stat[target] = {}
            if sport not in target2stat[target]:
                target2stat[target][sport] = 'wait_for_2nd_handshake'
            if ack == '1001' and target2stat[target][sport] == 'wait_for_2nd_handshake' and flag == 'SA':
                target2stat[target][sport] = 'wait_for_3rd_handshake'
            elif ack == '1006' and target2stat[target][sport] == 'wait_for_3rd_handshake' and 'A' in flag and 'S' not in flag and 'R' not in flag:
                target2stat[target][sport] = 'connected'
    
    target2label = {}
    for target in target2stat:
        target2label[target] = 'invalid'
        for sport in target2stat[target]:
            if target2stat[target][sport] == 'connected':
                target2label[target] = 'valid'
                break
    return target2label

def get_anycast_vp(tcp_result_file, date, experiment_id, hitlist):
    data_path = cf.get_data_path(date, experiment_id)
    target2conn_label = validate_tcp_connection(tcp_result_file)
    target2stat = {}
    with open(os.path.join(data_path, tcp_result_file)) as ifile:
        lines = ifile.readlines()
        for line in tqdm.tqdm(lines):
            line = line.strip('\n').split(',')
            flag = line[0]
            seq = line[1]
            ack = line[2]
            target = line[3]
            dport = line[4]
            sport = line[5]
            ttl = line[6]

            if target not in hitlist: continue
            if target not in target2stat:
                target2stat[target] = {}
            if sport not in target2stat[target]:
                target2stat[target][sport] = 'wait_for_2nd_handshake'
            if ack == '1001' and target2stat[target][sport] == 'wait_for_2nd_handshake' and flag == 'SA':
                target2stat[target][sport] = 'wait_for_3rd_handshake'
            elif ack == '1006' and target2stat[target][sport] == 'wait_for_3rd_handshake' and 'A' in flag and 'S' not in flag and 'R' not in flag:
                target2stat[target][sport] = 'connected'

    target2anycast_label = {}
    for target in target2stat:
        if target not in target2conn_label:
            continue
        elif target2conn_label[target] != 'valid':
            continue
        is_anycast = False
        if any(value == 'wait_for_3rd_handshake' for value in target2stat[target].values()) and all(value != 'connected' for value in target2stat[target].values()):
            is_anycast = True
        target2anycast_label[target] = is_anycast
    #get anycast vp
    anycast_vp_dir = '{}/anycast_vp'.format(data_path)
    if not os.path.exists(anycast_vp_dir):
        os.makedirs(anycast_vp_dir)
    local_anycast_vp_file = '{}/anycast_vp/anycast_vp/{}'.format(data_path, tcp_result_file)
    with open(local_anycast_vp_file, 'w') as ofile:
        for target in target2anycast_label:
            if target2anycast_label[target]: print(target, file=ofile)
    #upload to s3
    s3_anycast_vp_file = 'saip/{}/{}/anycast_vp/{}'.format(date, experiment_id, tcp_result_file)
    print('upload anycast_vp file [{}] to [{}]...'.format(local_anycast_vp_file, s3_anycast_vp_file))
    s3_buket = s3bu.S3Bucket()
    s3_buket.upload_files(s3_anycast_vp_file, local_anycast_vp_file)


def get_anycast_vps(date, experiment_id):
    data_path = cf.get_data_path(date, experiment_id)
    print('filter anycast candidate by saip-tcp...')
    #download hitlist
    s3_buket = s3bu.S3Bucket()
    s3_hitlist_file = 'saip/{}/{}/hitlist_tcp.csv'.format(date)
    local_hitlist_file = '{}/hitlist_tcp.csv'.format(data_path)
    print('download hitlist [{}] to [{}]...'.format(s3_hitlist_file, local_hitlist_file))
    s3_buket.download_file(s3_hitlist_file, local_hitlist_file)
    #read hitlist
    tcp_hitlist = set()
    with open(local_hitlist_file) as ifile:
        lines = ifile.readlines()
        for line in lines:
            line = line.strip().split(',')[0]
            tcp_hitlist.add(line)
    #download tcp measurement result
    print('download tcp measurement result from s3...')
    s3_buket = s3bu.S3Bucket()
    for flag in ["", 's']:
        local_tcp_result_dir = '{}/tcp{}_result'.format(data_path, flag)
        if not os.path.exists(local_tcp_result_dir):
            os.makedirs(local_tcp_result_dir)
        tcp_result_filenames = s3_buket.get_list_s3('saip/{}/{}/tcp{}_result'.format(date, experiment_id, flag))
        for tcp_result_filename in tcp_result_filenames:
            local_tcp_result_file = '{}/tcp{}_result/{}'.format(data_path, flag, tcp_result_filename)
            s3_tcp_result_file = 'saip/{}/{}/tcp{}_result/{}'.format(date, experiment_id, flag, tcp_result_filename)
            s3_buket.download_file(s3_tcp_result_file, local_tcp_result_file)
            if not os.path.exists(local_tcp_result_file[:-3]):
                subprocess.run(['xz', '-d', local_tcp_result_file])
    #get anycast vp
    print('start to identify anycast by saip-tcp...')
    tcp_result_files = os.listdir('{}/tcp_result'.format(data_path))
    for tcp_result_file in tcp_result_files:
        get_anycast_vp(tcp_result_file, date, experiment_id, tcp_hitlist)
    #get all anycast vp
    anycast_vps = set()
    anycast_dir = '{}/anycast_vp'.format(data_path)
    for filename in os.listdir(anycast_dir):
        with open(os.path.join(anycast_dir, filename)) as ifile:
            lines = ifile.readlines()
            for line in lines:
                line = line.strip()
                if line not in anycast_vps:
                    anycast_vps.add(line)
    local_anycast_vps_file = '{}/anycast_vps.csv'.format(data_path)
    with open(local_anycast_vps_file, 'w') as ofile:
        for anycast in anycast_vps:
            print(anycast, file = ofile)
    #upload to s3
    s3_anycast_vps_file = 'saip/anycast_vps/{}.csv'.format(date)
    print('upload anycast vps file [{}] to [{}]...'.format(local_anycast_vps_file, s3_anycast_vps_file))
    s3_buket = s3bu.S3Bucket()
    s3_buket.upload_files(s3_anycast_vps_file, local_anycast_vps_file)
    
if __name__ == '__main__':
    get_anycast_vps()