# -*- coding: utf-8 -*-
import os

import subprocess

import utils.S3BucketUtil as s3bu
import utils.conf as cf

data_path = cf.get_data_path()

def build_hitlist(date, measurement_id):
    s3_buket = s3bu.S3Bucket()
    # download active ipv4 data from s3
    if cf.if_download_data():
        s3_active_ipv4_dir_list = s3_buket.get_list_s3('active_ip/ipv4')
        for dir in reversed(s3_active_ipv4_dir_list):
            if s3_buket.check_file_exist('active_ip/ipv4/{}'.format(dir), 'icmp.txt.xz'):
                s3_active_ipv4_file = 'active_ip/ipv4/{}/icmp.txt.xz'.format(dir)
                break
        local_active_ipv4_file = '{}/active_ipv4-{}-{}.txt.xz'.format(data_path, date, measurement_id)
        print('download active ipv4 data [{}] to [{}]...'.format(s3_active_ipv4_file, local_active_ipv4_file))
        s3_buket.download_file(s3_active_ipv4_file, local_active_ipv4_file)
        # unzip active ipv4_data
        active_ipv4_data_file = '{}/active_ipv4-{}-{}.txt'.format(data_path, date, measurement_id)
        print('unzip active ipv4 data to [{}]...'.format(active_ipv4_data_file))
        if os.path.exists(active_ipv4_data_file):
            print('active ipv4 data file already exist!')
        else:
            subprocess.run(['xz', '-d', local_active_ipv4_file])
    #build icmp ip/24 hitlist
    prefix2ip = {}
    local_icmp_hitlist_file = '{}/hitlist_icmp-{}-{}.csv'.format(data_path, date, measurement_id)
    print('build icmp hitlist [{}]...'.format(local_icmp_hitlist_file))
    with open(active_ipv4_data_file) as ifile:
        while True:
            lines = ifile.readlines(1000000)
            if not lines: break
            for line in lines:
                line = line.strip()
                ll = line.split('.')
                prefix = ll[0] + '.' + ll[1] + '.' + ll[2]
                if prefix not in prefix2ip:
                    prefix2ip[prefix] = line

    with open(local_icmp_hitlist_file, 'w') as ofile:
        for prefix in prefix2ip:
            print(prefix2ip[prefix], file=ofile)
    #upload icmp hitlist to s3
    s3_icmp_hitlist_file = 'saip/{}/{}/hitlist_icmp.csv'.format(date, measurement_id)
    print('upload icmp hitlist [{}] to [{}]...'.format(local_icmp_hitlist_file, s3_icmp_hitlist_file))
    s3_buket.upload_files(s3_icmp_hitlist_file, local_icmp_hitlist_file)
    
if __name__ == '__main__':
    build_hitlist()