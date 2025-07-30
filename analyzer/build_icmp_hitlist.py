# -*- coding: utf-8 -*-
import os

import subprocess

import utils.S3BucketUtil as s3bu
import utils.conf as cf

def build_hitlist_ipv4(date, experiment_id, if_download):
    data_path = cf.get_data_path(date, experiment_id, 'ipv4')
    s3_buket = s3bu.S3Bucket()
    # download active ipv4 data from s3
    if if_download:
        s3_active_ipv4_dir_list = s3_buket.get_list_s3('active_ip/ipv4')
        for dir in reversed(s3_active_ipv4_dir_list):
            if s3_buket.check_file_exist('active_ip/ipv4/{}'.format(dir), 'icmp.txt.xz'):
                s3_active_ipv4_file = 'active_ip/ipv4/{}/icmp.txt.xz'.format(dir)
                break
        local_active_ipv4_file = '{}/active_ip.txt.xz'.format(data_path)
        print('download active ipv4 data [{}] to [{}]...'.format(s3_active_ipv4_file, local_active_ipv4_file))
        if not os.path.exists(local_active_ipv4_file):
            s3_buket.download_file(s3_active_ipv4_file, local_active_ipv4_file)
        # unzip active ipv4_data
        active_ipv4_data_file = '{}/active_ip.txt'.format(data_path)
        print('unzip active ipv4 data to [{}]...'.format(active_ipv4_data_file))
        if os.path.exists(active_ipv4_data_file):
            print('active ipv4 data file already exist!')
        else:
            subprocess.run(['xz', '-d', local_active_ipv4_file])
    else:
        active_ipv4_data_file = './config/target.csv'
    #build icmp ip/24 hitlist
    prefix2ip = {}
    local_icmp_hitlist_file = '{}/hitlist_icmp.csv'.format(data_path)
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
    s3_icmp_hitlist_file = 'saip/ipv4/{}/{}/hitlist_icmp.csv'.format(date, experiment_id)
    print('upload icmp hitlist [{}] to [{}]...'.format(local_icmp_hitlist_file, s3_icmp_hitlist_file))
    s3_buket.upload_files(s3_icmp_hitlist_file, local_icmp_hitlist_file)

def build_hitlist_ipv6(date, experiment_id, if_download):
    data_path = cf.get_data_path(date, experiment_id, 'ipv6')
    s3_buket = s3bu.S3Bucket()
    if if_download:
        local_active_ipv6_raw_file = '{}/active_ip_raw.txt.xz'.format(data_path)
        if not os.path.exists(local_active_ipv6_raw_file):
            cf.download_latest_icmp6(local_active_ipv6_raw_file)
        # unzip active ipv6_data
        active_ipv6_data_raw_file = '{}/active_ip_raw.txt'.format(data_path)
        active_ipv6_data_file = '{}/active_ip.txt'.format(data_path)
        print('unzip active ipv6 data to [{}]...'.format(active_ipv6_data_raw_file))
        if os.path.exists(active_ipv6_data_raw_file):
            print('active ipv6 data file already exist!')
        else:
            subprocess.run(['xz', '-d', local_active_ipv6_raw_file])
        with open(active_ipv6_data_file, 'w') as ofile:
            with open(active_ipv6_data_raw_file, 'r') as ifile:
                while True:
                    lines = ifile.readlines(1000000)
                    if not lines: break
                    for line in lines:
                        line = line.strip()
                        ll = line.split(',')
                        if len(ll) == 1: continue
                        print(ll[0], file=ofile)
    else:
        active_ipv6_data_file = './config/target6.csv'
    # build icmp ip/48 hitlist
    prefix2ip = {}
    local_icmp_hitlist_file = '{}/hitlist_icmp.csv'.format(data_path)
    print('build icmp hitlist [{}]...'.format(local_icmp_hitlist_file))
    with open(active_ipv6_data_file) as ifile:
        while True:
            lines = ifile.readlines(1000000)
            if not lines: break
            for line in lines:
                line = line.strip()
                prefix = cf.extract_ipv6_48_prefix(line)
                if prefix not in prefix2ip:
                    prefix2ip[prefix] = line

    with open(local_icmp_hitlist_file, 'w') as ofile:
        for prefix in prefix2ip:
            print(prefix2ip[prefix], file=ofile)
    #upload icmp hitlist to s3
    s3_icmp_hitlist_file = 'saip/ipv6/{}/{}/hitlist_icmp.csv'.format(date, experiment_id)
    print('upload icmp hitlist [{}] to [{}]...'.format(local_icmp_hitlist_file, s3_icmp_hitlist_file))
    s3_buket.upload_files(s3_icmp_hitlist_file, local_icmp_hitlist_file)

def build_hitlist(date, experiment_id, if_download, ip_type):
    if ip_type == 'ipv4':
        build_hitlist_ipv4(date, experiment_id, if_download)
    elif ip_type == 'ipv6':
        build_hitlist_ipv6(date, experiment_id, if_download)

if __name__ == '__main__':
    build_hitlist()