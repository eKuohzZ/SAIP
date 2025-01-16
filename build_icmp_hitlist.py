# -*- coding: utf-8 -*-
import S3BucketUtil as s3bu
import argparse
import os
import subprocess

user_home = os.path.expanduser('~')
data_path = user_home + '/.saip'
if not os.path.exists(data_path):
    os.makedirs(data_path)

def build_hitlist():
    #获取日期
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYYY-mm-dd')
    date = parser.parse_args().date
    #从s3下载活跃地址扫描文件
    s3_buket = s3bu.S3Bucket()
    date_dir_list = s3_buket.get_list_s3('active_ip/ipv4')
    down_s3_file = ''
    s3_date_dir = ''
    for dir in reversed(date_dir_list):
        if s3_buket.check_file_exist('active_ip/ipv4/{}'.format(dir), 'icmp.txt.xz'):
            down_s3_file = 'active_ip/ipv4/{}/icmp.txt.xz'.format(dir)
            s3_date_dir = dir
            break
    down_local_file = '{}/active_ipv4-{}.txt.xz'.format(data_path, date)
    print('Analyzer: download active_ipv4_data [{}] from s3 to [{}]...'.format(down_s3_file, down_local_file))
    s3_buket.download_file(down_s3_file, down_local_file)
    #解压
    active_ipv4_data_file = '{}/active_ipv4-{}.txt'.format(data_path, date)
    print('Analyzer: unzip active_ipv4_data to [{}]...'.format(active_ipv4_data_file))
    if os.path.exists(active_ipv4_data_file):
        print('Analyzer: file already exist!')
    else:
        subprocess.run(['xz', '-d', down_local_file])
    #建立icmp_ip/24_hitlist
    prefix2ip = {}
    hitlist_file = '{}/hitlist_icmp-{}.csv'.format(data_path, date)
    print('Analyzer: build icmp_hitlist [{}]...'.format(hitlist_file))
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

    with open(hitlist_file, 'w') as ofile:
        for prefix in prefix2ip:
            print(prefix2ip[prefix], file=ofile)
    #上传icmp_hitlist到s3
    up_s3_file = 'saip/hitlist_icmp/{}.csv'.format(date)
    print('Analyzer: upload icmp_hitlist [{}] to s3...'.format(up_s3_file))
    s3_buket.upload_files(up_s3_file, hitlist_file)
    
    
if __name__ == '__main__':
    build_hitlist()