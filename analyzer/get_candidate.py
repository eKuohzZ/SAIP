# -*- coding: utf-8 -*-
import utils.S3BucketUtil as s3bu
import argparse
import os
import subprocess
import tqdm

user_home = os.path.expanduser('~')
data_path = user_home + '/.saip'
if not os.path.exists(data_path):
    os.makedirs(data_path)

def get_candidate_vp(input_file, date, hitlist):
    target2ttl = {}
    with open(os.path.join(data_path, input_file)) as ifile:
        lines = ifile.readlines()
        for line in tqdm.tqdm(lines):
            line = line.strip('\n').split(',')
            target = line[0]
            id = int(line[1])
            seq = int(line[2])
            ttl = int(line[3])
            if target not in hitlist: continue#不是探测目标
            if not (id == 1459 or seq == 2636 or id == 1599 or seq == 2496): continue#不符合规范的响应
            #修正ttl范围为[-64, 64]
            if 64<ttl<=128: ttl -= 64 
            elif 128<ttl<=255: ttl -= 191
            if target not in target2ttl:
                target2ttl[target] = {'s': -1, 'o': -1}
            if id == 1459 or seq == 2636:# targetping
                target2ttl[target]['s'] = ttl
            else:
                target2ttl[target]['o'] = ttl
    
    #判断，将candiadte写入文件
    input_filename = input_file.split('-')[-1]
    output_file = '{}/candidate_vp-{}-{}'.format(data_path, date, input_filename)
    with open(output_file, 'w') as ofile: 
        for target in target2ttl:
            if target2ttl[target]['s'] != -1 and target2ttl[target]['o'] != -1:
                if target2ttl[target]['s'] - target2ttl[target]['o'] != 0: print(target, file=ofile)
    #文件上传至s3
    print('Analyzer: upload candidate_vp file [{}] to s3...'.format(output_file))
    up_s3_file = 'saip/candidate_vp/{}/{}'.format(date, input_filename)
    s3_buket = s3bu.S3Bucket()
    s3_buket.upload_files(up_s3_file, output_file)


def get_candidate_vps():
    print('Analyzer: filter anycast candidate by saip-ttl...')
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYYY-mm-dd')
    date = parser.parse_args().date
    #从s3下载ttl_hitlist
    s3_buket = s3bu.S3Bucket()
    down_s3_file = 'saip/hitlist_ttl/{}.csv'.format(date)
    down_local_file = '{}/hitlist_ttl-{}.csv'.format(data_path, date)
    print('Spoofer: download hitlist [{}] from s3...'.format(down_s3_file))
    s3_buket.download_file(down_s3_file, down_local_file)
    #构建hitlist
    icmp_hitlist = set()
    with open('{}/hitlist_icmp-{}.csv'.format(data_path, date)) as ifile:
        lines = ifile.readlines()
        for line in lines:
            line = line.strip()
            icmp_hitlist.add(line)
    #从s3下载并解压ttl_measurement_result
    print('Analyzer: download ttl measurement result from s3...')
    s3_buket = s3bu.S3Bucket()
    ttl_measurement_result_filenames = s3_buket.get_list_s3('saip/measurement_result_ttl/{}'.format(date))
    for ttl_measurement_result_filename in ttl_measurement_result_filenames:
        down_local_file = '{}/measurement_result_ttl-{}-{}'.format(data_path, date, ttl_measurement_result_filename)
        down_s3_file = 'saip/measurement_result_ttl/{}/{}'.format(date, ttl_measurement_result_filename)
        s3_buket.download_file(down_s3_file, down_local_file)
        subprocess.run(['xz', '-d', down_local_file])
    #生成每个vp的candidate结果
    print('Analyzer: start to filter candidate by saip-ttl...')
    key_words = 'measurement_result_ttl-{}'.format(date)
    ttl_measurement_result_filenames = [f for f in os.listdir(data_path) if key_words in f and '.xz' not in f]
    for ttl_measurement_result_filename in ttl_measurement_result_filenames:
        get_candidate_vp(ttl_measurement_result_filename, date, icmp_hitlist)
    #生成总的candidate结果
    candidate_vps = set()
    for filename in os.listdir(data_path):
        key_words = 'candidate_vp-{}'.format(date)
        if key_words in filename:
            with open(os.path.join(data_path, filename)) as ifile:
                lines = ifile.readlines()
                for line in lines:
                    line = line.strip()
                    if line not in candidate_vps:
                        candidate_vps.add(line)
    candidate_vps_file = '{}/candidate_vps-{}.csv'.format(data_path, date)
    with open(candidate_vps_file, 'w') as ofile:
        for candidate in candidate_vps:
            print(candidate, file = ofile)
    #获取candidate prefix的所有活跃ip
    candidate_prefix = set()
    for candidate in candidate_vps:
        ll = candidate.split('.')
        prefix = ll[0] + '.' + ll[1] + '.' + ll[2]
        candidate_prefix.add(prefix)
    active_ipv4_data_file = '{}/active_ipv4-{}.txt'.format(data_path, date)
    ip2do_port_scan_file = '{}/ip2do_port_scan-{}.csv'.format(data_path, date)
    with open(ip2do_port_scan_file, 'w') as ofile:
        with open(active_ipv4_data_file) as ifile:
            while True:
                lines = ifile.readlines(1000000)
                if not lines: break
                for line in lines:
                    line = line.strip()
                    ll = line.split('.')
                    prefix = ll[0] + '.' + ll[1] + '.' + ll[2]
                    if prefix in candidate_prefix:
                        print(line, file = ofile)
    #上传至s3
    print('Analyzer: upload candidate_vps&ip2do_port_scan file to s3...')
    up_s3_file = 'saip/candidate_vps/{}.csv'.format(date)
    s3_buket.upload_files(up_s3_file, candidate_vps_file)
    up_s3_file = 'saip/ip2do_port_scan/{}.csv'.format(date)
    s3_buket.upload_files(up_s3_file, ip2do_port_scan_file)
    

        
if __name__ == '__main__':
    get_candidate_vps()