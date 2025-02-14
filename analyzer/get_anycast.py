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

def get_anycast_vp(input_file, date, hitlist):
    target2stat = {}
    with open(os.path.join(data_path, input_file)) as ifile:
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

            if target not in hitlist: continue#不是探测目标
            if target not in target2stat:
                target2stat[target] = {}
            if sport not in target2stat[target]:
                target2stat[target][sport] = 'wait_for_2nd_hand'
            if ack == '1001' and target2stat[target][sport] == 'wait_for_2nd_hand' and flag == 'SA':
                target2stat[target][sport] = 'wait_for_3rd_hand'
            elif ack == '1006' and target2stat[target][sport] == 'wait_for_3rd_hand' and 'A' in flag and 'S' not in flag and 'R' not in flag:
                target2stat[target][sport] = 'connected'

    target2tag = {}
    for target in target2stat:
        is_any = ''
        for sport in target2stat[target]:
            if target2stat[target][sport]== 'connected':
                if is_any == '' or is_any == 'U':
                    is_any = 'U'
                else:
                    is_any = 'C'
                    break
            elif target2stat[target][sport] != 'wait_for_2nd_hand':
                if is_any == '' or is_any == 'A':
                    is_any = 'A'
                else:
                    is_any = 'C'
                    break
        target2tag[target] = is_any
    #判断，将anycast ip写入文件
    input_filename = input_file.split('-')[-1]
    output_file = '{}/anycast_vp-{}-{}'.format(data_path, date, input_filename)
    with open(output_file, 'w') as ofile: 
        for target in target2tag:
            if target2tag[target] == 'A': print(target, file=ofile)
    #文件上传至s3
    print('Analyzer: upload anycast_vp file [{}] to s3...'.format(output_file))
    up_s3_file = 'saip/anycast_vp/{}/{}'.format(date, input_filename)
    s3_buket = s3bu.S3Bucket()
    s3_buket.upload_files(up_s3_file, output_file)


def get_anycast_vps():
    print('Analyzer: filter anycast candidate by saip-tcp...')
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYYY-mm-dd')
    date = parser.parse_args().date
    #从s3下载tcp_hitlist
    s3_buket = s3bu.S3Bucket()
    down_s3_file = 'saip/hitlist_tcp/{}.csv'.format(date)
    down_local_file = '{}/hitlist_tcp-{}.csv'.format(data_path, date)
    print('Spoofer: download hitlist [{}] from s3...'.format(down_s3_file))
    s3_buket.download_file(down_s3_file, down_local_file)
    #构建hitlist
    tcp_hitlist = set()
    with open(down_local_file) as ifile:
        lines = ifile.readlines()
        for line in lines:
            line = line.strip().split(',')[0]
            tcp_hitlist.add(line)
    #从s3下载并解压tcp_measurement_result
    print('Analyzer: download tcp measurement result from s3...')
    s3_buket = s3bu.S3Bucket()
    tcp_measurement_result_filenames = s3_buket.get_list_s3('saip/measurement_result_tcp/{}'.format(date))
    for tcp_measurement_result_filename in tcp_measurement_result_filenames:
        down_local_file = '{}/measurement_result_tcp-{}-{}'.format(data_path, date, tcp_measurement_result_filename)
        down_s3_file = 'saip/measurement_result_tcp/{}/{}'.format(date, tcp_measurement_result_filename)
        s3_buket.download_file(down_s3_file, down_local_file)
        subprocess.run(['xz', '-d', down_local_file])
    #生成每个vp的anycast结果
    print('Analyzer: start to identify anycast by saip-tcp...')
    key_words = 'measurement_result_tcp-{}'.format(date)
    tcp_measurement_result_filenames = [f for f in os.listdir(data_path) if key_words in f and '.xz' not in f]
    for tcp_measurement_result_filename in tcp_measurement_result_filenames:
        get_anycast_vp(tcp_measurement_result_filename, date, tcp_hitlist)
    #生成总的anycast结果
    anycast_vps = set()
    for filename in os.listdir(data_path):
        key_words = 'anycast_vp-{}'.format(date)
        if key_words in filename:
            with open(os.path.join(data_path, filename)) as ifile:
                lines = ifile.readlines()
                for line in lines:
                    line = line.strip()
                    if line not in anycast_vps:
                        anycast_vps.add(line)
    anycast_vps_file = '{}/anycast_vps-{}.csv'.format(data_path, date)
    with open(anycast_vps_file, 'w') as ofile:
        for anycast in anycast_vps:
            print(anycast, file = ofile)
    #上传至s3
    print('Analyzer: upload anycast_vps file to s3...')
    up_s3_file = 'saip/anycast_vps/{}.csv'.format(date)
    s3_buket.upload_files(up_s3_file, anycast_vps_file)
    subprocess.run(['rm', '-r', data_path])
    
if __name__ == '__main__':
    get_anycast_vps()