# -*- coding: utf-8 -*-
import utils.S3BucketUtil as s3bu
import argparse
import os
import subprocess

user_home = os.path.expanduser('~')
data_path = user_home + '/.saip'
if not os.path.exists(data_path):
    os.makedirs(data_path)

def get_common_port(date, rate, interface):
    #从s3下载candidate file
    s3_buket = s3bu.S3Bucket()
    down_s3_file = 'saip/candidate_vps/{}.csv'.format(date)
    down_local_file = '{}/candidate_vps-{}.csv'.format(data_path, date)
    print('Scanner: download candidate file [{}] from s3 to [{}]'.format(down_s3_file, down_local_file))
    s3_buket.download_file(down_s3_file, down_local_file)
    #端口扫描
    sample_port_scan_result_file = '{}/sample_port_scan_result-{}.csv'.format(data_path, date)
    command = 'zmap -s 30000-50000 -p 0-65535 --output-filter="success = 1 && repeat = 0 && classification = synack" -r {} -i {} -f "saddr,sport" --allowlist-file={} -o {}'.format(rate, interface, down_local_file, sample_port_scan_result_file)
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
    portfeq_file = '{}/portfeq-{}.csv'.format(data_path, date)
    with open(portfeq_file, 'w') as ofile:
        for port in port2feq:
            output = port + ',' + str(port2feq[port])
            print(output, file = ofile)

def give_port2scan(date, lim = 1000):
    port_feq_file = '{}/portfeq-{}.csv'.format(data_path, date)
    ports = []
    count = 0 
    with open(port_feq_file) as ifile:
        lines = ifile.readlines()
        for line in lines:
            if count < lim:
                line = line.strip().split(',')
                port = int(line[0])
                ports.append(port)
            count += 1

    ports = sorted(ports)
    pl = ports[0]
    pr = ports[0]
    port2scan = ''
    newports = ports[1:]
    for port in newports:
        if port == pr + 1:
            pr = port
        else:
            if pl == pr:
                port2scan += str(pl) + ','
            else:
                port2scan += str(pl) + '-' + str(pr) + ','
            pl = port
            pr = port
    if pl == pr:
        port2scan += str(pl) + ','
    else:
        port2scan += str(pl) + '-' + str(pr) + ','
    return port2scan.strip(',')
    #return 80

def build_tcp_hitlist(date, rate, interface):
    #从s3下载ip2do_port_scan
    s3_buket = s3bu.S3Bucket()
    down_s3_file = 'saip/ip2do_port_scan/{}.csv'.format(date)
    down_local_file = '{}/ip2do_port_scan-{}.csv'.format(data_path, date)
    print('Scanner: download candidate file [{}] from s3 to [{}]'.format(down_s3_file, down_local_file))
    s3_buket.download_file(down_s3_file, down_local_file)
    #确定扫描的端口
    port2sacn = give_port2scan(date, 1000)
    #端口扫描
    port_scan_result_file = '{}/port_scan_result-{}.csv'.format(data_path, date)
    command = 'zmap -s 30000-50000 -p {} --output-filter="success = 1 && repeat = 0 && classification = synack" -r {} -i {} -f "saddr,sport" --allowlist-file={} -o {}'.format(port2sacn, rate, interface, down_local_file, port_scan_result_file)
    #command = 'zmap -p {} --output-filter="success = 1 && repeat = 0 && classification = synack" -r {} -i {} -f "saddr,sport" --allowlist-file={} -o {}'.format(port2sacn, rate, interface, down_local_file, port_scan_result_file)
    subprocess.run(command, shell=True)
    #生成tcp_hitlsit
    tcp_hitlist_file = '{}/hitlist_tcp-{}.csv'.format(data_path, date)
    prefix_record = set()
    with open(tcp_hitlist_file, 'w') as ofile:
        with open(port_scan_result_file) as ifile:
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
                    ll = target.split('.')
                    prefix = ll[0] + '.' + ll[1] + '.' + ll[2]
                    if prefix not in prefix_record:
                        output = target + ',' + port
                        print(output, file=ofile)
                        prefix_record.add(prefix)
    #上传s3
    print('Scanner: upload tcp_hitlist file [{}] to s3...'.format(tcp_hitlist_file))
    up_s3_file = 'saip/hitlist_tcp/{}.csv'.format(date)
    s3_buket.upload_files(up_s3_file, tcp_hitlist_file)
    #清理中间数据
    subprocess.run(['rm', '-r', data_path])



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYYY-mm-dd')
    parser.add_argument('--rate', type=str, help='scan rate/pps')
    parser.add_argument('--interface', type=str, help='network interface')
    date = parser.parse_args().date
    rate = parser.parse_args().rate
    interface = parser.parse_args().interface
    get_common_port(date, rate, interface)
    build_tcp_hitlist(date, rate, interface)