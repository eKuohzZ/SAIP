# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from conf import vpInfo
import tcp4, ttl4
import argparse
import S3BucketUtil as s3bu

user_home = os.path.expanduser('~')
data_path = user_home + '/.saip'
if not os.path.exists(data_path):
    os.makedirs(data_path)

def main():
    #接收参数
    parser = argparse.ArgumentParser()
    parser.add_argument('--date', type=str, help='YYYY-mm-dd')
    parser.add_argument('--mID', type=str, help='ID of measurement')
    parser.add_argument('--method', type=str, help='ttl or tcp')
    parser.add_argument('--spoofer', type=str, help='name of spoofer')
    parser.add_argument('--observer', type=str, help='name of observer')
    date = parser.parse_args().date
    mID = parser.parse_args().mID
    method = parser.parse_args().method
    spooferNam = parser.parse_args().spoofer
    observerNam = parser.parse_args().observer
    #从s3下载targetFile
    s3_buket = s3bu.S3Bucket()
    if 'ttl' in method:
            down_s3_file = 'saip/hitlist_icmp/{}.csv'.format(date)
            down_local_file = '{}/hitlist_icmp-{}.csv'.format(data_path, date)
    elif 'tcp' in method:
            down_s3_file = 'saip/hitlist_tcp/{}.csv'.format(date)
            down_local_file = '{}/hitlist_tcp-{}.csv'.format(data_path, date)
    print('Spoofer: download hitlist [{}] from s3 to [{}]...'.format(down_s3_file, down_local_file))
    s3_buket.download_file(down_s3_file, down_local_file)
    targetFile = down_local_file
    #根据role和method执行对应探测工作
    if method == 'tcp':
        tcp4.TCPsend(date, mID, spooferNam, observerNam, targetFile)
    elif method == 'ttl':
        ttl4.TTLsend(date, mID, spooferNam, observerNam, targetFile)

if __name__ == "__main__":
   main()