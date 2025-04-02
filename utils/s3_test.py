import os
import subprocess

import utils.S3BucketUtil as s3bu
import utils.conf as cf

def main():
    date = '250225'
    experiment_id = '12'
    data_path = cf.get_data_path('250225', '12')
    s3_buket = s3bu.S3Bucket()
    s3_ttl_result_files = s3_buket.get_list_s3('saip/{}/{}/ttl_result'.format(date, experiment_id))
    local_ttl_result_dir = '{}/ttl_result'.format(data_path)
    if not os.path.exists(local_ttl_result_dir):
        os.makedirs(local_ttl_result_dir)
    for file_name in s3_ttl_result_files:
        local_ttl_result_file = '{}/ttl_result/{}'.format(data_path, file_name)
        s3_ttl_result_file = 'saip/{}/{}/ttl_result/{}'.format(date, experiment_id, file_name)
        s3_buket.download_file(s3_ttl_result_file, local_ttl_result_file)
        if not os.path.exists(local_ttl_result_file[:-3]):
            subprocess.run(['xz', '-d', local_ttl_result_file])
    

if __name__ == '__main__':
    main()