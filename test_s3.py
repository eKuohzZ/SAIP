import S3BucketUtil as s3bu
import os
user_home = os.path.expanduser('~')
s3_buket = s3bu.S3Bucket()
s3_buket.download_file('saip/hitlist_icmp/2024-04-07.csv', user_home + '/saip/src/test_data.csv')
s3_buket.upload_files('saip/hitlist_icmp/test.csv', user_home + '/saip/srctest_data.csv')