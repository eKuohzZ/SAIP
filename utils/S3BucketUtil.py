# -*- coding: utf-8 -*-
#updown_s3.py

import boto3
import re
import os
import math
import hashlib
import urllib3
import warnings
from boto3.s3.transfer import TransferConfig
from botocore.exceptions import ClientError
from botocore.config import Config
from utils.conf import S3_CONFIG
import time

# 抑制SSL警告（仅在禁用SSL验证时）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class S3Bucket(object):
    """
    need download boto3 module
    """
    def __init__(self):
        S3_FILE_CONF = S3_CONFIG

        self.access_key = S3_FILE_CONF.get("ACCESS_KEY")
        self.secret_key = S3_FILE_CONF.get("SECRET_KEY")
        self.bucket_name = S3_FILE_CONF.get("BUCKET_NAME")
        self.url = S3_FILE_CONF.get("ENDPOINT_URL")
        self.verify_ssl = S3_FILE_CONF.get("VERIFY_SSL", True)

        # 配置SSL验证选项
        boto_config = Config(
            signature_version='s3v4',
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            read_timeout=60,
            connect_timeout=30
        )
        
        # 如果是HTTPS端点，根据配置决定是否验证SSL
        if self.url and self.url.startswith('https://'):
            if not self.verify_ssl:
                print("警告: SSL证书验证已禁用，这可能存在安全风险")

        # 连接s3
        # 注意：verify参数需要在client创建时传递，而不是在Config中
        client_kwargs = {
            'service_name': 's3',
            'aws_access_key_id': self.access_key,
            'aws_secret_access_key': self.secret_key,
            'endpoint_url': self.url,
            'config': boto_config
        }
        
        # 对于HTTPS端点，添加SSL验证配置
        if self.url and self.url.startswith('https://'):
            client_kwargs['verify'] = self.verify_ssl
            
        try:
            self.s3 = boto3.client(**client_kwargs)
            # 测试连接
            print(f"S3客户端初始化成功，端点: {self.url}")
        except Exception as e:
            print(f"S3客户端初始化失败: {e}")
            raise

    def upload_normal(self, path_prefix, file_upload):
        """
        ##小文件上传-上传本地文件到s3指定文件夹下
        """   
        GB = 1024 ** 3
        #default config
        config = TransferConfig(multipart_threshold=5*GB, max_concurrency=10, use_threads=True) #10默认，增加数值增加带宽
        file_name = os.path.basename(file_upload)
        object_name = os.path.join(path_prefix,file_name)
        print('-----begin to upload!----')
        try:
            self.s3.upload_file(file_upload, self.bucket_name, object_name, Config=config)
        except ClientError as e:
            print('error happend!' + str(e))
            return False
        print('upload done!')
        return True

    def upload_files(self, path_bucket, path_local, max_retries=3):
        for attempt in range(max_retries):
            try:
                '''
                ##大文件上传
                args:
                path_bucket: bucket桶下的路径，文件上传dir
                path_local: 待上传文件的绝对路径
                '''
                # multipart upload
                chunk_size = 52428800
                source_size = os.stat(path_local).st_size
                print('source_size=', source_size)
                chunk_count = int(math.ceil(source_size/float(chunk_size)))
                
                print(f'开始上传文件 {path_local} (尝试 {attempt + 1}/{max_retries})')
                mpu = self.s3.create_multipart_upload(Bucket=self.bucket_name, Key=path_bucket)
                part_info = {'Parts': []}
                
                with open(path_local, 'rb') as fp:
                    for i in range(chunk_count):
                        offset = chunk_size * i
                        bytes = min(chunk_size, source_size-offset)
                        data = fp.read(bytes)
                        md5s = hashlib.md5(data)
                        new_etag = '"%s"' % md5s.hexdigest()
                        
                        # 为每个分片添加重试机制
                        part_uploaded = False
                        for part_attempt in range(3):
                            try:
                                response = self.s3.upload_part(
                                    Bucket=self.bucket_name,
                                    Key=path_bucket, 
                                    PartNumber=i+1,
                                    UploadId=mpu['UploadId'],
                                    Body=data
                                )
                                part_uploaded = True
                                break
                            except Exception as part_exc:
                                print(f"分片 {i+1} 上传失败 (尝试 {part_attempt + 1}/3): {part_exc}")
                                if part_attempt == 2:  # 最后一次尝试失败
                                    raise part_exc
                                time.sleep(1)  # 等待1秒后重试
                        
                        if not part_uploaded:
                            raise Exception(f"分片 {i+1} 上传失败")
                            
                        print('uploading %s %s'%(path_local, str(i/chunk_count)))
                        parts={
                            'PartNumber': i+1,
                            'ETag': response['ETag']  # 使用服务器返回的ETag
                        }
                        part_info['Parts'].append(parts)
                        
                print('%s uploaded!' % (path_local))
                self.s3.complete_multipart_upload(
                    Bucket=self.bucket_name,
                    Key=path_bucket,
                    UploadId=mpu['UploadId'],
                    MultipartUpload=part_info
                )
                print('%s uploaded success!' % (path_local))
                return True
                
            except Exception as exc:
                print('%s uploaded failed! (尝试 %d/%d)' % (path_local, attempt + 1, max_retries))
                print("error occurred.", exc)
                
                # 如果不是最后一次尝试，等待后重试
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2  # 递增等待时间
                    print(f"等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    # 最后一次尝试失败，返回False
                    return False
        
        return False

    def download_file(self, object_name, path_local):
        """
        download the single file from s3 to local dir
        """
        GB = 1024**3
        config = TransferConfig(multipart_threshold=2*GB, max_concurrency=10, use_threads=True)
        suffix = object_name.split('.')[-1]
        if path_local[-len(suffix):] == suffix:
            file_name = path_local
            dir_name = os.path.dirname(file_name)
            if not os.path.exists(dir_name):
                os.mkdir(dir_name)
        else:
            if not os.path.exists(path_local):
                os.mkdir(path_local)
            file_name = os.path.join(path_local, os.path.basename(object_name))
        print(object_name, file_name)
        try:
            self.s3.download_file(self.bucket_name,object_name,file_name,Config= config)
        except Exception as exc:
            print('some wrong!')
            print("error occurred.", exc)
            return False
        print('downlaod ok', object_name)
        return True
    
    def download_files(self, path_prefix, path_local):
        """
        批量文件下载
        """
        GB = 1024**3
        config = TransferConfig(multipart_threshold=2*GB, max_concurrency=10, use_threads=True)
        list = self.s3.list_objects_v2(Bucket=self.bucket_name, Prefix=path_prefix)['Contents']
        for key in list:
            name = os.path.basename(key['Key'])
            object_name = key['Key']
            print('-----', object_name, name)
            if not os.path.exists(path_local):
                os.makedirs(path_local)
            file_name = os.path.join(path_local, name)
            try:
                self.s3.download_file(self.bucket_name, object_name, file_name,Config= config)
            except Exception as exc:
                print("error occurred.", exc)
                return False
        return True

    def get_list_s3(self, obj_folder_path):
        """
        用来列举出该目录下的所有文件
        args:
            obj_folder_path: 要查询的文件夹路径
        returns: 
            该目录下所有文件列表
        """
        # 用来存放文件列表
        folder_list = []
        continuation_token = None
        while True:
            if continuation_token:
                response = self.s3.list_objects_v2(
                    Bucket=self.bucket_name,
                    Prefix=obj_folder_path,
                    ContinuationToken=continuation_token
                )
            else:
                response = self.s3.list_objects_v2(
                    Bucket=self.bucket_name,
                    Prefix=obj_folder_path,
                ) 
            for prefix in response.get('Contents', []):
                obj_folder_path_len = len(obj_folder_path.split('/'))
                folder_name = prefix['Key'].split('/')[obj_folder_path_len]
                if folder_list == [] or folder_name != folder_list[-1]:
                    folder_list.append(folder_name)

            if response.get('IsTruncated'): continuation_token = response.get('NextContinuationToken')
            else: break
        return folder_list

    
    def delete_object(self, delete_path):
        try:
            self.s3.delete_object(Bucket=self.bucket_name, Key=delete_path)
            print("Successfully deleted '{}' from '{}'.".format(delete_path, self.bucket_name))
        except Exception as e:
            print("Error deleting '{}' from '{}': {}".format(delete_path, self.bucket_name, e))
    
    def check_file_exist(self, folder_path, file_name):
        response = self.s3.list_objects_v2(Bucket=self.bucket_name, Prefix=folder_path)
        for obj in response.get('Contents', []):
            if obj['Key'] == folder_path + '/' + file_name:
                return True
        return False
