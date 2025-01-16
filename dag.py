# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
from airflow import DAG
from airflow.datasets import Dataset
from airflow.operators.bash import BashOperator
from airflow.operators.dummy import DummyOperator
from airflow.utils.task_group import TaskGroup

from airflow_kubernetes_job_operator.kubernetes_job_operator import KubernetesJobOperator
# https://iqtczlgclp.feishu.cn/sheets/shtcn0dhqpTj9K1VRzlGzBhCmSd
from sqlalchemy_utils.types.enriched_datetime.pendulum_date import pendulum

PYTHON = '/home/kdp/anaconda3/bin/python'
JOBS_DIR = '/home/kdp/runtime/ki3/ki3-jobs/jobs'
default_args = {
    'owner':'xiangk',
    'queue':'k01',
    'start_date': pendulum.datetime(2022, 12, 25,tz='Asia/Shanghai'),
    'dagrun_timeout': timedelta(minutes=120),
    'retries': 0,
    'retry_delay': timedelta(minutes=1),
    'email': ['xiangk@zgclab.edu.cn'],
    'email_on_failure': True,
}

#{spoofer: {observer: {mID}}}
mID =   {'SAV01': {'SV2': '1'}, 
        'SAVLON': {'SV2': '11'}, 
        'SAVHK': {'SV2': '21'}}

conf = {'SAV01': {'interface': 'eno8380', 'packet_rate': 100000}, 
        'scanner': {'interface': 'eth0', 'packet_rate': 2500000}}

with DAG(
    dag_id = 'saip_anycast_detection',
    default_args = default_args|{'owner':'zhouke'},
    schedule = '00 00 * * 3',
    doc_md="""
    SAIP-任播检测
    """,
) as dag:
    data_date = '{{ (data_interval_start + macros.timedelta(days=7)+macros.timedelta(hours=8)).strftime("%Y-%m-%d") }}'
    build_icmp_hitlist = BashOperator(
        task_id = 'build_icmp_hitlist',
        queue = 'k01',
        bash_command='cd {path} && {python} {script} {args}'.format(
            path=f'{JOBS_DIR}/saip_anycast_detection',
            python=PYTHON,
            script='build_icmp_hitlist.py',
            args=f'--date {data_date}'
        ),
    )
    with TaskGroup(group_id='saip_ttl_sav01') as saip_ttl_sav01:
        saip_ttl_sav01_hk2 = BashOperator(
        task_id = 'saip_ttl_sav01_hk2',
        queue = 'SAV01',
        bash_command='cd {path} && {python} {script} {args}'.format(
            path=f'{JOBS_DIR}/saip_anycast_detection/spoofer',
            python=PYTHON,
            script='spoofer.py',
            args=f'--date {data_date} --method ttl --mID {mID['SAV01']['HK2']} --spoofer {'SAV01'} --observer {'HK2'}'
        ),
        #add more observer...
    )
    with TaskGroup(group_id='saip_ttl_savlon') as saip_ttl_savlon:
        saip_ttl_savlon_hk2 = BashOperator(
        task_id = 'saip_ttl_savlon_hk2',
        queue = 'SAVLON',
        bash_command='cd {path} && {python} {script} {args}'.format(
            path=f'{JOBS_DIR}/saip_anycast_detection/spoofer',
            python=PYTHON,
            script='spoofer.py',
            args=f'--date {data_date} --method ttl --mID {mID['SAVLON']['HK2']} --spoofer {'SAVLON'} --observer {'HK2'}'
        ),
        #add more observer...
    )
    #add more spoofer...
    get_candidate = BashOperator(
        task_id = 'get_candidate',
        queue = 'k01',
        bash_command='cd {path} && {python} {script} {args}'.format(
            path=f'{JOBS_DIR}/saip_anycast_detection',
            python=PYTHON,
            script='get_candidate.py',
            args=f'--date {data_date}'
        ),
    )
    build_tcp_hitlist = BashOperator(
        task_id = 'build_tcp_hitlist',
        queue = 'scanner',
        bash_command='cd {path} && {python} {script} {args}'.format(
            path=f'{JOBS_DIR}/saip_anycast_detection',
            python=PYTHON,
            script='build_tcp_hitlist.py',
            args=f'--date {data_date} --rate {conf['scanner']['packet_rate']} --interface{conf['scanner']['interface']}'
        ),
    )
    with TaskGroup(group_id='saip_tcp_sav01') as saip_tcp_sav01:
        saip_tcp_sav01_hk2 = BashOperator(
        task_id = 'saip_tcp_sav01_hk2',
        queue = 'SAV01',
        bash_command='cd {path} && {python} {script} {args}'.format(
            path=f'{JOBS_DIR}/saip_anycast_detection/spoofer',
            python=PYTHON,
            script='spoofer.py',
            args=f'--date {data_date} --method tcp --mID {mID['SAV01']['HK2']} --spoofer {'SAV01'} --observer {'HK2'}'
        ),
        #add more observer...
    )
    #add more spoofer...
    get_anycast = BashOperator(
        task_id = 'get_anycast',
        queue = 'k01',
        bash_command='cd {path} && {python} {script} {args}'.format(
            path=f'{JOBS_DIR}/saip_anycast_detection',
            python=PYTHON,
            script='get_anycast.py',
            args=f'--date {data_date}'
        ),
    )
    build_icmp_hitlist >> saip_ttl_sav01 >> saip_ttl_savlon >> get_candidate >> build_tcp_hitlist >> saip_tcp_sav01 >> get_anycast