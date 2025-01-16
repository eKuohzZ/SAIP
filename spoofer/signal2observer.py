import requests
from conf import vpInfo

def start_sniff(method, spoofer, observer, date, mID):
    # 定义要发送的数据
    data = {
        'date': date,
        'mID': mID,
        'method': method,
        'spoofer': spoofer,
        'observer': observer
    }
    # 发送 POST 请求到服务器的 /start_task 路由
    response = requests.post('http://{}:39999/start_task'.format(vpInfo[observer]['publicAddr']), json=data)

def stop_sniff(method, spoofer, observer, date, mID):
    # 定义要发送的数据
    data = {
        'date': date,
        'mID': mID,
        'method': method,
        'spoofer': spoofer,
        'observer': observer
    }
    # 发送 POST 请求到服务器的 /stop_task 路由
    response = requests.post('http://{}:39999/stop_task'.format(vpInfo[observer]['publicAddr']), json=data)