import socket
import requests

def observer_get_status():
    try:
        response = requests.get('http://{}:{}/get_status'.format('47.88.24.140', '36502'), timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error getting observer status: {e}")
        return None
    return response.json()

print(observer_get_status())