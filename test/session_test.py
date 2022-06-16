from __future__ import annotations

import json
from weakref import ref
from weakref import ReferenceType

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

print('=' * 20 + '  Authenticate  ' + '=' * 20)
json_response = requests.post(
    'https://127.0.0.1/authenticate', data={
        'username': 'johndoe', 'password': 'secret',
    }, verify=False,
).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print(f'access_token  : {access_token}')
print(f'refresh_token : {refresh_token}')

print('=' * 20 + '  Refresh Token  ' + '=' * 19)
json_response = requests.post(
    'https://127.0.0.1/refresh', headers={
        'Authorization': f'Bearer {refresh_token}',
    }, verify=False,
).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print(f'access_token  : {access_token}')
print(f'refresh_token : {refresh_token}')

print('=' * 20 + '  Refresh Token  ' + '=' * 19)
json_response = requests.post(
    'https://127.0.0.1/refresh', headers={
        'Authorization': f'Bearer {refresh_token}',
    }, verify=False,
).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print(f'access_token  : {access_token}')
print(f'refresh_token : {refresh_token}')

print('=' * 20 + '  Logout  ' + '=' * 26)
json_response = requests.post(
    'https://127.0.0.1/logout', headers={
        'Authorization': f'Bearer {access_token}',
    }, verify=False,
).json()

print('=' * 20 + '  Refresh Token  ' + '=' * 19)
response = requests.post(
    'https://127.0.0.1/refresh',
    headers={'Authorization': f'Bearer {refresh_token}'}, verify=False,
)
print(response)

print('=' * 20 + '  Authenticate  ' + '=' * 20)
json_response = requests.post(
    'https://127.0.0.1/authenticate', data={
        'username': 'johndoe', 'password': 'secret',
    }, verify=False,
).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print(f'access_token  : {access_token}')
print(f'refresh_token : {refresh_token}')

print('=' * 20 + '  Refresh Token  ' + '=' * 19)
json_response = requests.post(
    'https://127.0.0.1/refresh', headers={
        'Authorization': f'Bearer {refresh_token}',
    }, verify=False,
).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print(f'access_token  : {access_token}')
print(f'refresh_token : {refresh_token}')

print('=' * 20 + '  Refresh Token  ' + '=' * 19)
json_response = requests.post(
    'https://127.0.0.1/refresh', headers={
        'Authorization': f'Bearer {refresh_token}',
    }, verify=False,
).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print(f'access_token  : {access_token}')
print(f'refresh_token : {refresh_token}')
