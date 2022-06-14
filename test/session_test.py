import json
from weakref import ReferenceType, ref
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import requests

urllib3.disable_warnings(InsecureRequestWarning)

print("=" * 20 + "  Authenticate  " + "=" * 20)
json_response = requests.post("https://127.0.0.1/authenticate",data={"username": "johndoe", "password": "secret"}, verify=False).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print("access_token  : {}".format(access_token))
print("refresh_token : {}".format(refresh_token))

print("=" * 20 + "  Refresh Token  " + "=" * 19)
json_response = requests.post("https://127.0.0.1/refresh", headers={"Authorization": "Bearer {}".format(refresh_token)}, verify=False).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print("access_token  : {}".format(access_token))
print("refresh_token : {}".format(refresh_token))

print("=" * 20 + "  Refresh Token  " + "=" * 19)
json_response = requests.post("https://127.0.0.1/refresh", headers={"Authorization": "Bearer {}".format(refresh_token)}, verify=False).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print("access_token  : {}".format(access_token))
print("refresh_token : {}".format(refresh_token))

print("=" * 20 + "  Logout  " + "=" * 26)
json_response = requests.post("https://127.0.0.1/logout", headers={"Authorization": "Bearer {}".format(access_token)}, verify=False).json()

print("=" * 20 + "  Refresh Token  " + "=" * 19)
response = requests.post("https://127.0.0.1/refresh", headers={"Authorization": "Bearer {}".format(refresh_token)}, verify=False)
print(response)

print("=" * 20 + "  Authenticate  " + "=" * 20)
json_response = requests.post("https://127.0.0.1/authenticate",data={"username": "johndoe", "password": "secret"}, verify=False).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print("access_token  : {}".format(access_token))
print("refresh_token : {}".format(refresh_token))

print("=" * 20 + "  Refresh Token  " + "=" * 19)
json_response = requests.post("https://127.0.0.1/refresh", headers={"Authorization": "Bearer {}".format(refresh_token)}, verify=False).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print("access_token  : {}".format(access_token))
print("refresh_token : {}".format(refresh_token))

print("=" * 20 + "  Refresh Token  " + "=" * 19)
json_response = requests.post("https://127.0.0.1/refresh", headers={"Authorization": "Bearer {}".format(refresh_token)}, verify=False).json()
access_token = json_response['access_token']
refresh_token = json_response['refresh_token']
print("access_token  : {}".format(access_token))
print("refresh_token : {}".format(refresh_token))