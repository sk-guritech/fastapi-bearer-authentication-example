from __future__ import annotations

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)


def call_authentication(username: str, password: str) -> tuple[str, str]:
    print('=' * 20 + '  Authenticate  ' + '=' * 20)
    response = requests.post(
        'https://127.0.0.1/authenticate', data={
            'username': username, 'password': password,
        }, verify=False,
    )

    print(response)

    json_response = response.json()
    access_token = json_response['access_token']
    refresh_token = json_response['refresh_token']

    print(f'access_token  : {access_token}')
    print(f'refresh_token : {refresh_token}')

    return access_token, refresh_token


def call_refresh(refresh_token: str) -> tuple[str, str] | None:
    print('=' * 20 + '  Refresh Token  ' + '=' * 19)
    response = requests.post(
        'https://127.0.0.1/refresh', headers={
            'Authorization': f'Bearer {refresh_token}',
        }, verify=False,
    )

    try:
        print(response)
        json_response = response.json()
        access_token = json_response['access_token']
        refresh_token = json_response['refresh_token']
    except KeyError:
        return None

    print(f'access_token  : {access_token}')
    print(f'refresh_token : {refresh_token}')

    return access_token, refresh_token


def call_logout(access_token: str) -> requests.Response:
    print('=' * 20 + '  Logout  ' + '=' * 26)
    response = requests.post(
        'https://127.0.0.1/logout', headers={
            'Authorization': f'Bearer {access_token}',
        }, verify=False,
    )

    return response


username = 'johndoe'
password = 'secret'

access_token, refresh_token = call_authentication(username, password)
access_token, refresh_token = call_refresh(refresh_token)  # type: ignore
print(call_logout(access_token))
access_token, refresh_token = call_authentication(username, password)
access_token, refresh_token = call_authentication(username, password)
access_token, refresh_token = call_refresh(refresh_token)  # type: ignore
access_token, refresh_token = call_refresh(refresh_token)  # type: ignore
print(call_logout(access_token))
call_refresh(refresh_token)
print(call_logout(access_token))
