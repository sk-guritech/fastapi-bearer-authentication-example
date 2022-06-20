# fastapi-bearer-authentication-example
This is an Example that adds session functionality to the sample code described in the FastAPI tutorial "OAuth2 with Password (and hashing), Bearer with JWT tokens".

## Requirements
```
python3
pip
docker-compose
```

## Usage
Build the environments by following below commands.
```
$ git clone git@github.com:sk-guritech/fastapi-bearer-authentication-example.git
$ cd fastapi-bearer-authentication-example
$ pip install requests
$ docker-compose up -d
```

## Docker Containers
This example consists of the Docker containers in the table below.
| NAMES | PORTS | DESCRIPTION |
| ----- | ----- | ----------- |
| web   |80, 443| Nginx is running. |
| app   |       | FastAPI is running. |
| db    |       | The database stores users table. |
| redis |       | The redis stores jti for managing sessions. |


```mermaid
flowchart LR
    client --> |HTTP Request| web --> |Unix Sokcet| app
    app --> |SELECT| db
    app --> |GET/SET/DELETE| redis
```

## APIs
Provides following APIs.

- /authenticate

    Send password and username to get access token and refresh token.
    ```
    $ curl -X POST http://127.0.0.1/authenticate -d "username=johndoe&password=secret"

    {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTQ3NTY2OSwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6OTY5NTBiY2QyMjkyNGRiNGEyNDBkZGFhZGEzOTgwYzkiLCJncmFudCI6ImFjY2VzcyJ9.NtB1sCTnbgS_hvCMWsmVvOjP9NGx4CqBLVntDyDhq50","refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTU1ODQ2OSwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6MzE2YzJiMWM1MmUwNDQzMmFiOThlM2M4ZTBmMTVlMzIiLCJncmFudCI6InJlZnJlc2gifQ.wiy_FSMMlWhPmZJ0OF9Q7IKSIJnQzdHfZxKiFADLOFA","token_type":"bearer"}
    ```

- /refresh

    Send refresh token to get a new access token and a refresh token.
    ```
    $ curl -X POST http://127.0.0.1/refresh -H \
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTU1ODQ2OSwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6MzE2YzJiMWM1MmUwNDQzMmFiOThlM2M4ZTBmMTVlMzIiLCJncmFudCI6InJlZnJlc2gifQ.wiy_FSMMlWhPmZJ0OF9Q7IKSIJnQzdHfZxKiFADLOFA"

    {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTQ3NTc2NiwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6MGY4MGQ0MDMwMWZkNGJmNTlkZWVhNjhkOTlmZjRhZTkiLCJncmFudCI6ImFjY2VzcyJ9.8uSgKK1HpgrSnRkI3ZeTTf9rXWxOOrDDr6YhzMVjQYM","refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTU1ODU2NiwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6NDBlOWNhYjNlOGM2NDJhYjgxOGFkYWY4NmFlYzNmNmIiLCJncmFudCI6InJlZnJlc2gifQ.WACqUQ0Xm9tpGQYPBDjARpOASboma8bwhBHpM4IfCNM","token_type":"bearer"}
    ```

- /logout

    Send access token and deactivate current access token and refresh token.
    ```
    $ curl -X POST http://127.0.0.1/logout -H \
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTQ3NTc2NiwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6MGY4MGQ0MDMwMWZkNGJmNTlkZWVhNjhkOTlmZjRhZTkiLCJncmFudCI6ImFjY2VzcyJ9.8uSgKK1HpgrSnRkI3ZeTTf9rXWxOOrDDr6YhzMVjQYM"

    {}
    ```

## Author
- @sk-guritech
    - [https://github.com/sk-guritech/](https://github.com/sk-guritech/)
    - [https://twitter.com/GuriTech](https://twitter.com/GuriTech)

## License
Copyright (c) 2022~ @sk-guritech

Released under the MIT License
