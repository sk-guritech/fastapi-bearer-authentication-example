# fastapi-bearer-authentication-example
FastAPIチュートリアルの ["OAuth2 with Password (and hashing), Bearer with JWT tokens"](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/#update-the-dependencies) に記載されているサンプルコードにセッション機能を追加したExampleです。

## Requirements
```
python3
pip
docker-compose
```

## Usage
下記のコマンドで環境構築してください。
```
$ git clone git@github.com:sk-guritech/fastapi-bearer-authentication-example.git
$ cd fastapi-bearer-authentication-example
$ pip install requests
$ docker-compose up -d
```

## Docker Containers
このExampleは以下のDockerコンテナによって構成されています。
| NAMES | PORTS | DESCRIPTION |
| ----- | ----- | ----------- |
| web   |80, 443| Nginxが入っています。
| app   |       | FastAPIが動作しています。|
| db    |       | usersテーブルを保有しているデータベースです。|
| redis |       | セッション管理用のjtiをストアするRedisサーバーです。|


```mermaid
flowchart LR
    client <--> |HTTP Request| web <--> |Unix Sokcet| app
    app <--> |SELECT| db
    app <--> |GET/SET/DELETE| redis
```

## APIs
以下のAPIが提供されます。

- /authenticate

    passwordとusernameを送信して、access tokenとrefresh tokenを取得します。
    ```
    $ curl -X POST http://127.0.0.1/authenticate -d "username=johndoe&password=secret"

    {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTQ3NTY2OSwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6OTY5NTBiY2QyMjkyNGRiNGEyNDBkZGFhZGEzOTgwYzkiLCJncmFudCI6ImFjY2VzcyJ9.NtB1sCTnbgS_hvCMWsmVvOjP9NGx4CqBLVntDyDhq50","refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTU1ODQ2OSwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6MzE2YzJiMWM1MmUwNDQzMmFiOThlM2M4ZTBmMTVlMzIiLCJncmFudCI6InJlZnJlc2gifQ.wiy_FSMMlWhPmZJ0OF9Q7IKSIJnQzdHfZxKiFADLOFA","token_type":"bearer"}
    ```

- /refresh

    refresh tokenを送信して、新しいaccess tokenとrefresh tokenを取得します。
    ```
    $ curl -X POST http://127.0.0.1/refresh -H \
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTU1ODQ2OSwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6MzE2YzJiMWM1MmUwNDQzMmFiOThlM2M4ZTBmMTVlMzIiLCJncmFudCI6InJlZnJlc2gifQ.wiy_FSMMlWhPmZJ0OF9Q7IKSIJnQzdHfZxKiFADLOFA"

    {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTQ3NTc2NiwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6MGY4MGQ0MDMwMWZkNGJmNTlkZWVhNjhkOTlmZjRhZTkiLCJncmFudCI6ImFjY2VzcyJ9.8uSgKK1HpgrSnRkI3ZeTTf9rXWxOOrDDr6YhzMVjQYM","refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTU1ODU2NiwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6NDBlOWNhYjNlOGM2NDJhYjgxOGFkYWY4NmFlYzNmNmIiLCJncmFudCI6InJlZnJlc2gifQ.WACqUQ0Xm9tpGQYPBDjARpOASboma8bwhBHpM4IfCNM","token_type":"bearer"}
    ```

- /logout

    access tokenを送信して、現在のaccess tokenとrefresh tokenを無効化します。
    ```
    $ curl -X POST http://127.0.0.1/logout -H \
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMUc1RVhQR0VSRUY0UTlROE5LUVBKM0JCVCIsImV4cCI6MTY1NTQ3NTc2NiwianRpIjoiMDFHNUVYUEdFUkVGNFE5UThOS1FQSjNCQlQ6MGY4MGQ0MDMwMWZkNGJmNTlkZWVhNjhkOTlmZjRhZTkiLCJncmFudCI6ImFjY2VzcyJ9.8uSgKK1HpgrSnRkI3ZeTTf9rXWxOOrDDr6YhzMVjQYM"

    {}
    ```

## Author
- github: [@GuriTech](https://github.com/sk-guritech/)
- twitter: [@GuriTech](https://twitter.com/GuriTech)

## License
Copyright (c) 2022~ @sk-guritech

Released under the MIT License
