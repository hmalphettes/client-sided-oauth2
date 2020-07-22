# Client-Sided-Oauth - a stateless oauth provider that extracts a user profile from a client cert

Exposes an oauth2 Identity Provider that authenticates a user according to a client certificate.

Following the https://github.com/ory/fosite-example and using the same license.
Copyright will be marked when files are copied from ory/fosite-example


# Usage

Run the oauth2 server:

```
OAUTH2_SERVER_ADDR=https://localhost:3486 OAUTH2_TLS_KEY=./keys/localhost.key OAUTH2_TLS_CRT=./keys/localhost.crt DOWNSTREAM_SERVER_ADDR=http://localhost:8080 go run main.go
```

Run the example client application:

```
cd exampleclientapp && OAUTH2_SERVER_ADDR=https://localhost:3486 PORT=8080 go run main.go
```

Access the client app on http://localhost:8080
It sends the browser to https://localhost:3846/oauth2/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&response_type=token%20id_token&scope=fosite%20openid&state=some-random-state-foobar&nonce=some-random-nonce
Which returns then the browser to the callback page and then displays the profile of the user according to the Subject of the client cert

# Usage: Mattermost Gitlab SSO

```
Application ID:     <your-mattermost-url>/gitlab
Application Secret: foobar
GitLab Site URL:    https://localhost:3846
```

Create a System Admin bot - or at least with the following permissions: `edit_other_users` and `add_user_to_team`.

Specify the following environment variables

```
export MATTERMOST_SERVER_ADDR=http://localhost:8065
export MATTERMOST_BOT_TOKEN=howtynsfojfupk4fubggq3qmde
export MATTERMOST_DEFAULT_TEAM_NAME=testteam # optional team to which newly created users are added
```

Now `Login With Gitlab` will extract the username as the CN of the client certificate and log you into mattermost.

Also if you want this server to take care of the TLS termination and run mattermost on `http:8065`:

```
DOWNSTREAM_SERVER_ADDR=http://localhost:8065 go run main.go
```

# Notes on making the client side cert for development purpose

https://gist.github.com/mtigas/952344
I used the ec algos.

```
openssl x509 -req -in localhost.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out localhost.crt -days 500 -sha256
openssl x509 -in localhost.crt -text -noout
```

Install the pfx in the OS: https://support.globalsign.com/digital-certificates/digital-certificate-installation/install-pfx-pkcs12-file-mac-osx-safari-chrome
