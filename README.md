# Auth Server Playground

An OAuth 2.0 and OpenID Connect authorization server built with [Authlib](https://authlib.org/), configured from a web interface.
Run it to test and debug an OAuth 2.0 or OpenID Connect client, or to try the server features of Authlib.
For a client to test an authorization server, see [Auth Playground](https://github.com/authlib/auth-playground).

This page explains how to run, try and configure the server.
It assumes basic knowledge of OAuth 2.0 and OpenID Connect.
It does not explain how to build a server with Authlib: for that, read the [Authlib documentation](https://docs.authlib.org/) and the [example OAuth 2.0 server](https://github.com/authlib/example-oauth2-server).

## Features

The web interface has five sections:

- **Server**: the published metadata, the grants, the client authentication methods, PKCE, the token lifetimes, the scopes and the ID token algorithms. The defaults follow RFC 9700.
- **Keys**: the keys that sign the ID tokens, one active key per algorithm. A rotation creates a new active key. The old key stays in the JWKS until it is deleted, so clients can still verify the tokens it signed.
- **Clients**: create and edit the clients by hand. The form marks the values that the server does not support.
- **Personas**: the users of the server. The server checks no password: at the authorization endpoint, pick the persona to act as. Each persona has the standard claims of OpenID Connect. The persona page lists the consents of the persona, and revokes them.
- **Snapshot**: export the configuration, the personas, the clients and the signing keys to a JSON file, and import such a file. The file holds the client secrets and the private keys: keep it private.

The server supports these grants and endpoints:

- Authorization code grant, with PKCE (RFC 7636).
- Implicit grant, off by default.
- Resource owner password credentials grant, off by default.
- Client credentials grant.
- Refresh token grant.
- Token revocation (RFC 7009).
- Authorization server metadata (RFC 8414), at `/.well-known/oauth-authorization-server`.
- A protected resource, `/api/resource`, that returns the scope, the client and the persona of the access token.

OpenID Connect is on when the scopes of the server hold `openid`, as in the default configuration.
The server then supports:

- ID tokens in the authorization code flow, signed with RS256, PS256, ES256 or Ed25519.
- The UserInfo endpoint, at `/oauth/userinfo`.
- Discovery, at `/.well-known/openid-configuration`, and the public keys at `/oauth/jwks`.
- The `prompt`, `max_age`, `login_hint`, `ui_locales` and `acr_values` parameters.
  `login_hint` preselects a persona, and `ui_locales` sets the language of the persona and consent pages.
  The server accepts any `acr` value: the ID token holds the first requested value.
- A default `max_age` for each client.
- The `claims` parameter. The consent page lists the claims that the scopes do not give.
- Request objects in the `request` parameter, unsigned only (`alg` `none`): the clients have no keys yet.
  The `request_uri` parameter is not supported.

## Run the server

Run the server from the source code with [uv](https://docs.astral.sh/uv/):

```console
$ uv run auth-server-playground
 * Serving Flask app 'auth_server_playground'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:3000
Press CTRL+C to quit
```

Open `http://127.0.0.1:3000/` to reach the web interface.
The server stores its data in a SQLite database in the Flask instance folder.

Run the server with Docker:

```bash
docker build -t auth-server-playground .
docker run -p 3000:3000 -v auth-server-playground:/data auth-server-playground
```

The container stores the database in `/data`.
The volume keeps the data when the container is removed.

## Try the client credentials grant

The default configuration enables the authorization code, refresh token and client credentials grants.
The client credentials grant needs no persona, so it is the shortest way to get a token.
Create a client in the web interface:

1. Open **Clients**, then **New client**.
2. Set **Client ID** to `demo`.
3. Check `client_credentials` in **Grant types**.
4. Set **Scopes** to `profile`.
5. Keep `client_secret_basic` as the **Authentication method**.
6. Click **Save**. The client page shows the client secret.

Request a token, with `<SECRET>` replaced by the client secret:

```console
$ curl -u demo:<SECRET> -d grant_type=client_credentials -d scope=profile http://127.0.0.1:3000/oauth/token
{"token_type": "Bearer", "access_token": "XUpVEr75OavL4VdLKitjwnvypTJx2fn92JxW1LYiXC", "expires_in": 3600, "scope": "profile"}
```

Call the protected resource with the access token:

```console
$ curl -H "Authorization: Bearer <ACCESS_TOKEN>" http://127.0.0.1:3000/api/resource
{"scope":"profile","client_id":"demo"}
```

The password grant is off by default, as RFC 9700 §2.4 requires:

```console
$ curl -u demo:<SECRET> -d grant_type=password -d username=alice -d password=x http://127.0.0.1:3000/oauth/token
{"error": "unsupported_grant_type"}
```

Enable it in **Server**, then in the client.

## Try OpenID Connect

Clients find the endpoints of the server in its discovery document:

```console
$ curl -s http://127.0.0.1:3000/.well-known/openid-configuration | jq '{issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri}'
{
  "issuer": "http://127.0.0.1:3000",
  "authorization_endpoint": "http://127.0.0.1:3000/oauth/authorize",
  "token_endpoint": "http://127.0.0.1:3000/oauth/token",
  "userinfo_endpoint": "http://127.0.0.1:3000/oauth/userinfo",
  "jwks_uri": "http://127.0.0.1:3000/oauth/jwks"
}
```

Set up the `demo` client of the previous section for the authorization code flow:

1. Open **Clients**, then `demo`.
2. Set **Redirect URIs** to `http://127.0.0.1:8000/callback`.
   No server needs to listen there: the code shows in the address bar of the browser.
3. Check `authorization_code` in **Grant types**, and `code` in **Response types**.
4. Set **Scopes** to `openid profile`.
5. Click **Save**.

The default configuration requires PKCE for all clients.
Create a code verifier, and print an authorization URL with its challenge:

```bash
VERIFIER=$(openssl rand -hex 32)
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')
echo "http://127.0.0.1:3000/oauth/authorize?response_type=code&client_id=demo&redirect_uri=http://127.0.0.1:8000/callback&scope=openid%20profile&nonce=n-0S6_WzA2Mj&code_challenge=$CHALLENGE&code_challenge_method=S256"
```

Open the URL in a browser, pick a persona, and click **Accept**.
The browser goes to the redirect URI, such as `http://127.0.0.1:8000/callback?code=NfcKoEYKZVGeX3HWX0sfAA6HDZUtwmJl2QpC35gU6saJVXPc`.
In the same shell, exchange the code for the tokens, with `<CODE>` replaced by the code:

```console
$ curl -s -u demo:<SECRET> -d grant_type=authorization_code -d code=<CODE> -d redirect_uri=http://127.0.0.1:8000/callback -d code_verifier=$VERIFIER http://127.0.0.1:3000/oauth/token | tee token.json
{"token_type": "Bearer", "access_token": "BnRYDC5spCh9C4kugcA99yieB5dzFgzDtyTfuBcbk8", "expires_in": 3600, "refresh_token": "Tdh8EtppfPcv7bMcKEQP8FYqz32UrD5Eqos1kCqQQQKnDxzE", "scope": "openid profile", "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4cnMzM2lqd0IxNHdrWmR6ZWUxbWttZFJNakxtVTJWekN4VlE0RDJzNGsifQ..."}
```

The ID token is a JWT, shortened in this output.
Read some of its claims:

```console
$ jq '.id_token | split(".")[1] | gsub("-";"+") | gsub("_";"/") | @base64d | fromjson | {iss, aud, sub, nonce, auth_time, name}' token.json
{
  "iss": "http://127.0.0.1:3000",
  "aud": [
    "demo"
  ],
  "sub": "c0a1e3d2-7b5f-4e7a-9d2c-1f6b8a4e5c3d",
  "nonce": "n-0S6_WzA2Mj",
  "auth_time": 1794764875,
  "name": "Alice Martin"
}
```

Call the UserInfo endpoint with the access token:

```console
$ curl -s -H "Authorization: Bearer $(jq -r .access_token token.json)" http://127.0.0.1:3000/oauth/userinfo
{"name": "Alice Martin", "given_name": "Alice", "family_name": "Martin", "middle_name": "Claire", "nickname": "Ali", "preferred_username": "alice", "profile": "https://alice.example/profile", "website": "https://alice.example", "gender": "female", "birthdate": "1990-12-10", "zoneinfo": "Europe/Paris", "locale": "fr-FR", "updated_at": 1794764773, "sub": "c0a1e3d2-7b5f-4e7a-9d2c-1f6b8a4e5c3d", "picture": "http://127.0.0.1:3000/personas/1/picture.svg"}
```

The server passes the Config and Basic plans of the OpenID Foundation conformance suite, with a few warnings.
`conformance/expected-failures.json` lists them, with their reasons.
[`conformance/README.md`](conformance/README.md) explains how to run the suite against the server.

## Configuration

The server reads its configuration from environment variables.
`example.env` lists them.
Copy it to `.env`: the `auth-server-playground` command loads `.env` from the current directory.

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | generated | Key that signs the session cookies. Without it, the server generates a key once and stores it in the database. |
| `DATABASE_URL` | `sqlite:///db.sqlite` | SQLAlchemy database URL. A relative SQLite path goes in the Flask instance folder. |
| `INITIAL_SNAPSHOT` | unset | Snapshot file loaded when the database is empty. An invalid file stops the server. |
| `PROXY_FIX` | `false` | Set to `true` behind a reverse proxy. |
| `AUTHLIB_INSECURE_TRANSPORT` | unset | Set to `1` to accept plain HTTP requests. |
| `FLASK_RUN_HOST` | `127.0.0.1` | Address of the `auth-server-playground` command. |
| `FLASK_RUN_PORT` | `3000` | Port of the `auth-server-playground` command. |
| `FLASK_DEBUG` | `False` | Set to `True` to enable the Flask debug mode. |

Per RFC 6749 §3.1 and §3.2, the OAuth 2.0 endpoints require TLS.
The server accepts plain HTTP on loopback addresses, such as `127.0.0.1`.
On other hosts, plain HTTP requests get an `insecure_transport` error, unless `AUTHLIB_INSECURE_TRANSPORT` is set.
Never set it in production.

The Docker image serves the server with [Granian](https://github.com/emmett-framework/granian), configured by these variables:

| Variable | Value in the image | Description |
|---|---|---|
| `GRANIAN_HOST` | `0.0.0.0` | Address the server listens on. |
| `GRANIAN_PORT` | `3000` | Port the server listens on. |
| `GRANIAN_INTERFACE` | `wsgi` | Interface between Granian and the application. |
| `GRANIAN_LOG_ACCESS_ENABLED` | `true` | Log each request. |
| `GRANIAN_WORKERS` | `1` | Number of worker processes. |

Granian reads its other settings from `GRANIAN_*` variables too.
The workers share the key stored in the database, so several workers need no `SECRET_KEY`.

## Run in production

The web interface has no authentication.
Anyone who reaches it can read the client secrets, export a snapshot, and replace the configuration, the personas and the clients.
Only expose the server to people who may change it.

The `auth-server-playground` command uses the Flask development server.
It is enough for local tests.
For a public deployment, install the `granian` extra and serve the application with Granian:

```bash
uv sync --extra granian
uv run granian --interface wsgi --factory --host 0.0.0.0 --port 3000 --env-files .env auth_server_playground:create_app
```

`--workers` sets the number of worker processes.

## Run behind a reverse proxy

Behind a reverse proxy or a load balancer, enable the proxy support:

```bash
export PROXY_FIX=true
```

The server then trusts the `X-Forwarded-Proto` and `X-Forwarded-Prefix` headers set by the closest proxy.
When the proxy handles TLS, the server sees HTTPS requests and accepts them.
Under a sub-path, the redirections start with the path prefix.
The server also trusts `X-Forwarded-For`, which only changes the client address in the logs.
Only enable it when a proxy is present.
Without a proxy, clients could forge these headers.

The proxy must set `X-Forwarded-Proto` and forward the original `Host` header.
It must also set `X-Forwarded-Prefix`, or clear it when the server is at the root of the domain.
Otherwise clients could send their own prefix.
With nginx, at the root of the domain:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix "";
}
```

Under a sub-path, the proxy removes the prefix from the request path and sends it in `X-Forwarded-Prefix`:

```nginx
location /auth/ {
    proxy_pass http://127.0.0.1:3000/;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix /auth;
}
```

## Development

Run the tests:

```bash
uv run pytest
```

Install the Git hooks that check the code style and the commit messages:

```bash
uv run prek install
```

After a change to a translatable string, update the catalog, then translate the new strings in `src/auth_server_playground/translations/fr/LC_MESSAGES/messages.po`:

```bash
uv run prek run pybabel-extract --all-files
uv run pybabel update -i src/auth_server_playground/translations/messages.pot -d src/auth_server_playground/translations
```

The front-end dependencies are listed in `package.json` and copied in `src/auth_server_playground/static/vendor`.
To update one, install the new version and copy its files:

```bash
npm install <PACKAGE>@<VERSION>
npm run vendor
```

## License

The server is distributed under the BSD 3-Clause license. See [LICENSE](LICENSE).
It started from the [example OAuth 2.0 server](https://github.com/authlib/example-oauth2-server) of Authlib.
