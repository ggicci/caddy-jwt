# caddy-jwt

A Caddy HTTP Authentication Provider - who Facilitates JWT Authentication

This module fulfilled [`http.handlers.authentication`](https://caddyserver.com/docs/modules/http.handlers.authentication) middleware under namespace `http.authentication.providers`.

## Install

```bash
xcaddy --with github.com/ggicci/caddy-jwt
```

## Playground

You can play this module with the example configuration under the [example](./example) folder.

```bash
git clone https://github.com/ggicci/caddy-jwt.git
cd caddy-jwt
make example

TEST_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NTU4OTI2NzAsImp0aSI6IjgyMjk0YTYzLTk2NjAtNGM2Mi1hOGE4LTVhNjI2NWVmY2Q0ZSIsInVpZCI6MzQwNjMyNzk2MzUxNjkzMiwidXNlcm5hbWUiOiJnZ2ljY2kiLCJuc2lkIjozNDA2MzMwMTU3MTM3OTI2fQ.HWHw4qX4OGgCyNNa5En_siktjpoulTNwABXpEwQI4Q8

curl -v "http://localhost:8080?access_token=${TEST_TOKEN}"
# You should see authenticated output:
#
# User Authenticated with ID: 3406327963516932
#
# And the following command should also work:
curl -v -H"X-Api-Token: ${TEST_TOKEN}" "http://localhost:8080"
curl -v -H"Authorization: Bearer ${TEST_TOKEN}" "http://localhost:8080"
```

## Configuration

This module works as a provider to Caddy's [Authentication](https://caddyserver.com/docs/modules/http.handlers.authentication) handler:

```json
{
  "handler": "authentication",
  "providers": {
    "jwt": {
      "mode": "internal",
      "internal": {
        "sign_key": "NFL5*0Bc#9U6E@tnmC&E7SUN6GwHfLmY",
        "from_header": ["X-Api-Token", "Authorization"],
        "from_query": ["access_token", "token"],
        "header_first": true,
        "user_claims": ["aud", "uid", "username"]
      },
      "api": {
        "endpoint": "http://127.0.0.1:2546/v1/auth",
        "method": "HEAD"
      }
    }
  }
}
```

### Internal Mode

When `mode` set to `"internal"`. This module behaves as a "JWT Validator". Who

1. Extract the token from the header or query from the HTTP request.
2. Validate the token by using the `sign_key`.
3. If the token is invalid by any reason, auth **failed** with `401`. Otherwise, next.
4. Get user id by inspecting the claims defined by `user_claims`.
5. If no valid user id (non-empty string) found, auth **failed** with `401`. Otherwise, next.
6. Return the user id to Caddy's authentication handler, and the context value `{http.auth.user.id}` got set.

### API Mode

When `mode` set to `"api"`. This module behaves as a "Reverse Proxy" to the authentication API. Who

1. Not Implemented

## TODO

- [ ] Implement the "API" mode
- [ ] Create a `jwt` directive to support Caddyfile
- [ ] Add documentation under [Caddy Modules](https://caddyserver.com/docs/modules/) named `http.authentication.providers.jwt`
