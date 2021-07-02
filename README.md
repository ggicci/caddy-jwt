# caddy-jwt

A Caddy HTTP Module - who Facilitates **JWT Authentication**

This module fulfilled [`http.handlers.authentication`](https://caddyserver.com/docs/modules/http.handlers.authentication) middleware as a provider named `jwt`.

[Documentation](https://caddyserver.com/docs/modules/http.authentication.providers.jwt)

## Install

```bash
xcaddy --with github.com/ggicci/caddy-jwt
```

## Quick View

```bash
git clone https://github.com/ggicci/caddy-jwt.git
cd caddy-jwt

# Build a caddy with this module and run an example server at localhost.
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

**NOTE**: you can decode the `${TEST_TOKEN}` above at [jwt.io](https://jwt.io/) to get human readable payload as follows:

```json
{
  "exp": 1655892670,
  "jti": "82294a63-9660-4c62-a8a8-5a6265efcd4e",
  "uid": 3406327963516932,
  "username": "ggicci",
  "nsid": 3406330157137926
}
```

## Configurations

Sample configuration (find more under [example](./example)):

```Caddyfile
http://localhost:8080 {
	route * {
		jwtauth internal {
			sign_key NFL5*0Bc#9U6E@tnmC&E7SUN6GwHfLmY
			from_query access_token token
			from_header X-Api-Token
			header_first true
			user_claims aud uid user_id username login
		}
		respond 200 {
			body "User Authenticated with ID: {http.auth.user.id}"
		}
	}
}
```

### Internal Mode

When `mode` set to `"internal"`, this module will behave like a "JWT Validator". Who

1. Extract the token from the header or query from the HTTP request.
2. Validate the token by using the `sign_key`.
3. If the token is invalid by any reason, auth **failed** with `401`. Otherwise, next.
4. Get user id by inspecting the claims defined by `user_claims`.
5. If no valid user id (non-empty string) found, auth **failed** with `401`. Otherwise, next.
6. Return the user id to Caddy's authentication handler, and the context value `{http.auth.user.id}` got set.

### API Mode

When `mode` set to `"api"`, this module will behave like a "Reverse Proxy" with its upstream set to a specific API for authentication. Who

1. Not Implemented
