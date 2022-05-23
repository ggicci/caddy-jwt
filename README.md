# caddy-jwt

![Go Workflow](https://github.com/ggicci/caddy-jwt/actions/workflows/go.yml/badge.svg) [![codecov](https://codecov.io/gh/ggicci/caddy-jwt/branch/main/graph/badge.svg?token=4V9OX8WFAW)](https://codecov.io/gh/ggicci/caddy-jwt) [![Go Report Card](https://goreportcard.com/badge/github.com/ggicci/caddy-jwt)](https://goreportcard.com/report/github.com/ggicci/caddy-jwt) [![Go Reference](https://pkg.go.dev/badge/github.com/ggicci/caddy-jwt.svg)](https://pkg.go.dev/github.com/ggicci/caddy-jwt)

A Caddy HTTP Module - who Facilitates **JWT Authentication**

This module fulfilled [`http.handlers.authentication`](https://caddyserver.com/docs/modules/http.handlers.authentication) middleware as a provider named `jwt`.

[Documentation](https://caddyserver.com/docs/modules/http.authentication.providers.jwt)

## Install

Build this module with `caddy` at Caddy's official [download](https://caddyserver.com/download) site. Or:

```bash
xcaddy --with github.com/ggicci/caddy-jwt
```

## Sample Caddyfile

```Caddyfile
api.example.com {
	route * {
		jwtauth {
			sign_key TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk=
			from_query access_token token
			from_header X-Api-Token
			from_cookies user_session
			issuer_whitelist https://api.example.com
			audience_whitelist https://api.example.io https://learn.example.com
			user_claims aud uid user_id username login
			meta_claims "IsAdmin->is_admin" "settings.payout.paypal.enabled->is_paypal_enabled"
		}
		reverse_proxy http://172.16.0.14:8080
	}
}
```

**NOTE**:

1. If you were using **symmetric** signing algorithms, e.g. `HS256`, encode your key bytes in `base64` format as `sign_key`'s value.

```text
TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk=
```

2. If you were using **asymmetric** signing algorithms, e.g. `RS256`, encode your public key in x.509 PEM format as `sign_key`'s value.

```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArzekF0pqttKNJMOiZeyt
RdYiabdyy/sdGQYWYJPGD2Q+QDU9ZqprDmKgFOTxUy/VUBnaYr7hOEMBe7I6dyaS
5G0EGr8UXAwgD5Uvhmz6gqvKTV+FyQfw0bupbcM4CdMD7wQ9uOxDdMYm7g7gdGd6
SSIVvmsGDibBI9S7nKlbcbmciCmxbAlwegTYSHHLjwWvDs2aAF8fxeRfphwQZKkd
HekSZ090/c2V4i0ju2M814QyGERMoq+cSlmikCgRWoSZeWOSTj+rAZJyEAzlVL4z
8ojzOpjmxw6pRYsS0vYIGEDuyiptf+ODC8smTbma/p3Vz+vzyLWPfReQY2RHtpUe
hwIDAQAB
-----END PUBLIC KEY-----
```

3. The priority of `from_xxx` is `from_query > from_header > from_cookies`.

## Test it by yourself

```bash
git clone https://github.com/ggicci/caddy-jwt.git
cd caddy-jwt

# Build a caddy with this module and run an example server at localhost.
make example

TEST_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5NTU4OTI2NzAsImp0aSI6IjgyMjk0YTYzLTk2NjAtNGM2Mi1hOGE4LTVhNjI2NWVmY2Q0ZSIsInN1YiI6IjM0MDYzMjc5NjM1MTY5MzIiLCJpc3MiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsImF1ZCI6WyJodHRwczovL2FwaS5leGFtcGxlLmlvIl0sInVzZXJuYW1lIjoiZ2dpY2NpIn0.O8kvRO9y6xQO3AymqdFE7DDqLRBQhkntf78O9kF71F8

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
  "exp": 9955892670,
  "jti": "82294a63-9660-4c62-a8a8-5a6265efcd4e",
  "sub": "3406327963516932",
  "iss": "https://api.example.com",
  "aud": ["https://api.example.io"],
  "username": "ggicci"
}
```

## How it works?

Module **caddy-jwt** behaves like a **"JWT Validator"**. The authentication flow is:

```text
   ┌──────────────────┐
   │Extract token from│
   │  1. query        │
   │  2. header       │
   │  3. cookies      │
   └────────┬─────────┘
            │
    ┌───────▼────────┐
    │   is valid?    │
    │using `sign_key`├────NO───────┐
    └───────┬────────┘             │
            │YES                   │
┌───────────▼───────────┐          │
│Populate {http.user.id}│          │
│  by `user_claims`     │          │
└───────────┬───────────┘          │
            │                      │
 ┌──────────▼───────────┐          │
 │is {http.user.id} set?├──NO(empty)
 └──────────┬───────────┘       │  │
            │YES(non-empty)     │  │
 ┌──────────▼───────────┐       │  │
 │Populate {http.user.*}│       │  │
 │   by `meta_claims`   │       │  │
 └──────────┬───────────┘       │  │
            │                   │  │
   ┌────────▼──────────┐ ┌──────▼──▼─────┐
   │   Authenticated   │ │Unauthenticated│
   │ Continue to Caddy │ │      401      │
   └───────────────────┘ └───────────────┘
```

flowchart by https://asciiflow.com/

## References

- **MUST READ**: [JWT Security Best Practices](https://curity.io/resources/learn/jwt-best-practices/)
- Online Debuger: http://jwt.io/
