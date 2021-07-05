package caddyjwt

import (
	"encoding/base64"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("jwtauth", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile. Syntax:
//
//    jwtauth [<matcher>] {
//        sign_key <sign_key>
//        ...
//    }
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ja JWTAuth

	for h.Next() {
		for h.NextBlock(0) {
			opt := h.Val()
			switch opt {
			case "sign_key":
				var signKeyString string
				if !h.AllArgs(&signKeyString) {
					return nil, h.Errf("invalid sign_key")
				}
				// Decode key from base64 to binary.
				if key, err := base64.StdEncoding.DecodeString(signKeyString); err != nil {
					return nil, h.Errf("invalid sign_key: %v", err)
				} else {
					ja.SignKey = key
				}

			case "from_query":
				ja.FromQuery = h.RemainingArgs()

			case "from_header":
				ja.FromHeader = h.RemainingArgs()

			case "from_cookies":
				ja.FromCookies = h.RemainingArgs()

			case "user_claims":
				ja.UserClaims = h.RemainingArgs()

			case "header_first":
				return nil, h.Err("option header_first deprecated, the priority now defaults to from_query > from_header > from_cookies")

			default:
				return nil, h.Errf("unrecognized option: %s", opt)
			}
		}
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"jwt": caddyconfig.JSON(ja, nil),
		},
	}, nil
}
