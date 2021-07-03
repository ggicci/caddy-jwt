package caddyjwt

import (
	"strconv"

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
				if !h.AllArgs(&ja.SignKey) {
					return nil, h.Errf("invalid sign_key")
				}
			case "from_query":
				ja.FromQuery = h.RemainingArgs()
			case "from_header":
				ja.FromHeader = h.RemainingArgs()
			case "header_first":
				var headerFirst string
				var err error
				if !h.AllArgs(&headerFirst) {
					return nil, h.Errf("invalid header_first")
				}
				if ja.HeaderFirst, err = strconv.ParseBool(headerFirst); err != nil {
					return nil, h.Errf("invalid header_first")
				}
			case "user_claims":
				ja.UserClaims = h.RemainingArgs()
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
