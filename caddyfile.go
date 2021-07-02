package caddyjwt

import (
	"errors"
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
//    jwtauth [<matcher>] [<mode>] {
//        sign_key <sign_key>
//        ...
//    }
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ja JWTAuth

	for h.Next() {
		args := h.RemainingArgs()
		switch len(args) {
		case 0:
			ja.Mode = ModeInternal // default mode: "internal"
		case 1:
			ja.Mode = args[0]
		default:
			return nil, h.ArgErr()
		}

		switch ja.Mode {
		case ModeInternal:
			ja.Internal = &InternalMode{}
			if err := configInternalMode(h, ja.Internal); err != nil {
				return nil, err
			}
		case ModeAPI:
			ja.API = &APIMode{}
			if err := configApiMode(h, ja.API); err != nil {
				return nil, err
			}
		default:
			return nil, h.Errf("unrecognized mode: %s", ja.Mode)
		}
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"jwt": caddyconfig.JSON(ja, nil),
		},
	}, nil
}

func configInternalMode(h httpcaddyfile.Helper, m *InternalMode) error {
	for h.NextBlock(0) {
		opt := h.Val()
		switch opt {
		case "sign_key":
			if !h.AllArgs(&m.SignKey) {
				return h.Errf("invalid sign_key")
			}
		case "from_query":
			m.FromQuery = h.RemainingArgs()
		case "from_header":
			m.FromHeader = h.RemainingArgs()
		case "header_first":
			var headerFirst string
			var err error
			if !h.AllArgs(&headerFirst) {
				return h.Errf("invalid header_first")
			}
			if m.HeaderFirst, err = strconv.ParseBool(headerFirst); err != nil {
				return h.Errf("invalid header_first value")
			}
		case "user_claims":
			m.UserClaims = h.RemainingArgs()
		default:
			return h.Errf("unrecognized option: %s", opt)

		}
	}
	return nil
}

func configApiMode(ht httpcaddyfile.Helper, m *APIMode) error {
	return errors.New("not implemented")
}
