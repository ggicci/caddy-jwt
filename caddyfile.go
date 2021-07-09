package caddyjwt

import (
	"encoding/base64"
	"fmt"
	"strings"

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

			case "meta_claims":
				ja.MetaClaims = make(map[string]string)
				for _, metaClaim := range h.RemainingArgs() {
					claim, placeholder, err := parseMetaClaim(metaClaim)
					if err != nil {
						return nil, h.Errf("invalid meta_claims: %v", err)
					}
					if _, ok := ja.MetaClaims[claim]; ok {
						return nil, h.Errf("invalid meta_claims: duplicate claim: %s", claim)
					}
					ja.MetaClaims[claim] = placeholder
				}
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

// parseMetaClaim parses key to get the claim and corresponding placeholder.
// e.g "IsAdmin -> is_admin" as { Claim: "IsAdmin", Placeholder: "is_admin" }.
func parseMetaClaim(key string) (claim, placeholder string, err error) {
	parts := strings.Split(key, "->")
	if len(parts) == 1 {
		claim = strings.TrimSpace(parts[0])
		placeholder = strings.TrimSpace(parts[0])
	} else if len(parts) == 2 {
		claim = strings.TrimSpace(parts[0])
		placeholder = strings.TrimSpace(parts[1])
	} else {
		return "", "", fmt.Errorf("too many delimiters (->) in key %q", key)
	}

	if claim == "" {
		return "", "", fmt.Errorf("empty claim in key %q", key)
	}
	if placeholder == "" {
		return "", "", fmt.Errorf("empty placeholder in key %q", key)
	}
	return
}
