package caddyjwt

import (
	"errors"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	caddy.RegisterModule(JWTAuth{})
}

// JWTAuth facilitates JWT (JSON Web Token) authentication.
type JWTAuth struct {
	// TODO
}

func (JWTAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.jwt",
		New: func() caddy.Module { return new(JWTAuth) },
	}
}

func (ja *JWTAuth) Provision(ctx caddy.Context) error {
	return errors.New("not implemented")
}

// Authenticate validates the JWT in the request and returns the user, if valid.
func (ja *JWTAuth) Authenticate(rw http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	// TODO
	return caddyauth.User{ID: "<userid>"}, true, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*JWTAuth)(nil)
	_ caddyauth.Authenticator = (*JWTAuth)(nil)
)
