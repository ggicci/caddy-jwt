package caddyjwt

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	caddy.RegisterModule(JWTAuth{})
}

const (
	ModeAPI      = "api"
	ModeInternal = "internal"
)

type User = caddyauth.User

// JWTAuth facilitates JWT (JSON Web Token) authentication.
type JWTAuth struct {
	Mode     string                     `json:"mode"`
	API      *JWTAuthAPIModeConfig      `json:"api,omitempty"`
	Internal *JWTAuthInternalModeConfig `json:"internal,omitempty"`
}

type JWTAuthAPIModeConfig struct {
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
}

type JWTAuthInternalModeConfig struct {
	// TODO
}

func (JWTAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.jwt",
		New: func() caddy.Module { return new(JWTAuth) },
	}
}

func (ja *JWTAuth) Provision(ctx caddy.Context) error {
	return fastFail(
		ja.validateMode,
		ja.validateApiModeConfig,
		ja.validateInternalModeConfig,
	)
}

// Authenticate validates the JWT in the request and returns the user, if valid.
func (ja *JWTAuth) Authenticate(rw http.ResponseWriter, r *http.Request) (User, bool, error) {
	// TODO(ggicci): implement api mode (reverse proxy).
	return User{}, false, errors.New("expired")
}

func (ja *JWTAuth) validateMode() error {
	if ja.Mode == "" {
		ja.Mode = ModeInternal
	}
	if ja.Mode == ModeAPI || ja.Mode == ModeInternal {
		return nil
	}
	return fmt.Errorf("unrecognized mode: %s", ja.Mode)
}

func (ja *JWTAuth) validateApiModeConfig() error {
	if ja.Mode != ModeAPI {
		return nil
	}
	if ja.API == nil {
		return errors.New("api config is required")
	}
	return nil
}

func (ja *JWTAuth) validateInternalModeConfig() error {
	if ja.Mode != ModeInternal {
		return nil
	}
	if ja.Internal == nil {
		return errors.New("internal config is required")
	}
	return nil
}

func fastFail(validators ...func() error) error {
	for _, validate := range validators {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*JWTAuth)(nil)
	_ caddyauth.Authenticator = (*JWTAuth)(nil)
)
