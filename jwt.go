package caddyjwt

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(JWTAuth{})
}

type User = caddyauth.User

const (
	ModeAPI      = "api"
	ModeInternal = "internal"
)

var (
	ErrUnrecognizedMode = errors.New("unrecognized mode")
)

// JWTAuth facilitates JWT (JSON Web Token) authentication.
type JWTAuth struct {
	Mode     string        `json:"mode"`
	API      *APIMode      `json:"api,omitempty"`
	Internal *InternalMode `json:"internal,omitempty"`

	logger *zap.Logger
}

func (JWTAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.jwt",
		New: func() caddy.Module { return new(JWTAuth) },
	}
}

func (ja *JWTAuth) Provision(ctx caddy.Context) error {
	ja.logger = ctx.Logger(ja)
	return nil
}

// Authenticate validates the JWT in the request and returns the user, if valid.
func (ja *JWTAuth) Authenticate(rw http.ResponseWriter, r *http.Request) (User, bool, error) {
	switch ja.Mode {
	case ModeAPI:
		ja.API.logger = ja.logger
		return ja.API.Authenticate(rw, r)
	case ModeInternal:
		ja.Internal.logger = ja.logger
		return ja.Internal.Authenticate(rw, r)
	}
	return User{}, false, ErrUnrecognizedMode
}

// Validate implements caddy.Validator interface.
func (ja *JWTAuth) Validate() error {
	return fastFail(
		ja.validateMode,
		ja.validateApiModeConfig,
		ja.validateInternalModeConfig,
	)
}

func (ja *JWTAuth) validateMode() error {
	if ja.Mode == "" {
		ja.Mode = ModeInternal
	}
	if ja.Mode == ModeAPI || ja.Mode == ModeInternal {
		return nil
	}
	return ErrUnrecognizedMode
}

func (ja *JWTAuth) validateApiModeConfig() error {
	if ja.Mode != ModeAPI {
		return nil
	}
	if ja.API == nil {
		return errors.New("api config is required")
	}
	if err := ja.API.validate(); err != nil {
		return fmt.Errorf("api: %w", err)
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
	if err := ja.Internal.validate(); err != nil {
		return fmt.Errorf("internal: %w", err)
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
	_ caddy.Validator         = (*JWTAuth)(nil)
	_ caddyauth.Authenticator = (*JWTAuth)(nil)
)
