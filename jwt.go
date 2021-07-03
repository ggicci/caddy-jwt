package caddyjwt

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(JWTAuth{})
}

type User = caddyauth.User
type Token = jwt.Token
type MapClaims = jwt.MapClaims

// JWTAuth facilitates JWT (JSON Web Token) authentication.
type JWTAuth struct {
	SignKey     string   `json:"sign_key"`
	FromHeader  []string `json:"from_header"`
	FromQuery   []string `json:"from_query"`
	HeaderFirst bool     `json:"header_first"`
	UserClaims  []string `json:"user_claims"`

	logger *zap.Logger
}

// CaddyModule implements caddy.Module interface.
func (JWTAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.jwt",
		New: func() caddy.Module { return new(JWTAuth) },
	}
}

// Provision implements caddy.Provisioner interface.
func (ja *JWTAuth) Provision(ctx caddy.Context) error {
	ja.logger = ctx.Logger(ja)
	return nil
}

// Validate implements caddy.Validator interface.
func (ja *JWTAuth) Validate() error {
	if ja.SignKey == "" {
		return errors.New("sign_key is required")
	}
	if len(ja.UserClaims) == 0 {
		ja.UserClaims = []string{
			// "aud" (the audience) is a reserved claim name
			// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
			"aud",
		}
	}
	return nil
}

// Authenticate validates the JWT in the request and returns the user, if valid.
func (ja *JWTAuth) Authenticate(rw http.ResponseWriter, r *http.Request) (User, bool, error) {
	var (
		candidates []string
		gotToken   *Token
		err        error
	)

	if ja.HeaderFirst {
		candidates = append(candidates, getTokensFromHeader(r, ja.FromHeader)...)
		candidates = append(candidates, getTokensFromQuery(r, ja.FromQuery)...)
	} else {
		candidates = append(candidates, getTokensFromQuery(r, ja.FromQuery)...)
		candidates = append(candidates, getTokensFromHeader(r, ja.FromHeader)...)
	}
	candidates = append(candidates, getTokensFromHeader(r, []string{"Authorization"})...)
	checked := make(map[string]struct{})
	parser := &jwt.Parser{
		UseJSONNumber: true, // parse number in JSON object to json.Number instead of float64
	}

	for _, candidateToken := range candidates {
		tokenString := normToken(candidateToken)
		if _, ok := checked[tokenString]; ok {
			continue
		}

		gotToken, err = parser.Parse(tokenString, func(*Token) (interface{}, error) {
			return []byte(ja.SignKey), nil
		})
		checked[tokenString] = struct{}{}

		logger := ja.logger.With(zap.String("token_string", desensitizedTokenString(tokenString)))
		if err != nil {
			logger.Error("invalid token", zap.NamedError("error", err))
			continue
		}

		// The token is valid. Continue to check the user claim.
		claimName, gotUserID := getUserID(gotToken.Claims.(MapClaims), ja.UserClaims)
		if gotUserID == "" {
			err = errors.New("empty user claim")
			logger.Error("invalid token", zap.Strings("user_claims", ja.UserClaims), zap.NamedError("error", err))
			continue
		}

		// Successfully authenticated!
		logger.Info("user authenticated", zap.String("user_claim", claimName), zap.String("id_value", gotUserID))
		return User{ID: gotUserID}, true, nil
	}

	return User{}, false, err
}

func normToken(token string) string {
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = token[len("bearer "):]
	}
	return strings.TrimSpace(token)
}

func getTokensFromHeader(r *http.Request, names []string) []string {
	tokens := make([]string, 0)
	for _, key := range names {
		token := r.Header.Get(key)
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func getTokensFromQuery(r *http.Request, names []string) []string {
	tokens := make([]string, 0)
	for _, key := range names {
		token := r.FormValue(key)
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func getUserID(claims MapClaims, names []string) (string, string) {
	for _, name := range names {
		if userClaim, ok := claims[name]; ok {
			switch val := userClaim.(type) {
			case string:
				return name, val
			case json.Number:
				return name, val.String()
			}
		}
	}
	return "", ""
}

func desensitizedTokenString(token string) string {
	if len(token) <= 6 {
		return token
	}
	mask := len(token) / 3
	if mask > 16 {
		mask = 16
	}
	return token[:mask] + "…" + token[len(token)-mask:]
}

// Interface guards
var (
	_ caddy.Provisioner       = (*JWTAuth)(nil)
	_ caddy.Validator         = (*JWTAuth)(nil)
	_ caddyauth.Authenticator = (*JWTAuth)(nil)
)
