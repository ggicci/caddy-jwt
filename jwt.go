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
	// SignKey is the key used by the signing algorithm to verify the signature.
	SignKey string `json:"sign_key"`

	// FromQuery defines a list of names to get tokens from the query parameters
	// of an HTTP request.
	//
	// If multiple keys were given, all the corresponding query
	// values will be treated as candidate tokens. And we will verify each of
	// them until we got a valid one.
	//
	// Priority: from_query > from_header > from_cookies.
	FromQuery []string `json:"from_query"`

	// FromHeader works like FromQuery. But defines a list of names to get
	// tokens from the HTTP header.
	FromHeader []string `json:"from_header"`

	// FromCookie works like FromQuery. But defines a list of names to get tokens
	// from the HTTP cookies.
	FromCookies []string `json:"from_cookies"`

	// UserClaims defines a list of names to find the ID of the authenticated user.
	// By default, this config will be set to []string{"aud"}.
	// Where "aud" is a reserved name in RFC7519 indicating the audience of a token.
	// If multiple names given, we will try to get the value of each name from
	// the JWT payload and use the first non-empty one as the ID of the authenticated
	// user. If valid, the placeholder {http.auth.user.id} will be set to the ID.
	// For example, []string{"uid", "username"} will set "eva" as the final user ID
	// from JWT payload: { "username": "eva"  }.
	UserClaims []string `json:"user_claims"`

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

	candidates = append(candidates, getTokensFromQuery(r, ja.FromQuery)...)
	candidates = append(candidates, getTokensFromHeader(r, ja.FromHeader)...)
	candidates = append(candidates, getTokensFromCookies(r, ja.FromCookies)...)

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

func getTokensFromCookies(r *http.Request, names []string) []string {
	tokens := make([]string, 0)
	for _, key := range names {
		if ck, err := r.Cookie(key); err == nil && ck.Value != "" {
			tokens = append(tokens, ck.Value)
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
