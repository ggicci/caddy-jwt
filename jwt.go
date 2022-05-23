// caddyjwt is a Caddy Module - who facilitates JWT authentication.
package caddyjwt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	//
	// For symmetric algorithems, use the key directly. e.g.
	//
	//     "<secret_key_in_base64_format>".
	//
	// For asymmetric algorithems, use the public key in x509 PEM format. e.g.
	//
	//     -----BEGIN PUBLIC KEY-----
	//     ...
	//     -----END PUBLIC KEY-----
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

	// IssuerWhitelist defines a list of issuers. A non-empty list turns on "iss
	// verification": the "iss" claim must exist in the given JWT payload. And
	// the value of the "iss" claim must be on the whitelist in order to pass
	// the verification.
	IssuerWhitelist []string `json:"issuer_whitelist"`

	// AudienceWhitelist defines a list of audiences. A non-empty list turns on
	// "aud verification": the "aud" claim must exist in the given JWT payload.
	// The verification will pass as long as one of the "aud" values is on the
	// whitelist.
	AudienceWhitelist []string `json:"audience_whitelist"`

	// UserClaims defines a list of names to find the ID of the authenticated user.
	//
	// By default, this config will be set to []string{"username"}.
	//
	// If multiple names were given, we will use the first non-empty value of the key
	// in the JWT payload as the ID of the authenticated user. i.e. The placeholder
	// {http.auth.user.id} will be set to the ID.
	//
	// For example, []string{"uid", "username"} will set "eva" as the final user ID
	// from JWT payload: { "username": "eva"  }.
	//
	// If no non-empty values found, leaves it unauthenticated.
	UserClaims []string `json:"user_claims"`

	// MetaClaims defines a map to populate {http.auth.user.*} metadata placeholders.
	// The key is the claim in the JWT payload, the value is the placeholder name.
	// e.g. {"IsAdmin": "is_admin"} can populate {http.auth.user.is_admin} with
	// the value of `IsAdmin` in the JWT payload if found, otherwise "".
	//
	// NOTE: The name in the placeholder should be adhere to Caddy conventions
	// (snake_casing).
	//
	// Caddyfile:
	// Use syntax `<claim>[-> <placeholder>]` to define a map item. The placeholder is
	// optional, if not specified, use the same name as the claim.
	// e.g.
	//
	//     meta_claims "IsAdmin -> is_admin" "group"
	//
	// is equal to {"IsAdmin": "is_admin", "group": "group"}.
	//
	// Since v0.6.0, nested claim path is also supported, e.g.
	// For the following JWT payload:
	//
	//     { ..., "user_info": { "role": "admin" }}
	//
	// If you want to populate {http.auth.user.role} with "admin", you can use
	//
	//     meta_claims "user_info.role -> role"
	//
	// Use dot notation to access nested claims.
	MetaClaims map[string]string `json:"meta_claims"`

	logger        *zap.Logger
	parsedSignKey interface{} // can be []byte, *rsa.PublicKey, *ecdsa.PublicKey, etc.
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
	if keyBytes, asymmetric, err := parseSignKey(ja.SignKey); err != nil {
		// Key(step 1): base64 -> raw bytes.
		return fmt.Errorf("invalid sign_key: %w", err)
	} else {
		// Key(step 2): raw bytes -> parsed key.
		if !asymmetric {
			ja.parsedSignKey = keyBytes
		} else if ja.parsedSignKey, err = x509.ParsePKIXPublicKey(keyBytes); err != nil {
			return fmt.Errorf("invalid sign_key (asymmetric): %w", err)
		}
	}

	if len(ja.UserClaims) == 0 {
		ja.UserClaims = []string{
			"sub",
		}
	}
	for claim, placeholder := range ja.MetaClaims {
		if claim == "" || placeholder == "" {
			return fmt.Errorf("invalid meta claim: %s -> %s", claim, placeholder)
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
			return ja.parsedSignKey, nil
		})
		checked[tokenString] = struct{}{}

		logger := ja.logger.With(zap.String("token_string", desensitizedTokenString(tokenString)))
		if err != nil {
			logger.Error("invalid token", zap.Error(err))
			continue
		}

		var gotClaims = gotToken.Claims.(MapClaims)
		// By default, the following claims will be verified:
		//   - "exp"
		//   - "iat"
		//   - "nbf"
		// Here, if `aud_whitelist` or `iss_whitelist` were specified,
		// continue to verify "aud" and "iss" correspondingly.
		if len(ja.IssuerWhitelist) > 0 {
			isValidIssuer := false
			for _, issuer := range ja.IssuerWhitelist {
				if gotClaims.VerifyIssuer(issuer, true) {
					isValidIssuer = true
					break
				}
			}
			if !isValidIssuer {
				err = ErrInvalidIssuer
				logger.Error("invalid token", zap.Error(err))
				continue
			}
		}

		if len(ja.AudienceWhitelist) > 0 {
			isValidAudience := false
			for _, audience := range ja.AudienceWhitelist {
				if gotClaims.VerifyAudience(audience, true) {
					isValidAudience = true
					break
				}
			}
			if !isValidAudience {
				err = ErrInvalidAudience
				logger.Error("invalid token", zap.Error(err))
				continue
			}
		}

		// The token is valid. Continue to check the user claim.
		claimName, gotUserID := getUserID(gotClaims, ja.UserClaims)
		if gotUserID == "" {
			err = ErrEmptyUserClaim
			logger.Error("invalid token", zap.Strings("user_claims", ja.UserClaims), zap.Error(err))
			continue
		}

		// Successfully authenticated!
		var user = User{
			ID:       gotUserID,
			Metadata: getUserMetadata(gotClaims, ja.MetaClaims),
		}
		logger.Info("user authenticated", zap.String("user_claim", claimName), zap.String("id", gotUserID))
		return user, true, nil
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

func queryNested(claims MapClaims, path []string) (interface{}, bool) {
	var (
		object map[string]interface{} = (map[string]interface{})(claims)
		ok     bool
	)
	for i := 0; i < len(path)-1; i++ {
		if object, ok = object[path[i]].(map[string]interface{}); !ok || object == nil {
			return nil, false
		}
	}

	lastKey := path[len(path)-1]
	return object[lastKey], true
}

func getUserMetadata(claims MapClaims, placeholdersMap map[string]string) map[string]string {
	if len(placeholdersMap) == 0 {
		return nil
	}

	metadata := make(map[string]string)
	for claim, placeholder := range placeholdersMap {
		claimValue, ok := claims[claim]

		// Query nested claims.
		if !ok && strings.Contains(claim, ".") {
			claimValue, ok = queryNested(claims, strings.Split(claim, "."))
		}
		if !ok {
			metadata[placeholder] = ""
			continue
		}
		metadata[placeholder] = stringify(claimValue)
	}

	return metadata
}

func stringify(val interface{}) string {
	if val == nil {
		return ""
	}

	switch uv := val.(type) {
	case string:
		return uv
	case bool:
		return strconv.FormatBool(uv)
	case json.Number:
		return uv.String()
	case time.Time:
		return uv.UTC().Format(time.RFC3339Nano)
	}

	if stringer, ok := val.(fmt.Stringer); ok {
		return stringer.String()
	}

	return ""
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

// parseSignKey parses the given key and returns the key bytes.
func parseSignKey(signKey string) (keyBytes []byte, asymmetric bool, err error) {
	if len(signKey) == 0 {
		return nil, false, ErrMissingSignKey
	}
	if strings.Contains(signKey, "-----BEGIN PUBLIC KEY-----") {
		keyBytes, err = parsePEMFormattedPublicKey(signKey)
		return keyBytes, true, err
	}
	keyBytes, err = base64.StdEncoding.DecodeString(signKey)
	return keyBytes, false, err
}

func parsePEMFormattedPublicKey(pubKey string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pubKey))
	if block != nil && block.Type == "PUBLIC KEY" {
		return block.Bytes, nil
	}

	return nil, ErrInvalidPublicKey
}

// Interface guards
var (
	_ caddy.Provisioner       = (*JWTAuth)(nil)
	_ caddy.Validator         = (*JWTAuth)(nil)
	_ caddyauth.Authenticator = (*JWTAuth)(nil)
)
