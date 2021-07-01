package caddyjwt

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
)

// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1

type Token = jwt.Token
type MapClaims = jwt.MapClaims

type InternalMode struct {
	SignKey     string   `json:"sign_key"`
	FromHeader  []string `json:"from_header"`
	FromQuery   []string `json:"from_query"`
	HeaderFirst bool     `json:"header_first"`
	UserClaims  []string `json:"user_claims"`

	logger *zap.Logger
}

func (m *InternalMode) validate() error {
	if m.SignKey == "" {
		return errors.New("sign_key is required")
	}
	if len(m.UserClaims) == 0 {
		m.UserClaims = []string{
			"aud", // reserved claim name: "aud", the audience
		}
	}
	return nil
}

func (m *InternalMode) Authenticate(rw http.ResponseWriter, r *http.Request) (User, bool, error) {
	var candidates []string

	if m.HeaderFirst {
		candidates = append(candidates, getTokensFromHeader(r, m.FromHeader)...)
		candidates = append(candidates, getTokensFromQuery(r, m.FromQuery)...)
	} else {
		candidates = append(candidates, getTokensFromQuery(r, m.FromQuery)...)
		candidates = append(candidates, getTokensFromHeader(r, m.FromHeader)...)
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

		gotToken, err := parser.Parse(tokenString, func(*Token) (interface{}, error) {
			return []byte(m.SignKey), nil
		})
		checked[tokenString] = struct{}{}

		logger := m.logger.With(zap.String("token_string", desensitizedTokenString(tokenString)))
		if err != nil || !gotToken.Valid {
			logger.Error("invalid token", zap.NamedError("error", err))
			continue
		}

		// The token is valid. Continue to check the user claim.
		claimName, gotUserID := getUserID(gotToken.Claims.(MapClaims), m.UserClaims)
		if gotUserID == "" {
			logger.Error("invalid user claim", zap.Strings("user_claims", m.UserClaims))
			continue
		}

		// Successfully authenticated!
		logger.Info("user authenticated", zap.String("user_claim", claimName), zap.String("id_value", gotUserID))
		return User{ID: gotUserID}, true, nil
	}

	return User{}, false, nil
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
	return token[:16] + "…" + token[len(token)-16:]
}
