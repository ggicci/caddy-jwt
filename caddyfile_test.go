package caddyjwt

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/stretchr/testify/assert"
)

func TestParsingCaddyfileNormalCase(t *testing.T) {
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		sign_key "TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk="
		sign_alg HS256
		from_query access_token token _tok
		from_header X-Api-Key
		from_cookies user_session SESSID
		issuer_whitelist https://api.example.com
		audience_whitelist https://api.example.io https://learn.example.com
		user_claims uid user_id login username
		meta_claims "IsAdmin -> is_admin" "gender"
	}
	`),
	}
	expectedJA := &JWTAuth{
		SignKey:           TestSignKey,
		SignAlgorithm:     "HS256",
		FromQuery:         []string{"access_token", "token", "_tok"},
		FromHeader:        []string{"X-Api-Key"},
		FromCookies:       []string{"user_session", "SESSID"},
		IssuerWhitelist:   []string{"https://api.example.com"},
		AudienceWhitelist: []string{"https://api.example.io", "https://learn.example.com"},
		UserClaims:        []string{"uid", "user_id", "login", "username"},
		MetaClaims:        map[string]string{"IsAdmin": "is_admin", "gender": "gender"},
	}

	h, err := parseCaddyfile(helper)
	assert.Nil(t, err)
	auth, ok := h.(caddyauth.Authentication)
	assert.True(t, ok)
	jsonConfig, ok := auth.ProvidersRaw["jwt"]
	assert.True(t, ok)
	assert.Equal(t, caddyconfig.JSON(expectedJA, nil), jsonConfig)
}

func TestParsingCaddyfileError(t *testing.T) {
	// invalid sign_key: missing
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		sign_key
	}
	`),
	}

	_, err := parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "sign_key")

	// invalid sign_alg: missing
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		sign_alg
	}`),
	}

	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "sign_alg")

	// invalid jwk_url: missing
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		jwk_url
	}`),
	}

	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "jwk_url")

	// invalid sign_key: base64
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		sign_key TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk=
	}
	`),
	}

	_, err = parseCaddyfile(helper)
	assert.Nil(t, err)

	// header_first is deprecated
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		header_first true
	}
	`),
	}
	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "deprecated")

	// invalid meta_claims: parse error
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		meta_claims IsAdmin->is_admin->
	}
	`),
	}
	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "meta_claims")

	// invalid meta_claims: duplicate
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		meta_claims IsAdmin->is_admin Gender->gender IsAdmin->admin
	}
	`),
	}
	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "meta_claims")

	// unrecognized option
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		upstream http://192.168.1.4
	}
	`),
	}
	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unrecognized")
}

func TestParseMetaClaim(t *testing.T) {
	var testCases = []struct {
		Key         string
		Claim       string
		Placeholder string
		Pass        bool
	}{
		{"username", "username", "username", true},
		{"registerYear->register_year", "registerYear", "register_year", true},
		{"IsAdmin -> is_admin", "IsAdmin", "is_admin", true},
		{"Gender", "Gender", "Gender", true},
		{"->slot", "", "", false},
		{"IsMember->", "", "", false},
		{"Favorite -> favorite->fav", "", "", false},
	}

	for _, c := range testCases {
		claim, placeholder, err := parseMetaClaim(c.Key)
		assert.Equal(t, claim, c.Claim)
		assert.Equal(t, placeholder, c.Placeholder)
		if c.Pass == true {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Contains(t, err.Error(), c.Key)
		}
	}
}

func TestParsingCaddyfileWithSkipVerification(t *testing.T) {
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		skip_verification
		from_query access_token token _tok
		from_header X-Api-Key
		from_cookies user_session SESSID
		issuer_whitelist https://api.example.com
		audience_whitelist https://api.example.io https://learn.example.com
		user_claims uid user_id login username
		meta_claims "IsAdmin -> is_admin" "gender"
	}
	`),
	}
	expectedJA := &JWTAuth{
		SkipVerification:  true,
		FromQuery:         []string{"access_token", "token", "_tok"},
		FromHeader:        []string{"X-Api-Key"},
		FromCookies:       []string{"user_session", "SESSID"},
		IssuerWhitelist:   []string{"https://api.example.com"},
		AudienceWhitelist: []string{"https://api.example.io", "https://learn.example.com"},
		UserClaims:        []string{"uid", "user_id", "login", "username"},
		MetaClaims:        map[string]string{"IsAdmin": "is_admin", "gender": "gender"},
	}

	h, err := parseCaddyfile(helper)
	assert.Nil(t, err)
	auth, ok := h.(caddyauth.Authentication)
	assert.True(t, ok)
	jsonConfig, ok := auth.ProvidersRaw["jwt"]
	assert.True(t, ok)
	assert.Equal(t, caddyconfig.JSON(expectedJA, nil), jsonConfig)
}

func TestParsingCaddyFileClockSkew(t *testing.T) {
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		jwk_url https://example.com/.well-known/jwks.json
		clock_skew 60
		user_claims preferred_username
	}
	`),
	}
	expectedJA := &JWTAuth{
		JWKURL:     "https://example.com/.well-known/jwks.json",
		ClockSkew:  60,
		UserClaims: []string{"preferred_username"},
	}

	h, err := parseCaddyfile(helper)
	assert.Nil(t, err)
	auth, ok := h.(caddyauth.Authentication)
	assert.True(t, ok)
	jsonConfig, ok := auth.ProvidersRaw["jwt"]
	assert.True(t, ok)
	assert.Equal(t, caddyconfig.JSON(expectedJA, nil), jsonConfig)
}

func TestParsingCaddyFileErrorClockSkew(t *testing.T) {
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		clock_skew -60
	}
	`),
	}

	_, err := parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "clock_skew")

	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		clock_skew
	}
	`),
	}

	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "clock_skew")

	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		clock_skew abc
	}
	`),
	}

	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "clock_skew")
}

func TestParsingCaddyFileLogLevel(t *testing.T) {
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		sign_key "TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk="
		log_level debug
	}
	`),
	}
	expectedJA := &JWTAuth{
		SignKey:  TestSignKey,
		LogLevel: "debug",
	}

	h, err := parseCaddyfile(helper)
	assert.Nil(t, err)
	auth, ok := h.(caddyauth.Authentication)
	assert.True(t, ok)
	jsonConfig, ok := auth.ProvidersRaw["jwt"]
	assert.True(t, ok)
	assert.Equal(t, caddyconfig.JSON(expectedJA, nil), jsonConfig)
}

func TestParsingCaddyFileErrorLogLevel(t *testing.T) {
	// invalid log_level: missing
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		log_level
	}
	`),
	}

	_, err := parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "log_level")

	// invalid log_level: not a recognized zap level
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		log_level verbose
	}
	`),
	}

	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "log_level")

	// invalid log_level: disallowed zap level (would crash the process)
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		log_level fatal
	}
	`),
	}

	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "log_level")
}
