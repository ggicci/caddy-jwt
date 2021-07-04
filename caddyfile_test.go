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
		sign_key "NFL5*0Bc#9U6E@tnmC&E7SUN6GwHfLmY"
		from_query access_token token _tok
		from_header X-Api-Key
		from_cookies user_session SESSID
		user_claims uid user_id login username
	}
	`),
	}
	expectedJA := &JWTAuth{
		SignKey:     "NFL5*0Bc#9U6E@tnmC&E7SUN6GwHfLmY",
		FromQuery:   []string{"access_token", "token", "_tok"},
		FromHeader:  []string{"X-Api-Key"},
		FromCookies: []string{"user_session", "SESSID"},
		UserClaims:  []string{"uid", "user_id", "login", "username"},
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
	// missing sign_key
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
