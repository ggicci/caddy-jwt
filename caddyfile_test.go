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
		header_first true
		user_claims uid user_id login username
	}
	`),
	}
	expectedJA := &JWTAuth{
		SignKey:     "NFL5*0Bc#9U6E@tnmC&E7SUN6GwHfLmY",
		FromQuery:   []string{"access_token", "token", "_tok"},
		FromHeader:  []string{"X-Api-Key"},
		HeaderFirst: true,
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

	// header_first requires exactly 1 arg
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		header_first true false
	}
	`),
	}

	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "header_first")

	// header_first pasre boolean failed
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwtauth {
		header_first "not_sure"
	}
	`),
	}
	_, err = parseCaddyfile(helper)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "header_first")

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
