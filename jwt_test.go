package caddyjwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type MapClaims map[string]interface{}

var (
	testLogger, _ = zap.NewDevelopment()

	// Symmetric
	RawTestSignKey = []byte("NFL5*0Bc#9U6E@tnmC&E7SUN6GwHfLmY")
	TestSignKey    = base64.StdEncoding.EncodeToString(RawTestSignKey)

	// Asymmetric
	TestPubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArzekF0pqttKNJMOiZeyt
RdYiabdyy/sdGQYWYJPGD2Q+QDU9ZqprDmKgFOTxUy/VUBnaYr7hOEMBe7I6dyaS
5G0EGr8UXAwgD5Uvhmz6gqvKTV+FyQfw0bupbcM4CdMD7wQ9uOxDdMYm7g7gdGd6
SSIVvmsGDibBI9S7nKlbcbmciCmxbAlwegTYSHHLjwWvDs2aAF8fxeRfphwQZKkd
HekSZ090/c2V4i0ju2M814QyGERMoq+cSlmikCgRWoSZeWOSTj+rAZJyEAzlVL4z
8ojzOpjmxw6pRYsS0vYIGEDuyiptf+ODC8smTbma/p3Vz+vzyLWPfReQY2RHtpUe
hwIDAQAB
-----END PUBLIC KEY-----`

	// JWK URL
	TestJWKURL                = "http://127.0.0.1:2546/key"
	TestJWKSetURL             = "http://127.0.0.1:2546/keys"
	TestJWKSetURLInapplicable = "http://127.0.0.1:2546/keys_inapplicable"

	jwkKey                   jwk.Key // private key
	jwkPubKey                jwk.Key // public key
	jwkPubKeySet             jwk.Set // public key set
	jwkPubKeySetInapplicable jwk.Set // public key set (inapplicable)

	// EdDSA test
	jwkKeyEd25519      jwk.Key // private key for EdDSA test
	TestSignKeyEd25519 string  // base64 encoded public key
)

func init() {
	var err error
	jwkKey = generateJWK()

	jwkPubKey, err = jwkKey.PublicKey()
	panicOnError(err)

	anotherPubKeyI, err := generateJWK().PublicKey()
	panicOnError(err)
	anotherPubKeyII, err := generateJWK().PublicKey()
	panicOnError(err)

	jwkKeyEd25519 = generateEdDSAJWK()

	jwkPubKeySet = jwk.NewSet()
	jwkPubKeySet.AddKey(anotherPubKeyI)
	jwkPubKeySet.AddKey(jwkPubKey)

	jwkPubKeySetInapplicable = jwk.NewSet()
	jwkPubKeySetInapplicable.AddKey(anotherPubKeyI)
	jwkPubKeySetInapplicable.AddKey(anotherPubKeyII)

	publishJWKsOnLocalServer()
}

func generateJWK() jwk.Key {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	panicOnError(err)
	key, err := jwk.Import(privateKey)
	panicOnError(err)
	jwk.AssignKeyID(key)                       // set "kid"
	key.Set(jwk.AlgorithmKey, jwa.RS256())     // set "alg"
	key.Set(jwk.KeyUsageKey, jwk.ForSignature) // set "use"
	return key
}

func generateEdDSAJWK() jwk.Key {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	panicOnError(err)
	TestSignKeyEd25519 = base64.StdEncoding.EncodeToString(publicKey)
	key, err := jwk.Import(privateKey)
	panicOnError(err)
	jwk.AssignKeyID(key)
	key.Set(jwk.AlgorithmKey, jwa.EdDSA())
	key.Set(jwk.KeyUsageKey, jwk.ForSignature)
	return key
}

func publishJWKsOnLocalServer() {
	go func() {
		http.HandleFunc("/key", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(jwkPubKey)
		})
		http.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(jwkPubKeySet)
		})
		http.HandleFunc("/keys_inapplicable", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(jwkPubKeySetInapplicable)
		})
		panicOnError(http.ListenAndServe("127.0.0.1:2546", nil))
	}()
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func buildToken(claims MapClaims) jwt.Token {
	tb := jwt.NewBuilder()
	for k, v := range claims {
		tb = tb.Claim(k, v)
	}
	token, err := tb.Build()
	panicOnError(err)
	return token
}

// issueTokenString issues a token string with the given claims,
// using HS256 signing algorithm.
func issueTokenString(claims MapClaims) string {
	token := buildToken(claims)
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), RawTestSignKey))
	panicOnError(err)

	return string(tokenBytes)
}

// issueTokenString issues a token string with the given claims,
// using EdDSA signing algorithm.
func issueTokenStringEdDSA(claims MapClaims) string {
	token := buildToken(claims)
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), jwkKeyEd25519))
	panicOnError(err)

	return string(tokenBytes)
}

func issueTokenStringJWK(claims MapClaims, options ...func(*jwt.SignOption)) string {
	token := buildToken(claims)

	// Options par défaut
	signOptions := []jwt.SignOption{jwt.WithKey(jwa.RS256(), jwkKey)}

	// Appliquer les options supplémentaires
	for _, opt := range options {
		var option jwt.SignOption
		opt(&option)
		signOptions = append(signOptions, option)
	}

	tokenBytes, err := jwt.Sign(token, signOptions...)
	panicOnError(err)

	return string(tokenBytes)
}

func TestValidate_SignKey(t *testing.T) {
	// missing sign_key
	ja := &JWTAuth{}
	err := ja.Validate()
	assert.NotNil(t, err)
	assert.ErrorIs(t, err, ErrMissingKeys)

	// having sign_key
	ja = &JWTAuth{
		SignKey: TestSignKey,
	}
	assert.Nil(t, ja.Validate())
}

func TestValidate_SignAlg(t *testing.T) {
	// invalid sign_alg
	ja := &JWTAuth{
		SignKey:       TestSignKey,
		SignAlgorithm: "ABC",
	}
	assert.ErrorIs(t, ja.Validate(), ErrInvalidSignAlgorithm)
}

func TestValidate_usingJWK(t *testing.T) {
	ja := &JWTAuth{JWKURL: TestJWKSetURL, logger: testLogger}
	assert.True(t, ja.usingJWK())
	err := ja.Validate()
	assert.Nil(t, err)
}

// TestValidate_SkipVerification checks that validation does not fail when
// SkipVerification is enabled and no keys are provided. This ensures that
// enabling SkipVerification bypasses signature and keys validation without errors.
func TestValidate_SkipVerification(t *testing.T) {
	// skipping verification
	ja := &JWTAuth{
		SkipVerification: true,
	}
	assert.NoError(t, ja.Validate())
}

func TestValidate_LogLevel(t *testing.T) {
	// unset log_level defaults to info
	ja := &JWTAuth{SignKey: TestSignKey}
	assert.Nil(t, ja.Validate())
	assert.Equal(t, zapcore.InfoLevel, ja.logLevel)

	// valid log_level values
	for levelStr, level := range map[string]zapcore.Level{
		"debug": zapcore.DebugLevel,
		"info":  zapcore.InfoLevel,
		"warn":  zapcore.WarnLevel,
		"error": zapcore.ErrorLevel,
		"DEBUG": zapcore.DebugLevel,
	} {
		ja = &JWTAuth{SignKey: TestSignKey, LogLevel: levelStr}
		assert.Nil(t, ja.Validate(), "log_level=%s", levelStr)
		assert.Equal(t, level, ja.logLevel, "log_level=%s", levelStr)
	}

	// invalid log_level: not a recognized zap level
	ja = &JWTAuth{SignKey: TestSignKey, LogLevel: "verbose"}
	assert.Contains(t, ja.Validate().Error(), "log_level")

	// invalid log_level: disallowed zap level, would crash/exit the process
	// on every successfully authenticated request
	for _, levelStr := range []string{"dpanic", "panic", "fatal"} {
		ja = &JWTAuth{SignKey: TestSignKey, LogLevel: levelStr}
		assert.Contains(t, ja.Validate().Error(), "log_level", "log_level=%s", levelStr)
	}
}

func TestAuthenticate_ClockSkew_Exp(t *testing.T) {
	claims := MapClaims{"sub": "dfeden",
		"exp": time.Now().Add(-5 * time.Second).Unix(), // expired 5 Seconds ago
	}
	ja := &JWTAuth{
		SignKey:   TestSignKey,
		logger:    testLogger,
		ClockSkew: 10, // allow 10 seconds of clock skew
	}
	assert.Nil(t, ja.Validate())

	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+issueTokenString(claims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, "dfeden", gotUser.ID)
}

func TestAuthenticate_ClockSkew_Iat(t *testing.T) {
	claims := MapClaims{"sub": "dfeden",
		"iat": time.Now().Add(5 * time.Second).Unix(), // issued 5 Seconds in the future
	}
	ja := &JWTAuth{
		SignKey:   TestSignKey,
		logger:    testLogger,
		ClockSkew: 10, // allow 10 seconds of clock skew
	}
	assert.Nil(t, ja.Validate())

	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+issueTokenString(claims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, "dfeden", gotUser.ID)
}

func TestAuthenticate_ClockSkew_Nbf(t *testing.T) {
	claims := MapClaims{"sub": "dfeden",
		"nbf": time.Now().Add(5 * time.Second).Unix(), // issued 5 Seconds in the future
	}
	ja := &JWTAuth{
		SignKey:   TestSignKey,
		logger:    testLogger,
		ClockSkew: 10, // allow 10 seconds of clock skew
	}
	assert.Nil(t, ja.Validate())

	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+issueTokenString(claims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, "dfeden", gotUser.ID)
}

func TestValidate_InvalidMetaClaims(t *testing.T) {
	ja := &JWTAuth{
		SignKey: TestSignKey,
		MetaClaims: map[string]string{
			"IsAdmin": "",
		},
	}
	assert.Contains(t, ja.Validate().Error(), "invalid meta claim")
}

func TestDetermineSigningAlgorithmFallback(t *testing.T) {
	ja := &JWTAuth{SignAlgorithm: jwa.HS256().String()}

	alg := ja.determineSigningAlgorithm()
	assert.Equal(t, jwa.HS256(), alg)

	alg = ja.determineSigningAlgorithm(jwa.EdDSA().String())
	assert.Equal(t, jwa.EdDSA(), alg)
}

func TestAuthenticate_FromAuthorizationHeader(t *testing.T) {
	claims := MapClaims{"sub": "ggicci"}
	ja := &JWTAuth{SignKey: TestSignKey, logger: testLogger}
	assert.Nil(t, ja.Validate())

	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+issueTokenString(claims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)
}

func TestAuthenticate_DisableAuthorizationFallback(t *testing.T) {
	token := issueTokenString(MapClaims{"sub": "ggicci"})
	for _, tc := range []struct {
		name          string
		disable       bool
		explicit      bool
		cookie        bool
		authorization string
		authenticated bool
	}{
		{name: "default fallback", authorization: "Bearer " + token, authenticated: true},
		{name: "disabled fallback", disable: true, authorization: "Bearer " + token},
		{name: "explicit header", disable: true, explicit: true, authorization: "Bearer " + token, authenticated: true},
		{name: "cookie and Basic", disable: true, cookie: true, authorization: "Basic dXNlcjpwYXNz", authenticated: true},
		{name: "Basic without cookie", disable: true, authorization: "Basic dXNlcjpwYXNz"},
		{name: "API key without cookie", disable: true, authorization: "Bearer key_aaaabbbbccccddddeeeeffff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			ja := &JWTAuth{
				SignKey: TestSignKey, FromCookies: []string{"gate"},
				DisableAuthorizationFallback: tc.disable, logger: zap.New(core),
			}
			if tc.explicit {
				ja.FromHeader = []string{"Authorization"}
			}
			require.NoError(t, ja.Validate())
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", tc.authorization)
			if tc.cookie {
				r.AddCookie(&http.Cookie{Name: "gate", Value: token})
			}
			user, authenticated, err := ja.Authenticate(httptest.NewRecorder(), r)
			require.NoError(t, err)
			assert.Equal(t, tc.authenticated, authenticated)
			assert.Empty(t, logs.FilterMessage("invalid token").All())
			if tc.authenticated {
				assert.Equal(t, "ggicci", user.ID)
			} else {
				assert.Empty(t, user.ID)
			}
		})
	}
}

func TestAuthenticate_LogsOmitTokenString(t *testing.T) {
	malformedClaims, err := jws.Sign([]byte(`{"sub":"ggicci","exp":"private-credential-value"}`), jws.WithKey(jwa.HS256(), RawTestSignKey))
	require.NoError(t, err)
	for _, tc := range []struct {
		name          string
		token         string
		wantError     string
		authenticated bool
	}{
		{name: "short credential", token: "abc123"},
		{name: "opaque API key", token: "key_aaaabbbbccccddddeeeeffff"},
		{name: "Basic", token: "Basic dXNlcjpwYXNz"},
		{name: "malformed claims", token: string(malformedClaims), wantError: "private-credential-value"},
		{name: "expired JWT", token: issueTokenString(MapClaims{"sub": "ggicci", "exp": 689702400})},
		{name: "valid JWT", token: issueTokenString(MapClaims{"sub": "ggicci"}), authenticated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			ja := &JWTAuth{SignKey: TestSignKey, logger: zap.New(core)}
			require.NoError(t, ja.Validate())
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", tc.token)
			_, authenticated, err := ja.Authenticate(httptest.NewRecorder(), r)
			assert.Equal(t, tc.authenticated, authenticated)
			if tc.authenticated {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.ErrorIs(t, err, jwt.ParseError())
				if tc.wantError != "" {
					assert.Contains(t, err.Error(), tc.wantError)
				}
			}
			entries := logs.All()
			require.Len(t, entries, 1)
			fields := entries[0].ContextMap()
			assert.NotContains(t, fields, "token_string")
			if !tc.authenticated {
				assert.Equal(t, err.Error(), fields["error"])
			}
		})
	}
}

func TestAuthenticate_EdDSA(t *testing.T) {
	claims := MapClaims{"sub": "ggicci"}
	ja := &JWTAuth{SignKey: TestSignKeyEd25519, SignAlgorithm: jwa.EdDSA().String(), logger: testLogger}
	assert.Nil(t, ja.Validate())

	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+issueTokenStringEdDSA(claims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)
}

func TestAuthenticate_FromCustomHeader(t *testing.T) {
	claims := MapClaims{"sub": "ggicci"}
	ja := &JWTAuth{
		SignKey:    TestSignKey,
		FromHeader: []string{"X-Api-Token"},
		logger:     testLogger,
	}
	assert.Nil(t, ja.Validate())

	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("x-api-token", issueTokenString(claims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)
}

func TestAuthenticate_FromQueryWithSkipVerification(t *testing.T) {
	var (
		claims = MapClaims{"sub": "ggicci"}
		ja     = &JWTAuth{
			FromQuery:        []string{"access_token", "token"},
			SkipVerification: true,
			logger:           testLogger,
		}
		tokenString = issueTokenString(claims)

		err           error
		rw            *httptest.ResponseRecorder
		r             *http.Request
		params        url.Values
		gotUser       User
		authenticated bool
	)
	assert.Nil(t, ja.Validate())

	// trying "access_token" without signature key
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)

	// invalid "token" without signature key
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString+"INVALID")
	params.Add("token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)
}

func TestAuthenticate_PopulateUserMetadataWithSkipVerification(t *testing.T) {
	ja := &JWTAuth{
		SkipVerification: true,
		MetaClaims: map[string]string{
			"jti":                            "jti",
			"IsAdmin":                        "is_admin",
			"settings.role":                  "role",
			"settings.payout.paypal.enabled": "is_paypal_enabled",
		},
		logger: testLogger,
	}
	assert.Nil(t, ja.Validate())

	claimsWithMetadata := MapClaims{
		"jti":     "a976475a-186a-4c1f-b182-95b3f886e2b4",
		"sub":     "ggicci",
		"IsAdmin": true,
		"settings": map[string]interface{}{
			"role": "admin",
			"payout": map[string]interface{}{
				"paypal": map[string]interface{}{
					"enabled": true,
				},
			},
		},
	}
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claimsWithMetadata))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, "a976475a-186a-4c1f-b182-95b3f886e2b4", gotUser.Metadata["jti"])
	assert.Equal(t, "true", gotUser.Metadata["is_admin"])
	assert.Equal(t, "admin", gotUser.Metadata["role"])
	assert.Equal(t, "true", gotUser.Metadata["is_paypal_enabled"])
}

func TestAuthenticate_FromQuery(t *testing.T) {
	var (
		claims = MapClaims{"sub": "ggicci"}
		ja     = &JWTAuth{
			SignKey:   TestSignKey,
			FromQuery: []string{"access_token", "token"},
			logger:    testLogger,
		}
		tokenString = issueTokenString(claims)

		err           error
		rw            *httptest.ResponseRecorder
		r             *http.Request
		params        url.Values
		gotUser       User
		authenticated bool
	)
	assert.Nil(t, ja.Validate())

	// only "access_token"
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)

	// only "token"
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)

	// both valid "access_token", "token"
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString)
	params.Add("token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)

	// invalid "access_token", and valid "token"
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString+"INVALID")
	params.Add("token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)

	// both invalid "access_token", "token"
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString+"INVALID")
	params.Add("token", tokenString+"INVALID")
	r.URL.RawQuery = params.Encode()
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.NotEqual(t, User{ID: "ggicci"}, gotUser)
}

func TestAuthenticate_FromCookies(t *testing.T) {
	claims := MapClaims{"sub": "ggicci"}
	ja := &JWTAuth{
		SignKey:     TestSignKey,
		FromCookies: []string{"user_session", "sess"},
		logger:      testLogger,
	}
	assert.Nil(t, ja.Validate())

	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "user_session", Value: issueTokenString(claims)})
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)
}

func TestAuthenticate_CustomUserClaims(t *testing.T) {
	claims := MapClaims{"sub": "182140474727", "username": "ggicci"}
	ja := &JWTAuth{
		SignKey:    TestSignKey,
		UserClaims: []string{"username"},
		logger:     testLogger,
	}
	assert.Nil(t, ja.Validate())
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)

	// custom user claims all empty should fail - having keys
	claims = MapClaims{"sub": "ggicci", "username": ""}
	ja = &JWTAuth{
		SignKey:    TestSignKey,
		UserClaims: []string{"username"},
		logger:     testLogger,
	}
	assert.Nil(t, ja.Validate())
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// custom user claims all empty should fail - even no keys
	claims = MapClaims{"username": "ggicci"}
	ja = &JWTAuth{
		SignKey:    TestSignKey,
		UserClaims: []string{"uid", "user_id"},
		logger:     testLogger,
	}
	assert.Nil(t, ja.Validate())
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// custom user claims at least one is non-empty can work
	claims = MapClaims{"username": "ggicci", "user_id": nil, "uid": 19911110}
	ja = &JWTAuth{
		SignKey:    TestSignKey,
		UserClaims: []string{"user_id", "uid"},
		logger:     testLogger,
	}
	assert.Nil(t, ja.Validate())
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "19911110"}, gotUser)
}

func TestAuthenticate_ValidateStandardClaims(t *testing.T) {
	ja := &JWTAuth{
		SignKey: TestSignKey,
		logger:  testLogger,
	}
	assert.Nil(t, ja.Validate())

	// invalid "exp" (Expiration Time)
	expiredClaims := MapClaims{"sub": "ggicci", "exp": 689702400}
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "iat" (Issued At)
	expiredClaims = MapClaims{"sub": "ggicci", "iat": 3845462400}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "nbf" (Not Before)
	expiredClaims = MapClaims{"sub": "ggicci", "nbf": 3845462400}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)
}

func TestAuthenticate_VerifyIssuerWhitelist(t *testing.T) {
	ja := &JWTAuth{
		SignKey: TestSignKey,
		logger:  testLogger,

		IssuerWhitelist: []string{"https://api.example.com", "https://api.github.com"},
	}
	assert.Nil(t, ja.Validate())

	// valid "iss"
	exampleClaims := MapClaims{"sub": "ggicci", "iss": "https://api.example.com"}
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(exampleClaims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, gotUser.ID, "ggicci")

	githubClaims := MapClaims{"sub": "ggicci", "iss": "https://api.github.com"}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(githubClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, gotUser.ID, "ggicci")

	// invalid "iss" (no iss)
	noIssClaims := MapClaims{"sub": "ggicci"}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(noIssClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "iss" (wrong value)
	wrongIssClaims := MapClaims{"sub": "ggicci", "iss": "https://api.example.com/secure"}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(wrongIssClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)
}

func TestAuthenticate_VerifyAudienceWhitelist(t *testing.T) {
	ja := &JWTAuth{
		SignKey: TestSignKey,
		logger:  testLogger,

		IssuerWhitelist:   []string{"https://api.github.com"},
		AudienceWhitelist: []string{"https://api.codelet.io", "https://api.copilot.codelet.io"},
	}
	assert.Nil(t, ja.Validate())

	// valid "aud" (of single string)
	githubClaims := MapClaims{
		"sub": "ggicci",
		"iss": "https://api.github.com",
		"aud": "https://api.codelet.io",
	}
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(githubClaims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, gotUser.ID, "ggicci")

	// valid "aud" (multiple, as long as one of them is on the whitelist)
	githubClaims = MapClaims{
		"sub": "ggicci",
		"iss": "https://api.github.com",
		"aud": []string{"https://api.learn.codelet.io", "https://api.copilot.codelet.io"},
	}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(githubClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, gotUser.ID, "ggicci")

	// invalid "aud" (no aud)
	noIssClaims := MapClaims{"sub": "ggicci", "iss": "https://api.github.com"}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(noIssClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "aud" (wrong value)
	wrongIssClaims := MapClaims{
		"sub": "ggicci",
		"iss": "https://api.github.com",
		"aud": []string{"https://api.example.com", "https://api.example.org"},
	}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(wrongIssClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)
}

func TestAuthenticate_PopulateUserMetadata(t *testing.T) {
	ja := &JWTAuth{
		SignKey: TestSignKey,
		MetaClaims: map[string]string{
			"jti":                            "jti",
			"IsAdmin":                        "is_admin",
			"registerTime":                   "registered_at",
			"absent":                         "absent", // not found in JWT payload, final ""
			"aud":                            "aud",    // standard claim, final "aud1,aud2,aud3"
			"groups":                         "groups", // supported array type, final "csgo,dota2"
			"settings.role":                  "role",   // supported nested claim, final "admin"
			"settings.payout.paypal.enabled": "is_paypal_enabled",
			"settings.payout.alipay.enabled": "is_alipay_enabled",
		},
		logger: testLogger,
	}
	assert.Nil(t, ja.Validate())

	claimsWithMetadata := MapClaims{
		"jti":          "a976475a-186a-4c1f-b182-95b3f886e2b4",
		"sub":          "ggicci",
		"IsAdmin":      true,
		"aud":          []string{"aud1", "aud2", "aud3"},
		"registerTime": time.Date(2000, 1, 2, 15, 23, 18, 0, time.UTC),
		"groups":       []string{"csgo", "dota2"},
		"settings": map[string]interface{}{
			"role": "admin",
			"payout": map[string]interface{}{
				"paypal": map[string]interface{}{
					"enabled": true,
				},
			},
		},
	}
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claimsWithMetadata))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, "ggicci", gotUser.ID)
	assert.Equal(t, "a976475a-186a-4c1f-b182-95b3f886e2b4", gotUser.Metadata["jti"])
	assert.Equal(t, "true", gotUser.Metadata["is_admin"])
	assert.Equal(t, "2000-01-02T15:23:18Z", gotUser.Metadata["registered_at"])
	assert.Equal(t, "", gotUser.Metadata["absent"])
	assert.Equal(t, "aud1,aud2,aud3", gotUser.Metadata["aud"])
	assert.Equal(t, "csgo,dota2", gotUser.Metadata["groups"])
	assert.Equal(t, "admin", gotUser.Metadata["role"])
	assert.Equal(t, "true", gotUser.Metadata["is_paypal_enabled"])
	assert.Equal(t, "", gotUser.Metadata["is_alipay_enabled"])
}

// TestAuthenticate_LogLevel checks that the "user authenticated" log line is
// emitted at the level configured via LogLevel, instead of always at Info.
func TestAuthenticate_LogLevel(t *testing.T) {
	for levelStr, expectedLevel := range map[string]zapcore.Level{
		"":      zapcore.InfoLevel, // default, when unset
		"debug": zapcore.DebugLevel,
		"info":  zapcore.InfoLevel,
		"warn":  zapcore.WarnLevel,
		"error": zapcore.ErrorLevel,
	} {
		core, recorded := observer.New(zapcore.DebugLevel)
		ja := &JWTAuth{
			SignKey:  TestSignKey,
			LogLevel: levelStr,
			logger:   zap.New(core),
		}
		assert.Nil(t, ja.Validate(), "log_level=%q", levelStr)

		claims := MapClaims{"sub": "ggicci"}
		rw := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Add("Authorization", "Bearer "+issueTokenString(claims))
		gotUser, authenticated, err := ja.Authenticate(rw, r)
		assert.Nil(t, err)
		assert.True(t, authenticated)
		assert.Equal(t, User{ID: "ggicci"}, gotUser)

		entries := recorded.FilterMessage("user authenticated").All()
		assert.Len(t, entries, 1, "log_level=%q", levelStr)
		assert.Equal(t, expectedLevel, entries[0].Level, "log_level=%q", levelStr)
	}
}

type ThingNotStringer struct{}
type ThingIsStringer struct{}

func (t ThingIsStringer) String() string { return "i'm stringer" }

func Test_stringify(t *testing.T) {
	now := time.Now()

	for _, c := range []struct {
		Input    interface{}
		Expected string
	}{
		{nil, ""},
		{"abc", "abc"},
		{true, "true"},
		{false, "false"},
		{json.Number("1991"), "1991"},
		{now, now.UTC().Format(time.RFC3339Nano)},
		{[]string{"aud1", "aud2"}, "aud1,aud2"},
		{[]int{1, 2, 3}, ""},                // unsupported array type
		{ThingNotStringer{}, ""},            // unsupported custom type
		{ThingIsStringer{}, "i'm stringer"}, // support fmt.Stringer interface
	} {
		assert.Equal(t, stringify(c.Input), c.Expected)
	}
}

func Test_AsymmetricAlgorithm(t *testing.T) {
	ja := &JWTAuth{SignKey: TestPubKey, UserClaims: []string{"login"}, logger: testLogger}
	assert.Nil(t, ja.Validate())
	token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzMDc3NTU1IiwibG9naW4iOiJnZ2ljY2kiLCJkaXNwbGF5IjoiR2dpY2NpIiwiYWRtaW4iOmZhbHNlfQ.eOXRUSS-WSebEobZgqmui9VlKentHW5IxQpWR5xGu-u9svzdWJnGqLbnKBeIy42tQkFHNDWUx4R2z8Jv3ZPByN1qvWYIloJ8vLQsb0GsfXoqOPkhsfAzkOEp0m5Ws83ar9TT83MLQrUisKU-WjRZTOid9Hfe2atKN4h74vqpNMUfdRZ4NOZtBTmKjoRdWwNBmM5kg59b_cUKNR9Ruab0dwI72_svFZaNiRzBXLTTOVP2Xn0wk_mavyo4dhP83P66mefSYNkoA4_xft3iG43Zkta5lnjV-EF9fACG8g4pugytDGAgGBsOoKZagIqDdNqQWo1e4CLP4G2kMTfGqlosLQ"
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+token)
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)
}

func Test_AsymmetricAlgorithm_InvalidPubKey(t *testing.T) {
	ja := &JWTAuth{SignKey: `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAA ... invalid\n-----END PUBLIC KEY-----`, UserClaims: []string{"login"}, logger: testLogger}
	assert.ErrorIs(t, ja.Validate(), ErrInvalidPublicKey)
}

func TestJWK(t *testing.T) {
	time.Sleep(3 * time.Second)
	ja := &JWTAuth{JWKURL: TestJWKURL, logger: testLogger}
	assert.Nil(t, ja.Validate())

	// Le cache sera créé lors de la première authentification
	token := issueTokenStringJWK(MapClaims{"sub": "ggicci"})
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)

	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)

	r.Header.Add("Authorization", "Bearer "+token)
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)

	// Vérifier que le cache a bien été créé pour l'URL
	assert.NotNil(t, ja.jwkCaches)
	cachedEntry, exists := ja.jwkCaches[TestJWKURL]
	assert.True(t, exists, "Le cache devrait exister pour l'URL de test")
	assert.NotNil(t, cachedEntry)
	keySet, lookupErr := cachedEntry.Cache.Lookup(context.Background(), cachedEntry.URL)
	require.NoError(t, lookupErr)
	assert.Equal(t, 1, keySet.Len())
}

func TestJWKSet(t *testing.T) {
	time.Sleep(3 * time.Second)
	ja := &JWTAuth{JWKURL: TestJWKSetURL, logger: testLogger}
	assert.Nil(t, ja.Validate())

	// Authentifier pour créer le cache
	token := issueTokenStringJWK(MapClaims{"sub": "ggicci"})
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)

	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)

	r.Header.Add("Authorization", "Bearer "+token)
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "ggicci"}, gotUser)

	// Vérifier que le cache a été créé correctement
	assert.NotNil(t, ja.jwkCaches)
	cachedEntry, exists := ja.jwkCaches[TestJWKSetURL]
	assert.True(t, exists, "Le cache devrait exister pour l'URL du set JWK")
	assert.NotNil(t, cachedEntry)
	keySet, lookupErr := cachedEntry.Cache.Lookup(context.Background(), cachedEntry.URL)
	require.NoError(t, lookupErr)
	assert.Equal(t, 2, keySet.Len())
}

func TestJWKSet_KeyNotFound(t *testing.T) {
	time.Sleep(3 * time.Second)
	ja := &JWTAuth{JWKURL: TestJWKSetURLInapplicable, logger: testLogger}
	assert.Nil(t, ja.Validate())

	// Première requête pour créer le cache
	token := issueTokenStringJWK(MapClaims{"sub": "ggicci"})
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)

	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)

	r.Header.Add("Authorization", "Bearer "+token)
	gotUser, authenticated, err := ja.Authenticate(rw, r)

	// Vérifier que le cache a été créé correctement
	assert.NotNil(t, ja.jwkCaches)
	cachedEntry, exists := ja.jwkCaches[TestJWKSetURLInapplicable]
	assert.True(t, exists, "Le cache devrait exister pour l'URL inapplicable")
	assert.NotNil(t, cachedEntry)
	keySet, lookupErr := cachedEntry.Cache.Lookup(context.Background(), cachedEntry.URL)
	require.NoError(t, lookupErr)
	assert.Equal(t, 2, keySet.Len())

	// Vérifier que l'authentification a échoué car la clé n'est pas trouvée
	assert.Error(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)
}

func TestJWKFetchFailureRecovery(t *testing.T) {
	for _, failure := range []string{"404", "500", "invalid JSON", "connection closed"} {
		t.Run(failure, func(t *testing.T) {
			var healthy atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if healthy.Load() {
					json.NewEncoder(w).Encode(jwkPubKeySet)
					return
				}
				switch failure {
				case "404":
					http.NotFound(w, r)
				case "500":
					w.WriteHeader(http.StatusInternalServerError)
				case "invalid JSON":
					w.Write([]byte("invalid"))
				case "connection closed":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
				}
			}))
			defer server.Close()
			ja := &JWTAuth{JWKURL: server.URL, logger: testLogger}
			require.NoError(t, ja.Validate())
			defer func() {
				for _, entry := range ja.jwkCaches {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					assert.NoError(t, entry.Cache.Shutdown(ctx))
					cancel()
				}
			}()

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
			r.Header.Set("Authorization", "Bearer "+issueTokenStringJWK(MapClaims{"sub": "ggicci"}))
			_, authenticated, err := ja.Authenticate(httptest.NewRecorder(), r)
			require.Error(t, err)
			require.False(t, authenticated)
			entry := ja.jwkCaches[server.URL]
			require.NotNil(t, entry)

			// More failures than the worker pool size must still allow recovery.
			for range 10 {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				assert.Error(t, entry.refresh(ctx, testLogger))
				assert.NoError(t, ctx.Err())
				cancel()
			}
			_, authenticated, err = ja.Authenticate(httptest.NewRecorder(), r)
			require.Error(t, err)
			require.False(t, authenticated)

			healthy.Store(true)
			require.Eventually(t, func() bool {
				user, authenticated, err := ja.Authenticate(httptest.NewRecorder(), r)
				return err == nil && authenticated && user.ID == "ggicci"
			}, time.Second, 10*time.Millisecond)

			// A later outage must leave the last successfully fetched keys usable.
			healthy.Store(false)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			require.Error(t, entry.refresh(ctx, testLogger))
			user, authenticated, err := ja.Authenticate(httptest.NewRecorder(), r)
			require.NoError(t, err)
			require.True(t, authenticated)
			assert.Equal(t, "ggicci", user.ID)
		})
	}
}

func TestJWKInitialFetchBoundedAndIsolated(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case started <- struct{}{}:
			default:
			}
			<-r.Context().Done()
			return
		}
		json.NewEncoder(w).Encode(jwkPubKeySet)
	}))
	defer server.Close()
	ja := &JWTAuth{JWKURL: server.URL + "/{key_path}", logger: testLogger}
	require.NoError(t, ja.Validate())
	defer func() {
		for _, entry := range ja.jwkCaches {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			assert.NoError(t, entry.Cache.Shutdown(ctx))
			cancel()
		}
	}()
	token := issueTokenStringJWK(MapClaims{"sub": "ggicci"})
	request := func(ctx context.Context, path string) *http.Request {
		repl := caddy.NewReplacer()
		repl.Set("key_path", path)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r = r.WithContext(context.WithValue(ctx, caddy.ReplacerCtxKey, repl))
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
	type result struct {
		authenticated bool
		err           error
	}
	done := make(chan result, 1)
	go func() {
		_, authenticated, err := ja.Authenticate(httptest.NewRecorder(), request(context.Background(), "slow"))
		done <- result{authenticated, err}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("initial fetch did not start")
	}

	// A request waiting for the same initial fetch can cancel independently.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, authenticated, err := ja.Authenticate(httptest.NewRecorder(), request(ctx, "slow"))
	require.Error(t, err)
	require.False(t, authenticated)
	require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)

	// A different resolved URL must authenticate while the first fetch is stalled.
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	user, authenticated, err := ja.Authenticate(httptest.NewRecorder(), request(ctx, "keys"))
	require.NoError(t, err)
	require.True(t, authenticated)
	assert.Equal(t, "ggicci", user.ID)

	select {
	case got := <-done:
		assert.Error(t, got.err)
		assert.False(t, got.authenticated)
	case <-time.After(jwkFetchTimeout + time.Second):
		t.Fatal("initial fetch exceeded its timeout")
	}
}
