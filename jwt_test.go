package caddyjwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/caddyserver/caddy/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
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
	key, err := jwk.FromRaw(privateKey)
	panicOnError(err)
	jwk.AssignKeyID(key)                       // set "kid"
	key.Set(jwk.AlgorithmKey, jwa.RS256)       // set "alg"
	key.Set(jwk.KeyUsageKey, jwk.ForSignature) // set "use"
	return key
}

func generateEdDSAJWK() jwk.Key {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	panicOnError(err)
	TestSignKeyEd25519 = base64.StdEncoding.EncodeToString(publicKey)
	key, err := jwk.FromRaw(privateKey)
	panicOnError(err)
	jwk.AssignKeyID(key)
	key.Set(jwk.AlgorithmKey, jwa.EdDSA)
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
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, RawTestSignKey))
	panicOnError(err)

	return string(tokenBytes)
}

// issueTokenString issues a token string with the given claims,
// using EdDSA signing algorithm.
func issueTokenStringEdDSA(claims MapClaims) string {
	token := buildToken(claims)
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, jwkKeyEd25519))
	panicOnError(err)

	return string(tokenBytes)
}

func issueTokenStringJWK(claims MapClaims, options ...func(*jwt.SignOption)) string {
	token := buildToken(claims)

	// Options par défaut
	signOptions := []jwt.SignOption{jwt.WithKey(jwa.RS256, jwkKey)}

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

func TestValidate_InvalidMetaClaims(t *testing.T) {
	ja := &JWTAuth{
		SignKey: TestSignKey,
		MetaClaims: map[string]string{
			"IsAdmin": "",
		},
	}
	assert.Contains(t, ja.Validate().Error(), "invalid meta claim")
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

func TestAuthenticate_EdDSA(t *testing.T) {
	claims := MapClaims{"sub": "ggicci"}
	ja := &JWTAuth{SignKey: TestSignKeyEd25519, SignAlgorithm: string(jwa.EdDSA), logger: testLogger}
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
	assert.Equal(t, "csgo,dota2", gotUser.Metadata["groups"])
	assert.Equal(t, "admin", gotUser.Metadata["role"])
	assert.Equal(t, "true", gotUser.Metadata["is_paypal_enabled"])
	assert.Equal(t, "", gotUser.Metadata["is_alipay_enabled"])
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
		{[]int{1, 2, 3}, ""},                // unsupported array type
		{ThingNotStringer{}, ""},            // unsupported custom type
		{ThingIsStringer{}, "i'm stringer"}, // support fmt.Stringer interface
	} {
		assert.Equal(t, stringify(c.Input), c.Expected)
	}
}

func Test_desensitizedTokenString(t *testing.T) {
	for _, c := range []struct {
		Input    string
		Expected string
	}{
		{"", ""},
		{"abc", "abc"},
		{"abcdef", "abcdef"},
		{"abcdefg", "ab…fg"},
		{"abcdefeijk", "abc…ijk"},
		{"abcdefghijklmnopqrstuvwxyz", "abcdefgh…stuvwxyz"},
		{"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv", "abcdefghijklmnop…ghijklmnopqrstuv"},
		{
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
			"abcdefghijklmnop…klmnopqrstuvwxyz",
		},
		{
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
			"abcdefghijklmnop…klmnopqrstuvwxyz",
		},
	} {
		assert.Equal(t, desensitizedTokenString(c.Input), c.Expected)
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
	assert.Equal(t, 1, cachedEntry.cachedSet.Len())
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
	assert.Equal(t, 2, cachedEntry.cachedSet.Len())
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
	assert.Equal(t, 2, cachedEntry.cachedSet.Len())

	// Vérifier que l'authentification a échoué car la clé n'est pas trouvée
	assert.Error(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)
}
