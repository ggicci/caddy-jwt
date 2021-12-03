package caddyjwt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

var TestSignKey = []byte("NFL5*0Bc#9U6E@tnmC&E7SUN6GwHfLmY")

var (
	testLogger, _ = zap.NewDevelopment()
)

func issueTokenString(claims MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(TestSignKey))
	if err != nil {
		panic(err)
	}
	return tokenString
}

func TestValidate_SignKey(t *testing.T) {
	// missing sign_key
	ja := &JWTAuth{}
	err := ja.Validate()
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "sign_key is required")

	// having sign_key
	ja = &JWTAuth{
		SignKey: TestSignKey,
	}
	assert.Nil(t, ja.Validate())
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
	claims := MapClaims{"username": "ggicci"}
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

func TestAuthenticate_FromCustomHeader(t *testing.T) {
	claims := MapClaims{"username": "ggicci"}
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

func TestAuthenticate_FromQuery(t *testing.T) {
	var (
		claims = MapClaims{"username": "ggicci"}
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
	claims := MapClaims{"username": "ggicci"}
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
	claims := MapClaims{"username": "ggicci", "user_id": "182140474727"}
	ja := &JWTAuth{
		SignKey:    TestSignKey,
		UserClaims: []string{"user_id"},
		logger:     testLogger,
	}
	assert.Nil(t, ja.Validate())
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, User{ID: "182140474727"}, gotUser)

	// custom user claims all empty should fail - having keys
	claims = MapClaims{"username": "ggicci", "user_id": ""}
	ja = &JWTAuth{
		SignKey:    TestSignKey,
		UserClaims: []string{"user_id"},
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
	expiredClaims := MapClaims{"username": "ggicci", "exp": 689702400}
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "iat" (Issued At)
	expiredClaims = MapClaims{"username": "ggicci", "iat": 3845462400}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "nbf" (Not Before)
	expiredClaims = MapClaims{"username": "ggicci", "nbf": 3845462400}
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
	exampleClaims := MapClaims{"username": "ggicci", "iss": "https://api.example.com"}
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(exampleClaims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, gotUser.ID, "ggicci")

	githubClaims := MapClaims{"username": "ggicci", "iss": "https://api.github.com"}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(githubClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, gotUser.ID, "ggicci")

	// invalid "iss" (no iss)
	noIssClaims := MapClaims{"username": "ggicci"}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(noIssClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "iss" (wrong value)
	wrongIssClaims := MapClaims{"username": "ggicci", "iss": "https://api.example.com/secure"}
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
		"username": "ggicci",
		"iss":      "https://api.github.com",
		"aud":      "https://api.codelet.io",
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
		"username": "ggicci",
		"iss":      "https://api.github.com",
		"aud":      []string{"https://api.learn.codelet.io", "https://api.copilot.codelet.io"},
	}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(githubClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.Nil(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, gotUser.ID, "ggicci")

	// invalid "aud" (no aud)
	noIssClaims := MapClaims{"username": "ggicci", "iss": "https://api.github.com"}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(noIssClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "aud" (wrong value)
	wrongIssClaims := MapClaims{
		"username": "ggicci",
		"iss":      "https://api.github.com",
		"aud":      []string{"https://api.example.com", "https://api.example.org"},
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
			"groups":                         "groups", // unsupported array type, final ""
			"settings.role":                  "role",   // supported nested claim, final "admin"
			"settings.payout.paypal.enabled": "is_paypal_enabled",
			"settings.payout.alipay.enabled": "is_alipay_enabled",
		},
		logger: testLogger,
	}
	assert.Nil(t, ja.Validate())

	claimsWithMetadata := MapClaims{
		"jti":          "a976475a-186a-4c1f-b182-95b3f886e2b4",
		"username":     "ggicci",
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
	assert.Equal(t, "", gotUser.Metadata["groups"])
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
