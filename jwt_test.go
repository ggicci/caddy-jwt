package caddyjwt

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const TestSignKey = "NFL5*0Bc#9U6E@tnmC&E7SUN6GwHfLmY"

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

func TestValidate(t *testing.T) {
	ja := &JWTAuth{}
	err := ja.Validate()
	assert.NotNil(t, err)
}

func TestAuthenticate_FromAuthorizationHeader(t *testing.T) {
	claims := MapClaims{"aud": "ggicci"}
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
	claims := MapClaims{"aud": "ggicci"}
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
		claims = MapClaims{"aud": "ggicci"}
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
	claims := MapClaims{"aud": "ggicci"}
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
	claims := MapClaims{"aud": "ggicci", "user_id": "182140474727"}
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

	// custom user claims all empty should fail
	claims = MapClaims{"aud": "ggicci", "user_id": ""}
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

	// custom user claims at least one is non-empty can work
	claims = MapClaims{"aud": "ggicci", "user_id": nil, "uid": 19911110}
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
	expiredClaims := MapClaims{"aud": "ggicci", "exp": 689702400}
	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotUser, authenticated, err := ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "iat" (Issued At)
	expiredClaims = MapClaims{"aud": "ggicci", "iat": 3845462400}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)

	// invalid "nbf" (Not Before)
	expiredClaims = MapClaims{"aud": "ggicci", "nbf": 3845462400}
	rw = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotUser, authenticated, err = ja.Authenticate(rw, r)
	assert.NotNil(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, gotUser.ID)
}
