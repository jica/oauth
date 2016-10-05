package aps_test

import (
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"

	"net/http"

	"github.com/jica/oauth/client/goth/aps"
	"gopkg.in/h2non/gock.v1"
)

type param map[string]string

func (p param) Get(key string) string {
	return p[key]
}

const (
	mockServer   = "localhost:9096"
	testLocation = "local"
	testUserId   = "000001"
	testEmail    = testUserId + "@" + testLocation + ".es"
)

func Test_Complete(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	//Server Mock that return token
	gock.New(mockServer).
		Post("/token").
		Reply(http.StatusOK).
		JSON(map[string]string{"access_token": token, "expires_in": "7200", "refresh_token": "REFRESHTOKENREFRESHTOK", "scope": "profile email openid", "token_type": "Bearer"})

	//Server Mock that return user info
	gock.New(mockServer).
		Get("/userinfo").
		Reply(http.StatusOK).
		JSON(map[string]string{"location": testLocation, "email": testEmail, "id": testUserId})

	defer gock.Off() // Flush pending mocks after test execution

	provider := aps.New(clientKey, secret, callbackURL)
	session, _ := provider.BeginAuth(test_state)
	s := session.(*aps.Session)

	tk, err := s.Authorize(provider, param{"code": "12345", "state": test_state})
	if err != nil {
		a.Fail("There was an error on session.Authorize")
	}
	a.Equal(token, tk) //Check the returned token

	var u goth.User
	u, err = provider.FetchUser(s)
	if err != nil {
		a.Fail("There was an error on provider.FetchUser")
	}

	//Check that the user values
	a.Equal(testLocation, u.Location)
	a.Equal(testEmail, u.Email)
	a.Equal(testUserId, u.UserID)
	a.Equal(token, u.AccessToken)
}
