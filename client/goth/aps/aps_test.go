package aps_test

import (
	"fmt"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"

	"github.com/jica/oauth/client/goth/aps"
)

const (
	authURL     string = "http://" + mockServer + "/authorize"
	clientKey   string = "APS_KEY"
	secret      string = "APS_SECRET"
	callbackURL string = "/callback"
	token       string = "1234567890"
	test_state  string = "test_state"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := apsProvider()
	a.Equal(provider.ClientKey, clientKey)
	a.Equal(provider.Secret, secret)
	a.Equal(provider.CallbackURL, callbackURL)
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := apsProvider()
	session, err := provider.BeginAuth(test_state)
	s := session.(*aps.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, authURL)
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", clientKey))
	a.Contains(s.AuthURL, "state="+test_state)
	a.Contains(s.AuthURL, "scope=profile+email+openid")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), apsProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := apsProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"` + authURL + `","AccessToken":"` + token + `"}`)
	a.NoError(err)
	session := s.(*aps.Session)
	a.Equal(session.AuthURL, authURL)
	a.Equal(session.AccessToken, token)
}

func apsProvider() *aps.Provider {
	return aps.New(clientKey, secret, callbackURL)
}
