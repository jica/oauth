# Backend Developer Test

## Solution
To get the application:
``` bash
$ go get github.com/jica/oauth
```

To run the client:
``` bash
$ cd $GOPATH/src/github.com/jica/oauth/client
$ go run main.go
```
Now you can access using aps provider using http://localhost:3000/auth/aps

To execute the tests it is necesary to get gock:
(TODO: Add to vendor using godep)
``` bash
$ go get gopkg.in/h2non/gock.v1
$ go test github.com/jica/oauth/goth/aps
```


## Introduction
The intention of the exercise is to test your ability to resolve a complex problem we could find in the real world. We are asking you to create a [Goth](https://github.com/markbates/goth/) provider for a mock oauth2 server that we have created. We are giving you both the oauth2 server and a skeleton for the goauth provider.

This test should take you less than 2 hours. Once you are done send us a link to a public github repository with your code. If you are unable to complete it, it is ok, just send us your solution so far and tell us where you got stuck. We plan to give you the solution at the interview, anyway.

## Oauth2 Server
We have borrowed code from https://github.com/go-oauth2/oauth2 to make this APS Oauth2 server. To make it run you only have to:

``` bash
$ cd server
$ go run main.go
```
Please bear in mind that any user and password combinations will always work and provide you with a token. Something similar to:

```json
{"email":"test@test.com","id":"000000","location":"localhost"},....,"Location":"localhost","AccessToken":"...","AccessTokenSecret":"...","RefreshToken":"...","ExpiresAt":"..."}
```
Plus if you try the example located here it will work: https://github.com/go-oauth2/oauth2/tree/master/example/client

## Demo Client

To compile and start the authentication-client server please run the following command.

``` bash
$ cd client
$ go run main.go
```

Once the server has started you should see the following output.

```bash
Configured Routes:
               NAME                       METHOD         PATH
               /                          GET            /
               /auth/:provider            GET            /auth/:provider
               /auth/:provider/callback   GET            /auth/:provider/callback
               /login                     GET            /login
               /logout                    GET            /logout
         _____      _
        |_   _|    (_)
          | |  ____ _  ___
          | | | __|| |/ __|
         _| |_| |  | |\__ \
        |_____|_|  |_||___/ 4.0.0-alpha.4

Running at 0.0.0.0:3000
```
To test that the server is working correctly please access the following URL: http://localhost:3000/. You will get a message like this:
```json
"{\"code\":\"401\",\"message\":\"Please login into the platform\"}"
```
Now to test that Goth is set up correctly we have inserted Google Plus goth driver into the code. Access the following URL: http://localhost:3000/auth/gplus. Once you have done that you should be logged into the platform with your google account credentials. To log out you can access the following URL: http://localhost:3000/logout.

Your exercise is to modify the server to integrate the APS OAuth2 server described above as an OAuth provider, just like Google Plus is integrated. We would like the login route to be http://localhost:3000/auth/aps, the server already has the route available and a skeleton for the APS provider is waiting in the client/goth/aps package for your implementation. Namely you have to implement the following methods:

* In session.go
    * func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error)
* In aps.go
    * func New(clientKey, secret, callbackURL string, scopes ...string) *Provider
    * func (p *Provider) FetchUser(session goth.Session) (goth.User, error)
    * func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error)
    * func (p *Provider) RefreshTokenAvailable() bool
    * func (p *Provider) BeginAuth(state string) (goth.Session, error)
    * func (p *Provider) SetPrompt(prompt ...string)

Good luck.

## Hints and Recommendations

+ Please always use localhost for all the connection. As 127.0.0.1 will give you errors.
+ Please look into other [auth providers](https://github.com/markbates/goth/tree/master/providers) in Goth to see how they are structured and how they work. Look especially into the one we have set up ;)
+ Please take into consideration that OAuth2 server does not support the HTTP Basic authentication scheme to authenticate with the authorization server. If you look at the [WePay](https://github.com/markbates/goth/tree/master/providers/wepay) driver you might find the solution but please do not use this driver as a reference. Another hint is the following API docs around [oauth2 in go](https://godoc.org/golang.org/x/oauth2#RegisterBrokenAuthHeaderProvider)
+ If you have extra time and really want to impress us, you can write some tests as a bonus
