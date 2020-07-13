// From ory/fosite-example
// Copyright 2019-2020 Ory

package authorizationserver

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/hmalphettes/client-sided-oauth2/storage"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// fosite requires four parameters for the server to get up and running:
// 1. config - for any enforcement you may desire, you can do this using `compose.Config`. You like PKCE, enforce it!
// 2. store - no auth service is generally useful unless it can remember clients and users.
//    fosite is incredibly composable, and the store parameter enables you to build and BYODb (Bring Your Own Database)
// 3. secret - required for code, access and refresh token generation.
// 4. privateKey - required for id/jwt token generation.
var (
	oauth2ServerAddr string
	// Check the api documentation of `compose.Config` for further configuration options.
	config = &compose.Config{
		AccessTokenLifespan: time.Minute * 30,
		// ...
	}

	// This is the example storage that contains:
	// * an OAuth2 Client with id "my-client" and secret "foobar" capable of all oauth2 and open id connect grant and response types.
	// * a User for the resource owner password credentials grant type with username "peter" and password "secret".
	//
	// You will most likely replace this with your own logic once you set up a real world application.
	store = storage.NewExampleStore()

	// This secret is used to sign authorize codes, access and refresh tokens.
	// It has to be 32-bytes long for HMAC signing. This requirement can be configured via `compose.Config` above.
	// In order to generate secure keys, the best thing to do is use crypto/rand:
	//
	// ```
	// package main
	//
	// import (
	//	"crypto/rand"
	//	"encoding/hex"
	//	"fmt"
	// )
	//
	// func main() {
	//	var secret = make([]byte, 32)
	//	_, err := rand.Read(secret)
	//	if err != nil {
	//		panic(err)
	//	}
	// }
	// ```
	//
	// If you require this to key to be stable, for example, when running multiple fosite servers, you can generate the
	// 32byte random key as above and push it out to a base64 encoded string.
	// This can then be injected and decoded as the `var secret []byte` on server start.
	secret = []byte("some-cool-secret-that-is-32bytes")

	// privateKey is used to sign JWT tokens. The default strategy uses RS256 (RSA Signature with SHA-256)
	// privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	privateKey *rsa.PrivateKey
	oauth2     fosite.OAuth2Provider

	jwtStrategy *fositeoauth2.DefaultJWTStrategy
)

func loadPrivateKey(keyFile string) (*rsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read the tls private key '%s': %s", keyFile, err.Error())
	}

	block, _ := pem.Decode(pemBytes)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to extract the private key '%s': %s", keyFile, err.Error())
	}
	return key, nil
}

func RegisterHandlers(oauth2ServerAddrVal string, keyFile string) error {
	var err error
	oauth2ServerAddr = oauth2ServerAddrVal
	privateKey, err = loadPrivateKey(keyFile)
	if err != nil {
		return err
	}
	// Build a fosite instance with all OAuth2 and OpenID Connect handlers enabled, plugging in our configurations as specified above.
	// oauth2 = compose.ComposeAllEnabled(config, store, secret, privateKey)

	// Use JWT tokens instead of opaque HMAC
	jwtStrategy = compose.NewOAuth2JWTStrategy(
		privateKey,
		compose.NewOAuth2HMACStrategy(config, []byte("some-super-cool-secret-that-nobody-knows"), nil),
	)
	strategy := compose.CommonStrategy{
		CoreStrategy:               jwtStrategy,
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(config, privateKey),
	}
	oauth2 = compose.Compose(
		config,
		store,
		strategy,
		nil,

		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2ResourceOwnerPasswordCredentialsFactory,

		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectImplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectRefreshFactory,

		compose.OAuth2TokenIntrospectionFactory,

		compose.OAuth2PKCEFactory,
	)
	// Set up oauth2 endpoints. You could also use gorilla/mux or any other router.
	http.HandleFunc("/oauth2/auth", authEndpoint)
	http.HandleFunc("/oauth2/token", tokenEndpoint)

	// revoke tokens
	http.HandleFunc("/oauth2/revoke", revokeEndpoint)
	http.HandleFunc("/oauth2/introspect", introspectionEndpoint)

	// gitlab style
	http.HandleFunc("/oauth/authorize", authEndpoint)
	http.HandleFunc("/oauth/token", tokenEndpoint)
	http.HandleFunc("/api/v4/user", gitlabUserEndpoint)

	return nil
}

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field

// newSession is a helper function for creating a new session. This may look like a lot of code but since we are
// setting up multiple strategies it is a bit longer.
// Usually, you could do:
//
//  session = new(fosite.DefaultSession)
// func newSession(user, issuer string) *openid.DefaultSession {
func newSession(user, issuer string) *storage.Session {
	// For additional claims: https://www.iana.org/assignments/jwt/jwt.xhtml
	opendidSession := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      issuer, //"https://" + oauth2ServerAddr,
			Subject:     user,
			Audience:    []string{"https://" + oauth2ServerAddr}, // TODO try to get the redirect and make that the audience
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
		Username: user,
		Subject:  user,
	}
	// return opendidSession
	return &storage.Session{
		DefaultSession: opendidSession,
		// ClientID: ,
		Extra: map[string]interface{}{},
	}
}
