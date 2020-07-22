// From ory/fosite-example
// Copyright 2019-2020 Ory

package authorizationserver

import (
	"crypto/rand"
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

const useJWT = true

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
		AccessTokenLifespan: time.Minute * 15, // 15 minutes is more than enough for the auth code flow.
		// ...
	}

	// the state during the auth flows. everything is in memory with a cache and items are expired after a few minutes
	store = storage.NewCacheStore()

	secret     = make([]byte, 32)
	privateKey *rsa.PrivateKey

	oauth2      fosite.OAuth2Provider
	jwtStrategy *fositeoauth2.DefaultJWTStrategy
)

func init() {
	var err error
	// initialize a new rsa key to sign the jwt tokens
	// It will be used if we choose not to pass a stable private key.
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)

	// Initialize a secret to sign the HMAC codes
	_, err = rand.Read(secret)
	if err != nil {
		panic(err)
	}
}

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

func RegisterHandlers(oauth2ServerAddrVal, mattermostServerAddrVal string, keyFile string) error {
	var err error
	oauth2ServerAddr = oauth2ServerAddrVal
	privateKey, err = loadPrivateKey(keyFile)
	if err != nil {
		return err
	}
	// Build a fosite instance with all OAuth2 and OpenID Connect handlers enabled, plugging in our configurations as specified above.
	if !useJWT {
		// currently not fully supported (need to change gitlab_user to resolve the user info from the opaque HMAC token rather than decode the JWT)
		oauth2 = compose.ComposeAllEnabled(config, store, secret, privateKey)
	} else {
		// Use JWT tokens instead of the opaque HMAC
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
	}

	// Set up oauth2 endpoints. You could also use gorilla/mux or any other router.
	// gitlab style as expected by Mattermost
	if mattermostServerAddrVal != "" {
		http.HandleFunc("/oauth/authorize", consentEndpoint)
	} else {
		http.HandleFunc("/oauth/authorize", authEndpoint)
	}
	http.HandleFunc("/oauth/token", tokenEndpoint)
	http.HandleFunc("/api/v4/user", gitlabUserEndpoint)

	// revoke tokens
	http.HandleFunc("/oauth/revoke", revokeEndpoint)
	http.HandleFunc("/oauth/introspect", introspectionEndpoint)

	// Debugging endpoints
	http.HandleFunc("/debug/clientcert", debugClientCertsEndpoint)
	http.HandleFunc("/debug/clientcertuser", debugClientCertGitlabUserEndpoint)

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
func newSession(user, email, issuer string) *storage.Session {
	// For additional claims: https://www.iana.org/assignments/jwt/jwt.xhtml
	opendidSession := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      issuer, //"https://" + oauth2ServerAddr,
			Subject:     email,
			Audience:    []string{"https://" + oauth2ServerAddr}, // TODO try to get the redirect and make that the audience
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
			Extra:       map[string]interface{}{},
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
		Username: email,
		Subject:  email,
	}
	// return opendidSession
	session := &storage.Session{
		DefaultSession: opendidSession,
		Extra:          map[string]interface{}{},
	}
	return session
}
