/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package storage

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/ory/fosite"

	cache "github.com/patrickmn/go-cache"
)

var (
	cacheExpiration    = 5 * time.Minute
	cachePurge         = 4 * time.Minute
	clientSecretHashed []byte
	hasher             = &fosite.BCrypt{}
)

type CacheStore struct {
	Clients        map[string]fosite.Client
	AuthorizeCodes *cache.Cache //map[string]StoreAuthorizeCode
	IDSessions     *cache.Cache //map[string]fosite.Requester
	RefreshTokens  *cache.Cache //map[string]fosite.Requester
	PKCES          *cache.Cache //map[string]fosite.Requester
}

func NewCacheStore() *CacheStore {
	return &CacheStore{
		Clients:        make(map[string]fosite.Client),
		AuthorizeCodes: cache.New(cacheExpiration, cachePurge), //make(map[string]StoreAuthorizeCode),
		IDSessions:     cache.New(cacheExpiration, cachePurge), //make(map[string]fosite.Requester),
		RefreshTokens:  cache.New(cacheExpiration, cachePurge), //make(map[string]fosite.Requester),
		PKCES:          cache.New(cacheExpiration, cachePurge), //make(map[string]fosite.Requester),
	}
}

type StoreAuthorizeCode struct {
	active bool
	fosite.Requester
}

func init() {
	var err error
	clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "foobar"
	}
	hasher := fosite.BCrypt{}
	clientSecretHashed, err = hasher.Hash(nil, []byte(clientSecret))
	if err != nil {
		panic(err)
	}
}

func (s *CacheStore) CreateOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) error {
	s.IDSessions.Set(authorizeCode, requester, cache.DefaultExpiration)
	s.displayCounts("CreateOpenIDConnectSession")
	return nil
}

func (s *CacheStore) GetOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	cl, ok := s.IDSessions.Get(authorizeCode)
	if !ok {
		return nil, fosite.ErrNotFound
	}
	s.displayCounts("GetOpenIDConnectSession")
	return cl.(fosite.Requester), nil
}

func (s *CacheStore) DeleteOpenIDConnectSession(_ context.Context, authorizeCode string) error {
	//delete(s.IDSessions, authorizeCode)
	s.IDSessions.Delete(authorizeCode)
	s.displayCounts("DeleteOpenIDConnectSession")
	return nil
}

// Try passing the callback as the same value than the id.
func (s *CacheStore) GetClient(_ context.Context, id string) (fosite.Client, error) {
	cl, ok := s.Clients[id]
	if ok {
		return cl.(fosite.Client), nil
	}
	redirectURIs := []string{id /*"http://localhost:3846/callback"*/}
	// be nice with gitlab:
	if strings.HasSuffix(id, "/gitlab") {
		redirectURIs = []string{strings.TrimSuffix(id, "/gitlab") + "/signup/gitlab/complete", strings.TrimSuffix(id, "/gitlab") + "/login/gitlab/complete"}
	}

	cl = &fosite.DefaultClient{
		ID:            id,
		Secret:        clientSecretHashed,
		RedirectURIs:  redirectURIs,
		ResponseTypes: []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		GrantTypes:    []string{ /*"implicit", "refresh_token",*/ "authorization_code" /*, "password", "client_credentials"*/}, // could probably restrict a number of use cases
		Scopes:        []string{ /*"fosite", */ "openid" /*, "photos", "offline"*/},
	}
	s.Clients[id] = cl
	return cl.(fosite.Client), nil
}

func (s *CacheStore) ClientAssertionJWTValid(_ context.Context, jti string) error {
	return nil
}

func (s *CacheStore) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	return nil
}

func (s *CacheStore) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	// fmt.Printf("CreateAuthorizeCodeSession for username=%s subject=%s\n", req.GetSession().GetUsername(), req.GetSession().GetSubject())
	s.AuthorizeCodes.Set(code, StoreAuthorizeCode{active: true, Requester: req}, cache.DefaultExpiration)
	s.displayCounts("CreateAuthorizeCodeSession")
	return nil
}

func (s *CacheStore) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.AuthorizeCodes.Get(code)
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if !rel.(StoreAuthorizeCode).active {
		return rel.(StoreAuthorizeCode), fosite.ErrInvalidatedAuthorizeCode
	}
	// sess := rel.Requester.GetSession().(*Session)
	// fmt.Printf("returning the requester for username=%s subject=%s from the authorizeCode. claims: %+v\n",
	// 	sess.GetUsername(), sess.GetSubject(), sess.GetJWTClaims().ToMapClaims())
	s.displayCounts("GetAuthorizeCodeSession")

	return rel.(StoreAuthorizeCode).Requester, nil
}

func (s *CacheStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	rel, ok := s.AuthorizeCodes.Get(code)
	if !ok {
		return fosite.ErrNotFound
	}
	authRel := rel.(StoreAuthorizeCode)
	authRel.active = false
	s.AuthorizeCodes.Set(code, authRel, cache.DefaultExpiration)
	s.displayCounts("InvalidateAuthorizeCodeSession")
	return nil
}

func (s *CacheStore) CreatePKCERequestSession(_ context.Context, code string, req fosite.Requester) error {
	s.PKCES.Set(code, req, cache.DefaultExpiration)
	return nil
}

func (s *CacheStore) GetPKCERequestSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.PKCES.Get(code)
	if !ok {
		return nil, fosite.ErrNotFound
	}
	s.displayCounts("GetPKCERequestSession")
	return rel.(fosite.Requester), nil
}

func (s *CacheStore) displayCounts(msg string) {
	// fmt.Println(msg)
	// fmt.Printf("******** AuthorizeCodes.Count()=%d\n", s.AuthorizeCodes.ItemCount())
	// fmt.Printf("******** IDSessions.Count()=%d\n", s.IDSessions.ItemCount())
	// fmt.Printf("******** PKCES.Count()=%d\n", s.PKCES.ItemCount())
}

func (s *CacheStore) DeletePKCERequestSession(_ context.Context, code string) error {
	s.PKCES.Delete(code)
	return nil
}

func (s *CacheStore) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	return nil
}

func (s *CacheStore) GetAccessTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	return nil, nil
}

func (s *CacheStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	return nil
}

func (s *CacheStore) CreateRefreshTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	return nil
}

func (s *CacheStore) GetRefreshTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	return nil, nil
}

func (s *CacheStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	return nil
}

func (s *CacheStore) Authenticate(_ context.Context, name string, secret string) error {
	// fmt.Println("fosite store - Authenticate is called with " + name + " - " + secret)
	// If you have made it this far then you are OK: the validation is in the verification of the client certificate
	return nil
}

func (s *CacheStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return nil
}

func (s *CacheStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	return nil
}
