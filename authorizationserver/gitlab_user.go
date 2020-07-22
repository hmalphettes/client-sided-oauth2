package authorizationserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/hmalphettes/client-sided-oauth2/storage"
)

// These fields are the ones that Mattermost expects
// Other fields in Gitlab: https://docs.gitlab.com/ee/api/users.html#single-user
type GitLabUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Login    string `json:"login"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

func makeGitlabUser(claims jwt.MapClaims) (*GitLabUser, error) {
	// TODO: connect to the mattermost database and do match the sub to the actual user or create it.
	email := claims["sub"].(string)
	user := strings.Split(email, "@")[0]
	fmt.Printf("Serving a Gitlab user for %s\n", email)
	var id int64
	idA, err := strconv.Atoi(user)
	if err != nil {
		id = time.Now().Unix()
	} else {
		id = int64(idA)
	}

	if mattermostServer != "" {
		mmUser, err := LookupUser(email)
		if err != nil {
			return nil, err
		}
		if mmUser != nil {
			return &GitLabUser{
				ID:       id,
				Username: mmUser.Username,
				Login:    mmUser.Username,
				Email:    email,
				Name:     mmUser.Username,
			}, nil
		}
	}

	return &GitLabUser{
		ID:       id,
		Username: user,
		Login:    user,
		Email:    email,
		Name:     user,
	}, nil
}

// This is purely for debugging
func makeGitlabUserFromCert(clientCert *x509.Certificate) (*GitLabUser, error) {
	fmt.Println("makeGitlabUserFromCert is called")
	userInfo, err := storage.NewClientCertUserInfo(clientCert)
	if err != nil {
		return nil, err
	}
	user := strings.Split(userInfo.EmailAddress, "@")[0]
	var id int64
	idA, err := strconv.Atoi(user)
	if err != nil {
		id = time.Now().Unix()
	} else {
		id = int64(idA)
	}
	return &GitLabUser{
		ID:       id,
		Username: userInfo.CommonName,
		Login:    userInfo.CommonName,
		Email:    userInfo.EmailAddress,
		Name:     userInfo.CommonName,
	}, nil
}

// Gitlab user endpoint expected to be mapped as /api/v4/user
func gitlabUserEndpoint(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	authorization := req.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(`Invalid authorization header. Expected it to be a Bearer`))
		return
	}
	bearer := strings.TrimPrefix(authorization, "Bearer ")
	token, err := jwtStrategy.Decode(context.Background(), bearer)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(err.Error()))
		return
	}
	gitLabUser, err := makeGitlabUser(token.Claims.(jwt.MapClaims))
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(err.Error()))
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(gitLabUser)
}

// Displays the ClientCerts Info
func debugClientCertsEndpoint(rw http.ResponseWriter, req *http.Request) {
	fmt.Println("debugClientCertsEndpoint is called")
	rw.Header().Set("Content-Type", "application/json")
	for _, clientCert := range req.TLS.PeerCertificates {
		userInfo, err := storage.NewClientCertUserInfo(clientCert)
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte(fmt.Sprintf(`Error parsing the client cert: %s`, err)))
			return
		}

		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(userInfo)
		return
	}
	rw.WriteHeader(http.StatusBadRequest)
	rw.Write([]byte(`No Client Certificate`))
	return
}

// Generate a GitlabUser from the Client Certs. Check what kind of user gets identified from the clientcert
func debugClientCertGitlabUserEndpoint(rw http.ResponseWriter, req *http.Request) {
	fmt.Println("debugClientCertGitlabUserEndpoint is called")
	rw.Header().Set("Content-Type", "application/json")
	for _, clientCert := range req.TLS.PeerCertificates {
		gitlabUser, err := makeGitlabUserFromCert(clientCert)
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte(fmt.Sprintf(`Error parsing the cert: %s`, err)))
			return
		}

		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(gitlabUser)
		return
	}
	rw.WriteHeader(http.StatusBadRequest)
	rw.Write([]byte(`Missing Client Certificate`))
}
