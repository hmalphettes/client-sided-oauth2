package authorizationserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type GitLabUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Login    string `json:"login"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

func makeGitlabUser(claims jwt.MapClaims) (*GitLabUser, error) {
	// TODO: connect to the mattermost database and do match the sub to the actual user or create it.
	user := claims["sub"].(string)
	return &GitLabUser{
		ID:       123,
		Username: user,
		Login:    user,
		Email:    user + "@your-gitlab.com",
		Name:     user,
	}, nil
}

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
