package mattermostusers

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	mattermost "github.com/mattermost/platform/model"
)

var clients map[string]*mattermost.Client4

func makeUnauthenticatedMattermostClient(mattermostURL string) (*mattermost.Client4, error) {
	mmURL, err := url.Parse(mattermostURL)
	if err != nil {
		return nil, err
	}
	mmAddr := mmURL.Scheme + "://" + mmURL.Host
	return mattermost.NewAPIv4Client(mmAddr), nil
}

func getServiceClient(mattermostURL string) (*mattermost.Client4, error) {
	mmURL, err := url.Parse(mattermostURL)
	if err != nil {
		return nil, err
	}
	mmAddr := mmURL.Scheme + "://" + mmURL.Host

	client := clients[mmAddr]
	if client != nil {
		return client, nil
	}
	client = mattermost.NewAPIv4Client(mmAddr)
	mmTokenEnvVar := strings.ReplaceAll(mmURL.Hostname(), ".", "_")
	token := os.Getenv(mmTokenEnvVar)
	if token == "" {
		return nil, fmt.Errorf("Missing environment variable '%s'", mmTokenEnvVar)
	}
	client.SetOAuthToken(token)
	clients[mmAddr] = client
	return client, nil
}

func LookupUser(mattermostURL, usernameOrEmail string) (*mattermost.User, error) {
	client, err := getServiceClient(mattermostURL)
	if err != nil {
		return nil, err
	}
	if strings.Contains(usernameOrEmail, "@") {
		user, _ := client.GetUserByEmail(usernameOrEmail, "")
		return user, nil
	}
	user, _ := client.GetUserByUsername(usernameOrEmail, "")
	return user, nil
}

func ValidateLocalUsernamePassword(mattermostURL, username, password string) (bool, error) {
	client, err := makeUnauthenticatedMattermostClient(mattermostURL)
	if err != nil {
		return false, err
	}
	user, response := client.Login(username, password)
	if response.Error != nil {
		return false, response.Error
	}
	return user != nil, nil
}

func UpdateUserToGitlab(mattermostURL, username, emailAddress string) error {
	client, err := getServiceClient(mattermostURL)
	if err != nil {
		return err
	}
	user, response := client.GetUserByEmail(username, "")
	if response.Error != nil {
		return response.Error
	}
	user.Email = emailAddress
	user.EmailVerified = true
	user.AuthService = mattermost.USER_AUTH_SERVICE_GITLAB
	one := "1"
	user.AuthData = &one // mattermost does not actually use this value and does not require it to be unique. It must not be 0 though.
	user, response = client.UpdateUser(user)
	return response.Error
}
