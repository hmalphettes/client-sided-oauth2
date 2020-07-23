package authorizationserver

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	mattermost "github.com/mattermost/platform/model"
)

// export MATTERMOST_SERVER_ADDR=http://localhost:8065
// export MATTERMOST_BOT=botbot
// export MATTERMOST_BOT_TOKEN=hfeapgroftnefmj966rzib9wfw

var (
	mattermostServer   = os.Getenv("MATTERMOST_SERVER_ADDR")
	mattermostBot      = os.Getenv("MATTERMOST_BOT")
	mattermostBotToken = os.Getenv("MATTERMOST_BOT_TOKEN")

	theClient *mattermost.Client4

	teamIDs = make(map[string]string) // Team name - > Team ID

	insecureTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
)

func makeUnauthenticatedMattermostClient() (*mattermost.Client4, error) {
	mmURL, err := url.Parse(mattermostServer)
	if err != nil {
		return nil, err
	}
	mmAddr := mmURL.Scheme + "://" + mmURL.Host
	client := mattermost.NewAPIv4Client(mmAddr)
	serviceClient, err := getServiceClient()
	if err != nil {
		return nil, err
	}
	client.HttpClient = serviceClient.HttpClient
	return client, nil
}

func getServiceClient() (*mattermost.Client4, error) {
	mmURL, err := url.Parse(mattermostServer)
	if err != nil {
		return nil, err
	}
	mmAddr := mmURL.Scheme + "://" + mmURL.Host

	if theClient != nil {
		return theClient, nil
	}
	theClient = mattermost.NewAPIv4Client(mmAddr)
	theClient.HttpClient = &http.Client{
		Timeout:   time.Second * 10,
		Transport: insecureTransport,
	}
	token := os.Getenv("MATTERMOST_BOT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("Missing environment variable 'MATTERMOST_BOT_TOKEN'")
	}
	theClient.SetOAuthToken(token)
	return theClient, nil
}

func LookupUser(usernameOrEmail string) (*mattermost.User, error) {
	fmt.Printf("Lookup the mm user %s\n", usernameOrEmail)
	client, err := getServiceClient()
	if err != nil {
		return nil, err
	}
	if strings.Contains(usernameOrEmail, "@") {
		user, response := client.GetUserByEmail(usernameOrEmail, "")
		if response.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		if response.Error != nil {
			return nil, response.Error
		}
		return user, nil
	}
	user, response := client.GetUserByUsername(usernameOrEmail, "")
	fmt.Printf("GetUserByUsername Response %+v\n", response)
	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if response.Error != nil {
		return nil, response.Error
	}
	return user, nil
}

func ValidateLocalUsernamePassword(mmUser *mattermost.User, password string) (bool, error) {
	client, err := makeUnauthenticatedMattermostClient()
	if err != nil {
		return false, err
	}
	user, response := client.LoginById(mmUser.Id, password)
	fmt.Printf("ValidateLocalUsernamePassword of %s returned %+v - %+v\n", mmUser.Email, user, response)
	if response.Error != nil {
		return false, response.Error
	}
	return user != nil, nil
}

func UpdateUserToGitlab(mmUser *mattermost.User, emailAddress string) error {
	if emailAddress == "" {
		emailAddress = mmUser.Email
	}
	// if mmUser.Email == emailAddress && mmUser.AuthService == mattermost.USER_AUTH_SERVICE_GITLAB && mmUser.Password == "" {
	// 	return nil
	// }
	// fmt.Println("Need to update " + mmUser.Email + " != " + emailAddress + " OR " + mmUser.AuthService + " != " + mattermost.USER_AUTH_SERVICE_GITLAB)
	client, err := getServiceClient()
	if err != nil {
		return err
	}
	gitlabUserID := strings.Split(emailAddress, "@")[0]
	/*
		&mattermost.User{
			Id:          mmUser.Id,
			Email:       emailAddress,
			AuthService: mattermost.USER_AUTH_SERVICE_GITLAB,
			AuthData:    &gitlabUserID,
		}
	*/
	mmUser.Email = emailAddress
	mmUser.AuthService = mattermost.USER_AUTH_SERVICE_GITLAB
	mmUser.AuthData = &gitlabUserID
	mmUser.Password = ""
	mmUser, response := client.UpdateUser(mmUser)
	if response.Error == nil {
		fmt.Printf("Updated mmUser %+v\n", mmUser)
		fmt.Println("  GetUserRoute = " + client.GetUserRoute(mmUser.Id))
		return nil
	}
	if mmUser.AuthService != mattermost.USER_AUTH_SERVICE_GITLAB {
		return fmt.Errorf("Failed to update the Auth data of Mattermost. At the moment this code relies on github.com/mattermost-server/store/sql_store/userstore.go#Update to not igore AuthData, AuthService and Password")
	}
	return response.Error
}

func CreateUser(email string) (*mattermost.User, error) {
	client, err := getServiceClient()
	if err != nil {
		return nil, err
	}
	username := strings.Split(email, "@")[0]
	// user, _ := client.GetUserByUsername(username, "")
	// if user != nil {
	// 	username = strings.ReplaceAll(email, "@", "-")
	// }
	user, response := client.CreateUser(&mattermost.User{
		Username:    username,
		Email:       email,
		AuthService: mattermost.USER_AUTH_SERVICE_GITLAB,
		AuthData:    &username,
	})
	if response.Error == nil {
		return user, nil
	}
	return user, response.Error
}

func AddUserToTeam(mmUser *mattermost.User, teamName string) error {
	client, err := getServiceClient()
	if err != nil {
		return err
	}
	teamID := teamIDs[teamName]
	if teamID == "" {
		team, response := client.GetTeamByName(teamName, "")
		if response.Error != nil {
			return response.Error
		}
		teamID = team.Id
		teamIDs[teamID] = teamName
	}
	_, response := client.AddTeamMember(teamID, mmUser.Id)
	if response.Error != nil {
		return response.Error
	}
	return nil
}
