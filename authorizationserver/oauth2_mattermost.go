package authorizationserver

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hmalphettes/client-sided-oauth2/storage"
	mattermost "github.com/mattermost/platform/model"
	"github.com/ory/fosite"
)

const (
	actionTypeCreateNewUserFromClientCert                        = "createNewUserFromClientCert"
	actionTypeLoginExistingUserWithEmailAddressFromClientCert    = "loginExistingUserWithEmailAddressFromClientCert"
	actionTypeLoginUsernamePasswordNoEmailUpdate                 = "loginUsernamePasswordNoEmailUpdate"
	actionTypeLoginUsernamePasswordWithEmailUpdateFromClientCert = "loginUsernamePasswordWithEmailUpdateFromClientCert"
	style                                                        = `<style type="text/css">
body {
	font-family: "Open Sans", sans-serif
}
</style>`
)

/**
This consent page is geared at using the client certificate to authenticate a user.
It makes sure that a corresponding mattermost user is registered with the same email address.

When that is not the case, it offers to either create a new user or login an existing user and update its email address.
*/

func makeFormInputsFromQueryString(request *http.Request) string {
	extras := []string{}
	for name, values := range request.URL.Query() {
		extras = append(extras, fmt.Sprintf(`<input type="hidden" name="%s" value="%s"/>`, name, values[0]))
	}
	return strings.Join(extras, "\n")
}

func loginFormNoEmailUpdate(request *http.Request) string {
	return fmt.Sprintf(`<form method="post">
%s
<input type="hidden" name="actionType" value="%s"/>
<table boder="0">
<tr>
  <td><label for="username">Enter the mattermost username: </label></td>
  <td><input type="text" name="username" required></td>
</tr>
<tr>
  <td><label for="password">Enter the mattermost password: </label></td>
  <td><input type="password" name="password" required></td>
</tr>
<tr>
	<td><input type="submit" value="Submit"></td>
</tr>
</table>
</form>
`, makeFormInputsFromQueryString(request), actionTypeLoginUsernamePasswordNoEmailUpdate)
}

func loginFormAndUpdateEmailFromClientCert(emailFromCert string, request *http.Request) string {
	return fmt.Sprintf(`<form method="post">
%s
<input type="hidden" name="actionType" value="%s"/>
<table border="0">
<tr>
  <td><label for="username">Mattermost username: </label></td>
  <td><input type="text" name="username" required></td>
</tr>
<tr>
  <td><label for="password">Mattermost password: </label></td>
  <td><input type="password" name="password" required></td>
</tr>
<tr>
	<td><label for="email">Email: </label></td>
	<td><input type="text" name="email" placeholder="%s" readonly></td>
</tr>
<tr>
  <td><input type="submit" value="Login and update email"></td>
</tr>
</table>
</form>
`, makeFormInputsFromQueryString(request), actionTypeLoginUsernamePasswordWithEmailUpdateFromClientCert, emailFromCert)
}

func createNewUserFromClientCert(request *http.Request) string {
	return fmt.Sprintf(`<form method="post">
%s
<input type="hidden" name="actionType" value="%s"/>
<div>
  <input type="submit" value="Login and update with the email address of the client cert">
</div>
</form>
`, makeFormInputsFromQueryString(request), actionTypeCreateNewUserFromClientCert)
}

/**
Meant to be the oauth/authorize endpoint that starts an Authorize Code Grant Flow
*/
func consentEndpoint(rw http.ResponseWriter, req *http.Request) {
	fmt.Printf("You have reached the consentEndpoint with %s\n", req.Method)
	if req.Method == "GET" {
		consentGetEndpoint(rw, req)
		return
	}
	if req.Method == "POST" {
		consentPostEndpoint(rw, req)
		return
	}
	rw.WriteHeader(http.StatusMethodNotAllowed)
	rw.Write([]byte(`Unexpected method ` + req.Method))
}

/**
This endpoint handles the following cases:
- if no client cert is passed: display the login form with an explaination
- if the extracted email matches a user record, display it and a button to confirm to login with this user record
- if the extracted email does not match a user record offer to
  - create a new user derived from that email address
  - login with an existing account and update the email address to match the one identified by the client certificate
*/
func consentGetEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	// ctx := req.Context()
	_, email, _, _ := storage.ExtractUserEmailIssuer(req.TLS.PeerCertificates)

	if email == "" {
		consentNoClientCert(rw, req)
		return
	}

	mmUser, err := LookupUser(email)
	if err != nil {
		rw.WriteHeader(http.StatusServiceUnavailable)
		rw.Write([]byte(fmt.Sprintf(`Failed to lookup the user %s on the Mattermost server %s: %s`, email, mattermostServer, err.Error())))
		return
	}
	if mmUser == nil {
		consentNoSuchUserCreateNewOrLinkExisting(email, rw, req)
		return
	}
	consentLoginExistingUserWithEmailAddressFromClientCert(mmUser, rw, req)
}

func consentNoClientCert(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<body>
%s
<p>
No Client Certificate Received by the server.<br/>
<!--Please login with a username and password
</p>
%s -->
</body>
</html>
`, style, loginFormNoEmailUpdate(req))))
}

func consentLoginExistingUserWithEmailAddressFromClientCert(mmUser *mattermost.User, rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<body>
%s
<h1>Mattermost authentication</h1>
<p>
<form method="post">
%s
<input type="hidden" name="actionType" value="%s"/>
<div style="margin: 50px;">
  <div style="padding-bottom: 20px;">
  There is an existing mattermost account for the email address %s
  </div>

  <table border="0">
  <tr>
	<td><label for="username">Mattermost username: </label></td>
	<td><input type="text" name="username" placeholder="%s" required readonly></td>
  </tr>
  <tr>
	  <td><label for="email">Email: </label></td>
	  <td><input type="text" name="email" placeholder="%s" readonly></td>
  </tr>
  <tr>
	<td></td>
	<td><input type="submit" value="Login"></td>
  </tr>
  </table>

</div>
</form>
</p>
</body>
</html>
`, style, makeFormInputsFromQueryString(req), actionTypeLoginExistingUserWithEmailAddressFromClientCert, mmUser.Email, mmUser.Username, mmUser.Email)))
}

func consentNoSuchUserCreateNewOrLinkExisting(emailWithoutAccount string, rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<body>
%s
<h1>Mattermost authentication</h1>
<p>
The email %s is not linked to an existing Mattermost Account.
</p>
<p>
Would you like to:
<div style="height:150px;">
	<a href="#"
		onClick="document.getElementById('loginUsernamePasswordWithEmailUpdateFromClientCert').hidden=false;document.getElementById('createNewUserFromClientCert').hidden=true">
		Link the email %s to an existing user account</a>
	<div id="loginUsernamePasswordWithEmailUpdateFromClientCert" hidden="true" style="margin-left: 50px;">
	%s
	</div>
</div>
<div style="height:100px;">
<a href="#"onClick="document.getElementById('loginUsernamePasswordWithEmailUpdateFromClientCert').hidden=true;document.getElementById('createNewUserFromClientCert').hidden=false">
	Create a new user for the email %s</a>
<div id="createNewUserFromClientCert" hidden="true" style="margin-left: 50px;">

	<input type="hidden" name="actionType" value="createNewUserFromClientCert"/>

	<table boder="0">
	<tr>
	  <td><label for="username">Mattermost username:</label></td>
	  <td><input type="text" name="username" placeholder="%s" readonly></td>
	</tr>
	<tr>
	  <td><label for="email">Email: </label></td>
	  <td><input type="text" name="email" placeholder="%s" readonly></td>
	</tr>
	<tr>
		<td>
			<form method="post">
				%s
				<input type="submit" value="Submit">
			</form>
		</td>
	</tr>
	</table>


</div>
</div>

</body>
</html>
`, style, emailWithoutAccount, emailWithoutAccount, loginFormAndUpdateEmailFromClientCert(emailWithoutAccount, req), emailWithoutAccount, strings.Split(emailWithoutAccount, "@")[0], emailWithoutAccount, makeFormInputsFromQueryString(req))))
}

/**
Understand when to:
- create a new user; actionType:createNewUserWithEmailAddress
- login an existing user; actionType:loginExistingUserWithEmailAddressFromClientCert
- login and update the email address of a user; actionType:loginExistingUserByPasswordAndUpdateEmailAddress
*/
func consentPostEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()
	err := req.ParseForm()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(`Error parsing the form ` + err.Error()))
	}

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %+v", err)
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}
	// fmt.Printf("Got an ar in consentPostEndpoint, %+v\n", ar)

	scopes := []string{"openid"}
	actionType := req.PostForm.Get("actionType")
	// fmt.Printf("Got actionType=%s in consentPostEndpoint\n", actionType)

	if actionType == "" {
		oauth2.WriteAuthorizeError(rw, ar, fmt.Errorf("Missing actionType"))
		return
	}

	var mmUser *mattermost.User

	if actionType == actionTypeLoginUsernamePasswordNoEmailUpdate || actionType == actionTypeLoginUsernamePasswordWithEmailUpdateFromClientCert {
		userFromForm := req.PostForm.Get("username")
		passwordFromForm := req.PostForm.Get("password")
		if userFromForm == "" {
			http.Error(rw, "Missing username from form", http.StatusBadRequest)
			return
		}
		if passwordFromForm == "" {
			http.Error(rw, "The password is required", http.StatusForbidden)
			return
		}
		mmUser, err = LookupUser(userFromForm)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		if mmUser == nil {
			http.Error(rw, fmt.Sprintf("No such mattermost user %s or wrong password", userFromForm), http.StatusForbidden)
			return
		}
		validated, err := ValidateLocalUsernamePassword(mmUser, passwordFromForm)
		if err != nil {
			http.Error(rw, fmt.Sprintf("No such mattermost user %s or wrong password: %s", userFromForm, err.Error()), http.StatusForbidden)
			return
		}
		if !validated {
			http.Error(rw, fmt.Sprintf("No such mattermost user %s or wrong password.", userFromForm), http.StatusForbidden)
			return
		}
		if actionType == actionTypeLoginUsernamePasswordWithEmailUpdateFromClientCert {
			_, emailFromCert, _, err := storage.ExtractUserEmailIssuer(req.TLS.PeerCertificates)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusForbidden)
				return
			}
			if emailFromCert == "" {
				http.Error(rw, "No email extracted from the clent certificate", http.StatusForbidden)
				return
			}
			err = UpdateUserToGitlab(mmUser, emailFromCert)
			if err != nil {
				http.Error(rw, fmt.Sprintf("Failed to update the mattermost user %s with the email %s: %s", mmUser.Username, emailFromCert, err.Error()), http.StatusBadRequest)
				return
			}
		} else {
			// we still need to switch the user to use gitlab:
			err = UpdateUserToGitlab(mmUser, "")
			if err != nil {
				http.Error(rw, fmt.Sprintf("Failed to update the mattermost user %s to the gitlab authentication: %s", mmUser.Username, err.Error()), http.StatusBadRequest)
				return
			}
		}
		completeOAuthCodeGrantForMattermost(ar, scopes, mmUser, rw, req, false)
		return
	} else if actionType == actionTypeLoginExistingUserWithEmailAddressFromClientCert || actionType == actionTypeCreateNewUserFromClientCert {
		userFromCert, emailFromCert, _, err := storage.ExtractUserEmailIssuer(req.TLS.PeerCertificates)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusForbidden)
			return
		}
		if emailFromCert == "" {
			http.Error(rw, "No email extracted from the clent certificate", http.StatusForbidden)
			return
		}
		mmUser, err = LookupUser(emailFromCert)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		if actionType == actionTypeLoginExistingUserWithEmailAddressFromClientCert {
			if mmUser == nil {
				http.Error(rw, fmt.Sprintf("No such mattermost user %s", userFromCert), http.StatusNotFound)
				return
			}
			err = UpdateUserToGitlab(mmUser, emailFromCert)
			if err != nil {
				fmt.Printf("We are here %+v\n", err)
				http.Error(rw, fmt.Sprintf("Failed to update the mattermost user %s with the email %s: %s", mmUser.Username, emailFromCert, err.Error()), http.StatusBadRequest)
				return
			}
			completeOAuthCodeGrantForMattermost(ar, scopes, mmUser, rw, req, false)
			return
		}
		// Create new user
		if mmUser != nil {
			http.Error(rw, fmt.Sprintf("A mattermost user with the email %s already exist. Cannot create a new one.", userFromCert), http.StatusBadRequest)
			return
		}
		if mmUser, err = CreateUser(emailFromCert); err != nil {
			http.Error(rw, fmt.Sprintf("Unable to create a mattermost user with the email %s: %s", userFromCert, err.Error()), http.StatusBadRequest)
			return
		}
		// Add the user to the default team.

		completeOAuthCodeGrantForMattermost(ar, scopes, mmUser, rw, req, true)
		return
	} else {
		http.Error(rw, fmt.Sprintf("Unexpected action type %s", actionType), http.StatusForbidden)
		return
	}
}

func completeOAuthCodeGrantForMattermost(ar fosite.AuthorizeRequester, scopes []string, mmUser *mattermost.User, rw http.ResponseWriter, req *http.Request, isSignup bool) {
	signupOrLogin := "login"
	loginOrSignup := "signup"
	if isSignup {
		signupOrLogin = "signup"
		loginOrSignup = "login"
	}
	if !strings.Contains(ar.GetRedirectURI().Path, signupOrLogin) {
		ar.GetRedirectURI().Path = strings.ReplaceAll(ar.GetRedirectURI().Path, loginOrSignup, signupOrLogin)
		fmt.Printf("RedirectURI: replaced the %s in redirect URL by %s %+v\n", loginOrSignup, signupOrLogin, ar.GetRedirectURI())
	}
	fmt.Println("completeOAuthCodeGrant for " + mmUser.Email)
	completeOAuthCodeGrant(ar, scopes, mmUser.Username, mmUser.Email, os.Getenv("MATTERMOST_SERVER_ADDR"), rw, req)
}
