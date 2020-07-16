package mattermostusers

import (
	"fmt"
	"net/http"
	"os"

	mattermost "github.com/mattermost/platform/model"
)

/**
This consent page is geared at using the client certificate to authenticate a user.
It makes sure that a corresponding mattermost user is registered with the same email address.

When that is not the case, it offers to either create a new user or login an existing user and update its email address.
*/

const loginForm = `<form method="post" class="form-example">
<div class="form">
  <label for="username">Enter your username: </label>
  <input type="text" name="username" id="username" required>
</div>
<div class="form">
  <label for="email">Enter your password: </label>
  <input type="password" name="password" id="password" required>
</div>
<div class="form">
  <input type="submit" value="Submit">
</div>
</form>
`

var downstreamServer = os.Getenv("DOWNSTREAM_SERVER_ADDR")

/**
Meant to be the oauth/authorize endpoint that starts an Authorize Code Grant Flow
*/
func consentEndpoint(rw http.ResponseWriter, req *http.Request) {
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
	ctx := req.Context()

	user, email, issuer, err := extractUserEmailIssuer(req.TLS.PeerCertificates)

	if email == "" {
		consentNoClientCert(rw, req)
		return
	}

	mmUser, err := LookupUser(downstreamServer, email)
	if mmUser == nil {
		consentNoSuchUserCreateNewOrLinkExisting(email, rw, req)
		return
	}
	consentLoginWithEmailAddress(mmUser, rw, req)
}

func consentNoClientCert(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "text/html")
	rw.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<body>
<p>
No Client Certificate Received by the server.<br/>
Please login with a username and password
</p>
` + loginForm + `
</body>
</html>
`)))
}

func consentLoginWithEmailAddress(mmUser *mattermost.User, rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "text/html")
	rw.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<body>
<p>
<form>
<div class="form">
  <label for="Login">Login %s - %s</label>
  <input type="submit" value="Login">
</div>
</form>
</p>
</body>
</html>
`, mmUser.Name, mmUser.EmailAddress)))
}

func consentNoSuchUserCreateNewOrLinkExisting(emailWithoutAccount string, rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "text/html")
	rw.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<body>
<p>
No Mattermost account is configured with the email %s.
</p>
<p>
Please choose:
<p>
<form>
<div class="form">
  <input type="submit" value="Create New User">
</div>
</form>
</p>
<p>
Login and link an existing account to this email address:
%s
</p>
</body>
</html>
`, email, loginForm)))
}

/**
Understand when to:
- create a new user.
- login an existing user.
- login and update the email address of a user.
*/
func consentPostEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()
	err := req.ParseForm()
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte(`Error parsing the form ` + err.Error()))
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(`TODO: process!`))
}
