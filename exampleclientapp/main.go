package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"encoding/json"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/hmalphettes/client-sided-oauth2/oauth2client"
	"golang.org/x/net/context"
	goauth "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// The following provides the setup required for the client to perform the "Authorization Code" flow with PKCE in order
// to obtain an access token for public/untrusted clients.
const cookiePKCE = "isPKCE"

var (
	appServerAddr    string
	oauth2ServerAddr string
	// A valid oauth2 client (check the store) that additionally requests an OpenID Connect id token
	clientConf goauth.Config
	// The same thing (valid oauth2 client) but for using the client credentials grant
	appClientConf clientcredentials.Config
)

func init() {
	oauth2ServerAddr = os.Getenv("OAUTH2_SERVER_ADDR")
	if oauth2ServerAddr == "" {
		oauth2ServerAddr = "https://localhost:3846"
	}
	appServerAddr = os.Getenv("APP_SERVER_ADDR")
	if appServerAddr == "" {
		appServerAddr = "http://localhost:8080"
	}
	clientConf = goauth.Config{
		ClientID:     appServerAddr + "/callback", // id is the same than the callback so that we dont register the client conf before hand
		ClientSecret: "foobar",
		RedirectURL:  appServerAddr + "/callback",
		Scopes:       []string{"photos", "openid", "offline"},
		Endpoint: goauth.Endpoint{
			TokenURL: oauth2ServerAddr + "/oauth/token",
			AuthURL:  oauth2ServerAddr + "/oauth/authorize",
		},
	}

	appClientConf = clientcredentials.Config{
		ClientID:     appServerAddr + "/callback",
		ClientSecret: "foobar",
		Scopes:       []string{"fosite"},
		TokenURL:     oauth2ServerAddr + "/oauth/token",
	}
}

func main() {
	// ### oauth2 client ###
	http.HandleFunc("/", oauth2client.HomeHandler(clientConf)) // show some links on the index

	// the following handlers are oauth2 consumers
	http.HandleFunc("/client", oauth2client.ClientEndpoint(appClientConf)) // complete a client credentials flow
	http.HandleFunc("/callback", oauth2client.CallbackHandler(clientConf)) // the oauth2 callback endpoint

	// ### protected resource ###
	http.HandleFunc("/protected", ProtectedEndpoint(appClientConf))

	port := strings.Split(appServerAddr, ":")[2]

	fmt.Println("Please open your webbrowser at " + appServerAddr)
	// _ = exec.Command("open", appServerAddr).Run()
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

/*
func HomeHandler(c goauth.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			// The "/" pattern matches everything, so we need to check that
			// we're at the root here.
			return
		}
		redirectURL := url.QueryEscape(appServerAddr + "/callback")

		rw.Write([]byte(fmt.Sprintf(`
		<p>Obtain an access token with</p>
		<ul>
			<li>
				<a href="%s">Implicit grant (with OpenID Connect)</a>
			</li>
		</ul>`,
			oauth2ServerAddr+"/oauth2/auth?client_id="+redirectURL+"&redirect_uri="+redirectURL+"&response_type=token&scope=fosite%20openid&state=some-random-state-foobar&nonce=some-random-nonce",
		)))
	}
}*/

type session struct {
	User string
}

func ProtectedEndpoint(c clientcredentials.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		resp, err := c.Client(context.Background()).PostForm(strings.Replace(c.TokenURL, "token", "introspect", -1), url.Values{"token": []string{req.URL.Query().Get("token")}, "scope": []string{req.URL.Query().Get("scope")}})
		if err != nil {
			fmt.Fprintf(rw, "<h1>An error occurred!</h1><p>Could not perform introspection request: %v</p>", err)
			return
		}
		defer resp.Body.Close()

		var introspection = struct {
			Active bool `json:"active"`
		}{}
		out, _ := ioutil.ReadAll(resp.Body)
		if err := json.Unmarshal(out, &introspection); err != nil {
			fmt.Fprintf(rw, "<h1>An error occurred!</h1>%s\n%s", err.Error(), out)
			return
		}

		if !introspection.Active {
			fmt.Fprint(rw, `<h1>Request could not be authorized.</h1>
<a href="/">return</a>`)
			return
		}

		fmt.Fprintf(rw, `<h1>Request authorized!</h1>
<code>%s</code><br>
<hr>
<a href="/">return</a>
`,
			out,
		)
	}
}
