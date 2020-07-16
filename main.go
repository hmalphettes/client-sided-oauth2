// Compared with ory/fosite-example:
// - made the client app a separate server to clarify where the oauth2 identity provider stands and where the client app starts
// - focus on the implicit grant
// - extract the user and issuer from the client cert
package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/hmalphettes/client-sided-oauth2/authorizationserver"
)

var (
	oauth2ServerAddr string
	tlsKeyFile       string
	tlsCertFile      string
	downstreamAddr   string // optional reverse proxied server
)

func init() {
	oauth2ServerAddr = os.Getenv("OAUTH2_SERVER_ADDR")
	if oauth2ServerAddr == "" {
		oauth2ServerAddr = "localhost:3846"
	} else if strings.HasPrefix("https://", oauth2ServerAddr) {
		oauth2ServerAddr = strings.TrimPrefix("https://", oauth2ServerAddr)
	}
	tlsKeyFile = os.Getenv("OAUTH2_TLS_KEY")
	if tlsKeyFile == "" {
		tlsKeyFile = ".keys/localhost.key"
	}
	tlsCertFile = os.Getenv("OAUTH2_TLS_CRT")
	if tlsCertFile == "" {
		tlsCertFile = ".keys/localhost-with-chain.crt"
	}
	downstreamAddr = os.Getenv("DOWNSTREAM_SERVER_ADDR")
}

func main() {
	_, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		log.Fatalf("Unable to open the tls files tlsCertFile=%s; tlsKeyFile=%s\n", tlsCertFile, tlsKeyFile)
		return
	}

	// ### oauth2 server ###
	err = authorizationserver.RegisterHandlers(oauth2ServerAddr, tlsKeyFile) // the authorization server (fosite)
	if err != nil {
		log.Fatal(err.Error())
		return
	}

	http.HandleFunc("/welcome", welcomeEndpoint)
	if downstreamAddr == "" {
		http.HandleFunc("/", welcomeEndpoint)
	} else {
		origin, _ := url.Parse(downstreamAddr)
		director := func(req *http.Request) {
			req.Header.Add("X-Forwarded-Host", req.Host)
			req.Header.Add("X-Origin-Host", origin.Host)
			if strings.HasPrefix(downstreamAddr, "https://") {
				req.URL.Scheme = "https"
			} else {
				req.URL.Scheme = "http"
			}
			req.URL.Host = origin.Host
			req.Host = origin.Host
		}
		proxy := &httputil.ReverseProxy{Director: director}

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})
	}

	server := &http.Server{
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
			MinVersion: tls.VersionTLS12,
		},
		Addr: oauth2ServerAddr,
	}

	fmt.Printf("The client-sided-oauth2 identity provider is running on https://%s\n", oauth2ServerAddr)
	log.Fatal(server.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
}

func welcomeEndpoint(rw http.ResponseWriter, req *http.Request) {
	clientCerts := req.TLS.PeerCertificates
	var user, emailAddress, fullDN string

	for _, clientCert := range clientCerts {
		user = clientCert.Subject.CommonName

		fmt.Printf("Hello your username according to the client cert %s\n", user)
		fmt.Printf("Issuer %s\n", clientCert.Issuer)

		// golang does not decode the DC and userid
		// we get to do that ourselves: https://stackoverflow.com/questions/39125873/golang-subject-dn-from-x509-cert/50640119#50640119
		var subject pkix.RDNSequence
		if _, err := asn1.Unmarshal(clientCert.RawSubject, &subject); err != nil {
			fmt.Printf("WARN: unable to parse the RawSubject %s\n", err.Error())
			continue
		}
		fmt.Printf("Subject %s\n", subject.String())
		userInfo, err := authorizationserver.NewClientCertUserInfo(clientCert)
		fmt.Printf("userInfo %+v. err=%v\n", userInfo, err)
		emailAddress = userInfo.EmailAddress
		fullDN = userInfo.FullDN
		break
	}
	rw.Write([]byte(fmt.Sprintf(`<h1>Welcome to the client-sided-oauth of %s</h1>
	<h2>What is this?</h2>
	<h4>Oauth2 Identity Provider via a Client Certificate</h4>
	<p>This is an oauth2 server with support for an "Authorization Code Grant Flow".<br/>It uses a full fledged oauth2 SDK and may support other flows.</p>
	<p>User authentication and identity relies on a client certificate configure on the browser and passed to the server</p>
	<p>The client certificate is derived into a user profile and encoded into a JWT token that is used as the access token.</p>
	<p>There is no standard for a user record and there is no standard to deriving a user record from a client certificate.</p>
	
	<p>Feel free to fork this and suggest something else.</p>
	<h4>Mattermost Gitlab Authentication Side Car</h4>
	<p>
		The scenario primarily targeted here is to be a Gitlab authentication provider for Mattermost.
	</p>
	<p>
		To configure Mattermost to take advantage of this:
		<ol>
			<li>Browse to the System Console and select "Gitlab"</li>
			<li>Application ID: '<your-mattermost-url>/gitlab'</li>
			<li>Application Secret Key: 'foobar' - it is hardcoded at the moment</li>
			<li>Gitlab site URL: %s</li>
		</ol>
	</p>
	<p>
		There is no registration of a client ID and redirection URLs.
		This server derives the callbacks according to the Application ID.
		All other parameters are hardcoded.
	</p>

	<h2>Your infomation shared to us via a client certificate</h2>
	<p>Hello '%s' - %s - %s</p>
	<ul>
		<li><a href="debug/clientcert">Check the client certs passed here</a></li>
		<li><a href="debug/clientcertuser">Check the gitlab user derived from the selected client cert</a></li>
	</ul>
	`, oauth2ServerAddr, oauth2ServerAddr, user, emailAddress, fullDN)))
}
