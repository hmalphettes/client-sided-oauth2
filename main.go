// Compared with ory/fosite-example:
// - made the client app a separate server to clarify where the oauth2 identity provider stands and where the client app starts
// - focus on the implicit grant
// - extract the user and issuer from the client cert
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hmalphettes/client-sided-oauth2/authorizationserver"
)

var (
	oauth2ServerAddr string
	tlsKeyFile       string
	tlsCertFile      string
	// // A valid oauth2 client (check the store) that additionally requests an OpenID Connect id token
	// clientConf goauth.Config
	// The same thing (valid oauth2 client) but for using the client credentials grant
	// appClientConf clientcredentials.Config
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

	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		clientCerts := req.TLS.PeerCertificates
		var user string
		for _, clientCert := range clientCerts {
			user = clientCert.Subject.CommonName
			fmt.Printf("Hello your username according to the client cert %s\n", user)
			fmt.Printf("Issuer %s\n", clientCert.Issuer)
			break
		}
		rw.Write([]byte(fmt.Sprintf(`Hello '%s', nothing to see here %s`, user, oauth2ServerAddr)))
	})

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
