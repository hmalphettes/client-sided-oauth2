// From ory/fosite-example
// Copyright 2019-2020 Ory

package authorizationserver

import (
	"log"
	"net/http"
)

func introspectionEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	// user, issuer, err := extractUserIssuer(req.TLS.PeerCertificates)
	// if err != nil {
	// 	log.Printf("Error occurred in NewIntrospectionRequest: %+v", err)
	// 	oauth2.WriteIntrospectionError(rw, err)
	// 	return
	// }
	user := ""
	issuer := ""

	mySessionData := newSession(user, issuer)
	ir, err := oauth2.NewIntrospectionRequest(ctx, req, mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewIntrospectionRequest: %+v", err)
		oauth2.WriteIntrospectionError(rw, err)
		return
	}

	oauth2.WriteIntrospectionResponse(rw, ir)
}
