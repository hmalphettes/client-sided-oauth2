package oauth2client

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

var (
	tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
		// Certificates:       []tls.Certificate{cert},
		// RootCAs:            caCertPool,
	}
	transport = &http.Transport{TLSClientConfig: tlsConfig}
	client    = &http.Client{
		Transport: transport,
		Timeout:   time.Second * 5,
	}
)

// newBasicClient returns a client which always sends along basic auth
// credentials.
func newBasicClient(clientID string, clientSecret string) *basicClient {
	return &basicClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		client:       client,
	}
}

type basicClient struct {
	clientID     string
	clientSecret string

	client *http.Client
}

// Post sends a request to the given uri with a payload of url values.
func (c *basicClient) Post(uri string, payload url.Values) (res *http.Response, body string, err error) {
	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewReader([]byte(payload.Encode())))
	if err != nil {
		return
	}

	req.SetBasicAuth(c.clientID, c.clientSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = c.client.Do(req)
	if err != nil {
		return
	}

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}
	// reset body for re-reading
	res.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

	return res, string(bodyBytes), err
}
