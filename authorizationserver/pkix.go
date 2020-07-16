package authorizationserver

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

var oid = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "streetAddress",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.17":                   "postalCode",
	"2.5.4.42":                   "GN",
	"2.5.4.43":                   "initials",
	"2.5.4.44":                   "generationQualifier",
	"2.5.4.46":                   "dnQualifier",
	"2.5.4.65":                   "pseudonym",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.1":  "userid",
}

type ClientCertUserInfo struct {
	CommonName   string
	Issuer       string
	FullDN       string
	CNs          []string
	OUs          []string
	DCs          []string
	EmailAddress string
	Userid       string
}

func (clientcertInfo *ClientCertUserInfo) setField(oid string, val string) {
	if oid == "CN" {
		clientcertInfo.CNs = append(clientcertInfo.CNs, val)
	} else if oid == "OU" {
		clientcertInfo.OUs = append(clientcertInfo.OUs, val)
	} else if oid == "DC" {
		clientcertInfo.DCs = append(clientcertInfo.DCs, val)
	} else if oid == "emailAddress" {
		clientcertInfo.EmailAddress = val
	} else if oid == "userid" {
		clientcertInfo.Userid = val
	}
}

/**
 * DeriveEmailAddress returns an email address from the client cert info.
 *
 * Best effort at extracting an email address from the fields of the client certificates.
 * When the emailAddress was specified, returns that
 * When the DCs are specified, make an email address out of {userid}@{DCs}
 * If that userid is not specified, defaults to the first CN: {CN[0]}@{DCs}
 *
 * @param clientcertInfo The client cert parsed with its DCs
 * @return an email address or ""
 */
func DeriveEmailAddress(clientcertInfo *ClientCertUserInfo) string {
	if clientcertInfo.EmailAddress != "" {
		return clientcertInfo.EmailAddress
	}
	if len(clientcertInfo.DCs) != 0 {
		if clientcertInfo.Userid != "" {
			return clientcertInfo.Userid + "@" + strings.Join(clientcertInfo.DCs, ".")
		} else if clientcertInfo.CommonName != "" {
			return clientcertInfo.CommonName + "@" + strings.Join(clientcertInfo.DCs, ".")
		}
	}
	defaultEmailDomain := os.Getenv("DEFAULT_EMAIL_DOMAIN")
	if defaultEmailDomain != "" {
		return clientcertInfo.CommonName + "@" + defaultEmailDomain
	}
	return ""
}

// Displays the ClientCerts Info
func debugClientCertsEndpoint(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	for _, clientCert := range req.TLS.PeerCertificates {
		userInfo, err := NewClientCertUserInfo(clientCert)
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte(fmt.Sprintf(`Error parsing the client cert: %s`, err)))
			return
		}

		rw.WriteHeader(http.StatusOK)
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(userInfo)
		return
	}
	rw.WriteHeader(http.StatusBadRequest)
	rw.Write([]byte(`No Client Certificate`))
	return
}

func NewClientCertUserInfo(clientCert *x509.Certificate) (*ClientCertUserInfo, error) {
	// golang does not decode the DC and userid
	// we get to do that ourselves: https://stackoverflow.com/questions/39125873/golang-subject-dn-from-x509-cert/50640119#50640119
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(clientCert.RawSubject, &subject); err != nil {
		fmt.Printf("WARN: unable to parse the RawSubject %s\n", err.Error())
		return nil, err
	}
	fullDN := ""
	// fmt.Printf("subject %+v\n", subject.String())
	clientcertInfo := &ClientCertUserInfo{
		CommonName: clientCert.Subject.CommonName,
		Issuer:     fmt.Sprintf("%s", clientCert.Issuer),
	}
	// Reference: the source code for the String function of `clientCert.Subject.String()`
	for i := 0; i < len(subject); i++ {
		rdn := subject[len(subject)-1-i]
		if i > 0 {
			fullDN += ","
		}
		for j, tv := range rdn {
			if j > 0 {
				fullDN += "+"
			}
			oidString := tv.Type.String()
			typeName, ok := oid[oidString]
			if !ok {
				derBytes, err := asn1.Marshal(tv.Value)
				if err == nil {
					fullDN += oidString + "=#" + hex.EncodeToString(derBytes)
					continue // No value escaping necessary.
				}

				typeName = oidString
			}

			valueString := fmt.Sprint(tv.Value)
			escaped := make([]rune, 0, len(valueString))

			for k, c := range valueString {
				escape := false

				switch c {
				case ',', '+', '"', '\\', '<', '>', ';':
					escape = true

				case ' ':
					escape = k == 0 || k == len(valueString)-1

				case '#':
					escape = k == 0
				}

				if escape {
					escaped = append(escaped, '\\', c)
				} else {
					escaped = append(escaped, c)
				}
			}
			value := string(escaped)
			clientcertInfo.setField(typeName, value)
			fullDN += typeName + "=" + value
		}
	}
	clientcertInfo.FullDN = fullDN
	if clientcertInfo.EmailAddress == "" {
		clientcertInfo.EmailAddress = DeriveEmailAddress(clientcertInfo)
	}
	return clientcertInfo, nil
}
