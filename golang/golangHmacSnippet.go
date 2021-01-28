package golang

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/url"
)

const (
	dateTimeFormat = "2006-01-02T15:04:05.000Z"
)

// this is meant to be copied and used in your project to authenticate to the NCR Business Services Platform
//
// Disclaimer: This is not proper golang format, but it has been reduced for ease of integration for those not
//				familiar with the BSP or golang
//
// createHMAC
//
// Arguments:
// sharedKey - user's shared key
// secretKey - user's secret key
// date - date value in ISO-8601 format
// httpMethod - GET, POST, PUT, PATCH, etc.
// requestURL - full url of the request
// contentType - content-type header from request (optional, unless required by API documentation)
// contentMD5 - contentMD5 header from request (optional, unless required by API documentation)
// nepApplicationKey - nepApplicationKey header from request (optional, unless required by API documentation)
// nepCorrelationID - nepCorrelationID header from request (optional, unless required by API documentation)
// nepOrganization - nepOrganization header from request (optional, unless required by API documentation)
// nepServiceVersion - nepServiceVersion header from request (optional, unless required by API documentation)
//
// returns the header for the Authorization header on a BSP API request
func createHMAC(sharedKey,
	secretKey,
	date,
	httpMethod,
	requestURL,
	contentType,
	contentMD5,
	nepApplicationKey,
	nepCorrelationID,
	nepOrganization,
	nepServiceVersion string) (string, error) {
	parsedDate, err := http.ParseTime(date)
	if err != nil {
		return "", err
	}
	date = parsedDate.Format(dateTimeFormat)
	method := httpMethod
	oneTimeSecret := secretKey + date
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", err
	}
	toSign := method + "\n" + u.RequestURI()
	if contentType != "" {
		toSign += "\n" + contentType
	}
	if contentMD5 != "" {
		toSign += "\n" + contentMD5
	}
	if nepApplicationKey != "" {
		toSign += "\n" + nepApplicationKey
	}
	if nepCorrelationID != "" {
		toSign += "\n" + nepCorrelationID
	}
	if nepOrganization != "" {
		toSign += "\n" + nepOrganization
	}
	if nepServiceVersion != "" {
		toSign += "\n" + nepServiceVersion
	}

	key := hmac.New(sha512.New, []byte(oneTimeSecret))
	key.Write([]byte(toSign))
	token := "AccessKey " + sharedKey + ":" + base64.StdEncoding.EncodeToString(key.Sum(nil))
	return token, nil
}
