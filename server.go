package oauth

import (
    "net/http"
    "net/url"
    "strconv"
    "time"
    "strings"
)

// Parse a request on the server, gets all the oauth parameters into request.Form
func ParseRequest(request *http.Request) error {
    if err := request.ParseForm(); err != nil {
        return err
    }

    for _, header := range request.Header["Authorization"] {
        if err := extractAuthorizationHeader(header, request.Form); err != nil {
            return err
        }
    }

    if request.Form.Get(VERSION) != SUPPORTED_VERSION {
        return ErrUnsupportedVersion
    }

    if request.Form.Get(SIGNATURE_METHOD) != SUPPORTED_SIGNATURE_METHOD {
        return ErrUnsupportedSignatureMethod
    }

    if request.Form.Get(CONSUMER_KEY) == "" {
        return ErrInvalidParameters
    }

    if request.Form.Get(NONCE) == "" {
        return ErrInvalidParameters
    }

    if request.Form.Get(TIMESTAMP) == "" {
        return ErrInvalidParameters
    }

    if request.Form.Get(SIGNATURE) == "" {
        return ErrInvalidParameters
    }

    return nil
}

// Validate the request against consumer and token on the server side
func ValidateSignature(request *http.Request, consumer, token *Token) error {
    url := request.URL
    if url.Host == "" {
        url.Host = request.Host
    }
    if url.Scheme == "" {
        url.Scheme = "http"
        if request.TLS != nil {
            url.Scheme = "https"
        }
    }

    signature, err := Sign(request.Method, url, request.Form, consumer, token)
    if err != nil {
        return err
    }

    if signature != request.Form.Get(SIGNATURE) {
        return ErrInvalidSignature
    }

    return nil
}

// Validate time stamp on the server side
func ValidateTimestamp(request *http.Request, tolerance int64) error {
    timestamp, err := strconv.ParseInt(request.Form.Get(TIMESTAMP), 10, 64)
    if err != nil {
        return err
    }

    deviation := time.Now().Unix() - timestamp
    if deviation > tolerance || deviation < -tolerance {
        return ErrInvalidTimestamp
    }

    return nil
}

// Authorization: OAuth realm="http://sp.example.com/",
// oauth_consumer_key="0685bd9184jfhq22",
// oauth_token="ad180jjd733klru7",
// oauth_signature_method="HMAC-SHA1",
// oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
// oauth_timestamp="137131200",
// oauth_nonce="4572616e48616d6d65724c61686176",
// oauth_version="1.0"
func extractAuthorizationHeader(header string, parameters url.Values) error {
    if !strings.HasPrefix(header, "OAuth ") {
        return nil
    }

    for _, part := range strings.Split(strings.TrimPrefix(header, "OAuth "), ",") {
        parts := strings.SplitN(strings.TrimSpace(part), "=", 2)
        name, value := parts[0], parts[1]
        if name == "realm" {
            continue
        }

        value, err := url.QueryUnescape(strings.Trim(value, "\""))
        if err != nil {
            return err
        }
        parameters.Add(name, value)
    }
    return nil
}
