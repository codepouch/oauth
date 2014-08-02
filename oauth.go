package oauth

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha1"
    "encoding/base64"
    "errors"
    "io"
    "net/http"
    "net/url"
    "sort"
    "strings"
)

var (
    ErrInvalidSignature = errors.New("oauth: invalid signature")
)

type Token struct {
    key, secret string
}

func Parse(request *http.Request) error {
    if err := request.ParseForm(); err != nil {
        return err
    }

    for _, header := range request.Header["Authorization"] {
        extractAuthorizationHeader(header, request.Form)
    }

    return nil
}

func Validate(request *http.Request, consumer, token *Token) error {
    signature, err := Sign(request, consumer, token)
    if err != nil {
        return err
    }

    if signature != request.Form.Get("oauth_signature") {
        return ErrInvalidSignature
    }

    return nil
}

func Sign(request *http.Request, consumer, token *Token) (string, error) {
    key, err := buildSigningKey(consumer, token)
    if err != nil {
        return "", err
    }

    hasher := hmac.New(sha1.New, key)
    if err := writeSigningBase(hasher, request); err != nil {
        return "", err
    }

    sum := hasher.Sum(nil)
    return base64.StdEncoding.EncodeToString(sum), nil
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

type pair struct {
    key, value []byte
}

type pairs []pair

func (p pairs) Len() int {
    return len(p)
}

func (p pairs) Less(i, j int) bool {
    n := bytes.Compare(p[i].key, p[j].key)
    if n == 0 {
        n = bytes.Compare(p[i].value, p[j].value)
    }
    return n < 0
}

func (p pairs) Swap(i, j int) {
    p[i], p[j] = p[j], p[i]
}

func writeSigningBase(writer io.Writer, request *http.Request) error {

    // Method
    if _, err := writer.Write(encode(strings.ToUpper(request.Method), false)); err != nil {
        return err
    }

    if _, err := writer.Write([]byte{'&'}); err != nil {
        return err
    }

    // URL
    scheme := strings.ToLower(request.URL.Scheme)
    if _, err := writer.Write(encode(scheme, false)); err != nil {
        return err
    }

    if _, err := writer.Write(encode("://", false)); err != nil {
        return err
    }

    host := strings.ToLower(request.URL.Host)
    switch {
    case scheme == "http" && strings.HasSuffix(host, ":80"):
        host = host[:len(host)-len(":80")]
    case scheme == "https" && strings.HasSuffix(host, ":443"):
        host = host[:len(host)-len(":443")]
    }

    if _, err := writer.Write(encode(host, false)); err != nil {
        return err
    }

    if _, err := writer.Write(encode(request.URL.Path, false)); err != nil {
        return err
    }

    if _, err := writer.Write([]byte{'&'}); err != nil {
        return err
    }

    // Create sorted slice of encoded parameters. Parameter keys and values are
    // double encoded in a single step. This is safe because double encoding
    // does not change the sort order.

    capacity := 0
    for key, values := range request.Form {
        if key == "oauth_signature" {
            continue
        }
        capacity += len(values)
    }

    form := make(pairs, 0, capacity)
    for key, values := range request.Form {
        if key == "oauth_signature" {
            continue
        }

        k := encode(key, true)
        for _, value := range values {
            form = append(form, pair{k, encode(value, true)})
        }
    }
    sort.Sort(form)

    amp := encode("&", false)
    equal := encode("=", false)

    for index, param := range form {
        if index > 0 {
            if _, err := writer.Write(amp); err != nil {
                return err
            }
        }

        if _, err := writer.Write(param.key); err != nil {
            return err
        }

        if _, err := writer.Write(equal); err != nil {
            return err
        }

        if _, err := writer.Write(param.value); err != nil {
            return err
        }
    }

    return nil
}

func buildSigningKey(consumer, token *Token) ([]byte, error) {
    var key bytes.Buffer
    if _, err := key.Write(encode(consumer.secret, false)); err != nil {
        return nil, err
    }

    if err := key.WriteByte('&'); err != nil {
        return nil, err
    }

    if token == nil {
        return key.Bytes(), nil
    }

    if _, err := key.Write(encode(token.secret, false)); err != nil {
        return nil, err
    }

    return key.Bytes(), nil
}

