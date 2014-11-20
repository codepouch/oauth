package oauth

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha1"
    "encoding/base64"
    "errors"
    "io"
    "net/url"
    "sort"
    "strings"
)

const (
    SUPPORTED_VERSION          = "1.0"
    SUPPORTED_SIGNATURE_METHOD = "HMAC-SHA1"

    CONSUMER_KEY     = "oauth_consumer_key"
    VERSION          = "oauth_version"
    SIGNATURE_METHOD = "oauth_signature_method"
    NONCE            = "oauth_nonce"
    TIMESTAMP        = "oauth_timestamp"
    SIGNATURE        = "oauth_signature"
    TOKEN            = "oauth_token"
    TOKEN_SECRET     = "oauth_token_secret"
)

var (
    ErrInvalidParameters          = errors.New("oauth: invalid parameters")
    ErrUnsupportedVersion         = errors.New("oauth: unsupported version")
    ErrUnsupportedSignatureMethod = errors.New("oauth: unsupported signature method")
    ErrInvalidSignature           = errors.New("oauth: invalid signature")
    ErrInvalidTimestamp           = errors.New("oauth: invalid timestamp")
    ErrNoToken                    = errors.New("oauth: no token")
)

type Token struct {
    key, secret string
}

func NewToken(key, secret string) *Token {
    return &Token{key, secret}
}

func DecodeToken(raw string) (*Token, error) {
    query, err := url.ParseQuery(raw)
    if err != nil {
        return nil, err
    }

    token := query.Get(TOKEN)
    secret := query.Get(TOKEN_SECRET)
    if token == "" || secret == "" {
        return nil, ErrNoToken
    }

    return NewToken(token, secret), nil
}

func (t *Token) Key() string {
    return t.key
}

func (t *Token) Secret() string {
    return t.secret
}

func (t *Token) Encode() string {
    return url.Values{
        TOKEN: {t.key},
        TOKEN_SECRET: {t.secret},
    }.Encode()
}

func Sign(method string, url *url.URL, values url.Values, consumer, token *Token) (string, error) {
    key, err := buildSigningKey(consumer, token)
    if err != nil {
        return "", err
    }

    hasher := hmac.New(sha1.New, key)
    if err := writeSigningBase(hasher, method, url, values); err != nil {
        return "", err
    }

    sum := hasher.Sum(nil)
    return base64.StdEncoding.EncodeToString(sum), nil
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

func writeSigningBase(writer io.Writer, method string, url *url.URL, values url.Values) error {

    // Method
    if _, err := writer.Write(encode(strings.ToUpper(method), false)); err != nil {
        return err
    }

    if _, err := writer.Write([]byte{'&'}); err != nil {
        return err
    }

    // URL
    scheme := strings.ToLower(url.Scheme)
    if _, err := writer.Write(encode(scheme, false)); err != nil {
        return err
    }

    if _, err := writer.Write(encode("://", false)); err != nil {
        return err
    }

    host := strings.ToLower(url.Host)
    switch {
    case scheme == "http" && strings.HasSuffix(host, ":80"):
        host = host[:len(host)-len(":80")]
    case scheme == "https" && strings.HasSuffix(host, ":443"):
        host = host[:len(host)-len(":443")]
    }

    if _, err := writer.Write(encode(host, false)); err != nil {
        return err
    }

    if _, err := writer.Write(encode(url.Path, false)); err != nil {
        return err
    }

    if _, err := writer.Write([]byte{'&'}); err != nil {
        return err
    }

    // Create sorted slice of encoded parameters. Parameter keys and values are
    // double encoded in a single step. This is safe because double encoding
    // does not change the sort order.

    capacity := 0
    for key, values := range values {
        if key == SIGNATURE {
            continue
        }
        capacity += len(values)
    }

    form := make(pairs, 0, capacity)
    for key, values := range values {
        if key == SIGNATURE {
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
