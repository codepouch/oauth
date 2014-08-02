package oauth

import (
    "io/ioutil"
    "net/http"
    "net/url"
    "strings"
    "testing"
)

var testcases = []struct {
    request         *http.Request
    consumer, token *Token
}{
    // 1. Simple example from Twitter OAuth tool
    {
        request: &http.Request{
            Method: "GET",
            URL: &url.URL{
                Scheme:   "https",
                Host:     "api.twitter.com",
                Path:     "/1/",
                RawQuery: "page=10",
            },
            Header: http.Header{
                "Authorization": {`OAuth oauth_consumer_key="kMViZR2MHk2mM7hUNVw9A", oauth_nonce="8067e8abc6bdca2006818132445c8f4c", oauth_signature="o5cx1ggJrY9ognZuVVeUwglKV8U%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1355795903", oauth_token="10212-JJ3Zc1A49qSMgdcAO2GMOpW9l7A348ESmhjmOBOU", oauth_version="1.0"`},
            },
        },
        consumer: &Token{"kMViZR2MHk2mM7hUNVw9A", "56Fgl58yOfqXOhHXX0ybvOmSnPQFvR2miYmm30A"},
        token:    &Token{"10212-JJ3Zc1A49qSMgdcAO2GMOpW9l7A348ESmhjmOBOU", "yF75mvq4LZMHj9O0DXwoC3ZxUnN1ptvieThYuOAYM"},
    },

    // 2. Test case and port insensitivity.
    {
        request: &http.Request{
            Method: "GeT",
            URL: &url.URL{
                Scheme:   "https",
                Host:     "apI.twItter.com:443",
                Path:     "/1/",
                RawQuery: "page=10",
            },
            Header: http.Header{
                "Authorization": {`OAuth oauth_consumer_key="kMViZR2MHk2mM7hUNVw9A", oauth_nonce="8067e8abc6bdca2006818132445c8f4c", oauth_signature="o5cx1ggJrY9ognZuVVeUwglKV8U%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1355795903", oauth_token="10212-JJ3Zc1A49qSMgdcAO2GMOpW9l7A348ESmhjmOBOU", oauth_version="1.0"`},
            },
        },
        consumer: &Token{"kMViZR2MHk2mM7hUNVw9A", "56Fgl58yOfqXOhHXX0ybvOmSnPQFvR2miYmm30A"},
        token:    &Token{"10212-JJ3Zc1A49qSMgdcAO2GMOpW9l7A348ESmhjmOBOU", "yF75mvq4LZMHj9O0DXwoC3ZxUnN1ptvieThYuOAYM"},
    },

    // 3. Example generated using the Netflix OAuth tool.
    {
        request: &http.Request{
            Method: "GET",
            URL: &url.URL{
                Scheme:   "http",
                Host:     "api-public.netflix.com",
                Path:     "/catalog/titles",
                RawQuery: "term=Dark+Knight&count=2",
            },
            Header: http.Header{
                "Authorization": {`OAuth oauth_consumer_key="apiKey001", oauth_nonce="1234", oauth_signature="0JAoaqt6oz6TJx8N%2B06XmhPjcOs%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1355850443", oauth_token="accessToken003", oauth_version="1.0"`},
            },
        },
        consumer: &Token{"apiKey001", "sharedSecret002"},
        token:    &Token{"accessToken003", "accessSecret004"},
    },

    // 4. Test special characters in form values.
    {
        request: &http.Request{
            Method: "GET",
            URL: &url.URL{
                Scheme:   "http",
                Host:     "PHOTOS.example.net:8001",
                Path:     "/Photos",
                RawQuery: "photo+size=300%25&title=Back+of+$100+Dollars+Bill",
            },
            Header: http.Header{
                "Authorization": {`OAuth oauth_consumer_key="dpf43f3%2B%2Bp%2B%232l4k3l03", oauth_nonce="kllo~9940~pd9333jh", oauth_signature="n1UAoQy2PoIYizZUiWvkdCxM3P0%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1191242096", oauth_token="nnch734d%280%290sl2jdk", oauth_version="1.0"`},
            },
        },
        consumer: &Token{"dpf43f3++p+#2l4k3l03", "secret01"},
        token:    &Token{"nnch734d(0)0sl2jdk", "secret02"},
    },

    // 5. Test special characters in path, multiple values for same key in form.
    {
        request: &http.Request{
            Method: "GET",
            URL: &url.URL{
                Scheme:   "http",
                Host:     "EXAMPLE.COM:80",
                Path:     "/Space%20Craft",
                RawQuery: "name=value&name=value",
            },
            Header: http.Header{
                "Authorization": {`OAuth oauth_consumer_key="abcd", oauth_nonce="Ix4U1Ei3RFL", oauth_signature="TZZ5u7qQorLnmKs%2Biqunb8gqkh4%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1327384901", oauth_token="ijkl", oauth_version="1.0"`},
            },
        },
        consumer: &Token{"abcd", "efgh"},
        token:    &Token{"ijkl", "mnop"},
    },

    // 6. Test with query string in URL.
    {
        request: &http.Request{
            Method: "GET",
            URL: &url.URL{
                Scheme:   "http",
                Host:     "EXAMPLE.COM:80",
                Path:     "/Space%20Craft",
                RawQuery: "name=value&name=value",
            },
            Header: http.Header{
                "Authorization": {`OAuth oauth_consumer_key="abcd", oauth_nonce="Ix4U1Ei3RFL", oauth_signature="TZZ5u7qQorLnmKs%2Biqunb8gqkh4%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1327384901", oauth_token="ijkl", oauth_version="1.0"`},
            },
        },
        consumer: &Token{"abcd", "efgh"},
        token:    &Token{"ijkl", "mnop"},
    },

    // 7. Test "/" in form value.
    {
        request: &http.Request{
            Method: "POST",
            URL: &url.URL{
                Scheme: "https",
                Host:   "stream.twitter.com",
                Path:   "/1.1/statuses/filter.json",
            },
            Body: ioutil.NopCloser(strings.NewReader("track=example.com/abcd")),
            Header: http.Header{
                "Content-Type":  {"application/x-www-form-urlencoded"},
                "Authorization": {`OAuth oauth_consumer_key="consumer_key", oauth_nonce="bf2cb6d611e59f99103238fc9a3bb8d8", oauth_signature="LcxylEOnNdgoKSJi7jX07mxcvfM%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1362434376", oauth_token="token", oauth_version="1.0"`},
            },
        },
        consumer: &Token{"consumer_key", "consumer_secret"},
        token:    &Token{"token", "secret"},
    },

    // 8. Test "/" in query string
    {
        request: &http.Request{
            Method: "POST",
            URL: &url.URL{
                Scheme:   "https",
                Host:     "stream.twitter.com",
                Path:     "/1.1/statuses/filter.json",
                RawQuery: "track=example.com/query",
            },
            Body: ioutil.NopCloser(strings.NewReader("")),
            Header: http.Header{
                "Content-Type":  {"application/x-www-form-urlencoded"},
                "Authorization": {`OAuth oauth_consumer_key="consumer_key", oauth_nonce="884275759fbab914654b50ae643c563a", oauth_signature="OAldqvRrKDXRGZ9BqSi2CqeVH0g%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1362435218", oauth_token="token", oauth_version="1.0"`},
            },
        },
        consumer: &Token{"consumer_key", "consumer_secret"},
        token:    &Token{"token", "secret"},
    },
}

func TestOAuth(t *testing.T) {
    for _, testcase := range testcases {

        if err := Parse(testcase.request); err != nil {
            t.Fatal(err)
        }

        if err := Validate(testcase.request, testcase.consumer, testcase.token); err != nil {
            t.Fatal(err)
        }
    }

}

