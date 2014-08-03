package oauth

import (
    "bytes"
    "net/http"
    "net/url"
    "strconv"
    "time"
)

//
// Example:
//
//     // create a new request
//     request, err := http.NewRequest(method, url, nil)
//     if err != nil {
//         return err
//     }
//
//     // save any parameters on the url or in the body
//     request.Form = values
//
//     // sets the oauth header including signature
//     if err := oauth.SignRequest(request, consumer, token, nonce); err != nil {
//         return err
//     }
//
//     // send the request
//     response, err := client.Do(request)
//
func SignRequest(request *http.Request, consumer, token *Token, nonce string) error {

    // prepare oauth parameters
    oauth := url.Values{
        VERSION:          {SUPPORTED_VERSION},
        SIGNATURE_METHOD: {SUPPORTED_SIGNATURE_METHOD},
        NONCE:            {nonce},
        TIMESTAMP:        {strconv.FormatInt(time.Now().Unix(), 10)},
        CONSUMER_KEY:     {consumer.key},
    }

    if token != nil {
        oauth.Set(TOKEN, token.key)
    }

    // copy oauth parameters to form
    for key, values := range oauth {
        for _, value := range values {
            request.Form.Set(key, value)
        }
    }

    signature, err := Sign(request.Method, request.URL, request.Form, consumer, token)
    if err != nil {
        return err
    }

    // set signatures
    oauth.Set(SIGNATURE, signature)
    request.Form.Set(SIGNATURE, signature)

    // set auth header
    request.Header.Set("Authorization", buildAuthorizationHeader(oauth))
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
func buildAuthorizationHeader(oauth url.Values) string {
    var buffer bytes.Buffer
    buffer.WriteString("OAuth realm=\"\"")
    for key, values := range oauth {
        for _, value := range values {
            buffer.WriteString(",")
            buffer.WriteString(key)
            buffer.WriteString("=\"")
            buffer.WriteString(url.QueryEscape(value))
            buffer.WriteString("\"")
        }
    }
    return buffer.String()
}
