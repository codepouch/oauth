package oauth

var safe = [256]bool{
    'A': true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    'a': true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    '0': true, true, true, true, true, true, true, true, true, true,
    '-': true,
    '.': true,
    '_': true,
    '~': true,
}

// encode encodes string per section 3.6 of the RFC. If double is true, then
// the encoding is applied twice.
func encode(s string, double bool) []byte {
    // Compute size of result.
    m := 3
    if double {
        m = 5
    }
    n := 0
    for i := 0; i < len(s); i++ {
        if safe[s[i]] {
            n += 1
        } else {
            n += m
        }
    }

    p := make([]byte, n)

    // Encode it.
    j := 0
    for i := 0; i < len(s); i++ {
        b := s[i]
        if safe[b] {
            p[j] = b
            j += 1
        } else if double {
            p[j] = '%'
            p[j+1] = '2'
            p[j+2] = '5'
            p[j+3] = "0123456789ABCDEF"[b>>4]
            p[j+4] = "0123456789ABCDEF"[b&15]
            j += 5
        } else {
            p[j] = '%'
            p[j+1] = "0123456789ABCDEF"[b>>4]
            p[j+2] = "0123456789ABCDEF"[b&15]
            j += 3
        }
    }
    return p
}
