package nodes

import (
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

var (
	errInvalidScheme = errors.New(`uri must use the "otpauth" scheme`)
	errUnknownType   = errors.New(`uri host must be "totp" or "hotp"`)
)

// encodeOtpauthQuery mirrors pquerna/otp's internal query encoder (which is
// Go's stdlib url.Values.Encode with %20 instead of + for spaces — needed
// for some authenticator apps to render an issuer/account with a space
// correctly). That helper lives in an `internal` package we cannot import
// from outside github.com/pquerna/otp, so this is a small, faithful replica
// of pure URL-formatting glue — not a reimplementation of anything
// algorithmic.
func encodeOtpauthQuery(v url.Values) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, val := range v[k] {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.PathEscape(k))
			b.WriteByte('=')
			b.WriteString(url.PathEscape(val))
		}
	}
	return b.String()
}

// buildKeyURI builds an "otpauth://{typ}/{issuer}:{account}?..." URI per the
// Google Authenticator Key-Uri-Format spec.
func buildKeyURI(typ, issuer, account, secretB32, algorithm string, digits int32, period uint32, counter uint64, hasCounter bool) string {
	v := url.Values{}
	v.Set("secret", secretB32)
	v.Set("issuer", issuer)
	v.Set("algorithm", algorithm)
	v.Set("digits", strconv.FormatInt(int64(digits), 10))
	if typ == "totp" {
		v.Set("period", strconv.FormatUint(uint64(period), 10))
	}
	if hasCounter {
		v.Set("counter", strconv.FormatUint(counter, 10))
	}

	u := url.URL{
		Scheme:   "otpauth",
		Host:     typ,
		Path:     "/" + issuer + ":" + account,
		RawQuery: encodeOtpauthQuery(v),
	}
	return u.String()
}

// parsedKeyURI is the result of parsing an otpauth:// URI.
type parsedKeyURI struct {
	typ        string
	issuer     string
	account    string
	secretB32  string
	algorithm  string
	digits     int32
	period     uint32
	counter    uint64
	hasCounter bool
}

// parseKeyURI parses an "otpauth://{totp|hotp}/{label}?..." URI, applying
// the same field-default and label-precedence rules as the Key-Uri-Format
// spec (and the same ones github.com/pquerna/otp's Key type applies).
func parseKeyURI(raw string) (*parsedKeyURI, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "otpauth" {
		return nil, errInvalidScheme
	}
	typ := strings.ToLower(u.Host)
	if typ != "totp" && typ != "hotp" {
		return nil, errUnknownType
	}

	q := u.Query()
	label := strings.TrimPrefix(u.Path, "/")
	issuer := q.Get("issuer")
	account := label
	if i := strings.Index(label, ":"); i != -1 {
		account = label[i+1:]
		if issuer == "" {
			issuer = label[:i]
		}
	}

	algorithm := strings.ToUpper(q.Get("algorithm"))
	if algorithm == "" {
		algorithm = "SHA1"
	}

	digits := int32(6)
	if d, err := strconv.ParseInt(q.Get("digits"), 10, 32); err == nil {
		digits = int32(d)
	}

	period := uint32(30)
	if p, err := strconv.ParseUint(q.Get("period"), 10, 32); err == nil {
		period = uint32(p)
	}

	var counter uint64
	hasCounter := false
	if c, err := strconv.ParseUint(q.Get("counter"), 10, 64); err == nil {
		counter = c
		hasCounter = true
	}

	return &parsedKeyURI{
		typ:        typ,
		issuer:     issuer,
		account:    account,
		secretB32:  q.Get("secret"),
		algorithm:  algorithm,
		digits:     digits,
		period:     period,
		counter:    counter,
		hasCounter: hasCounter,
	}, nil
}
