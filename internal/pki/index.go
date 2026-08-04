// Package pki reads the easy-rsa certificate index.
//
// The management interface only knows about clients that are connected right
// now, so it cannot answer "who exists but has never logged in" or "whose
// certificate was revoked". The index that easy-rsa maintains can.
//
// Reading it is optional: everything else works without it, and a server whose
// PKI lives somewhere unusual simply gets a user list built from connection
// history instead.
package pki

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// Status is the state easy-rsa records for a certificate.
type Status string

const (
	Valid   Status = "valid"
	Revoked Status = "revoked"
	Expired Status = "expired"
)

// Entry is one issued certificate.
type Entry struct {
	CommonName string    `json:"common_name"`
	Status     Status    `json:"status"`
	NotAfter   time.Time `json:"not_after"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	Serial     string    `json:"serial,omitempty"`
}

// DefaultPaths are where easy-rsa indexes usually live. The second is what
// Nyr/openvpn-install creates, which is the common case for a server someone
// else set up.
var DefaultPaths = []string{
	"/etc/openvpn/server/easy-rsa/pki/index.txt",
	"/etc/openvpn/easy-rsa/pki/index.txt",
	"/etc/easy-rsa/pki/index.txt",
	"/usr/share/easy-rsa/pki/index.txt",
}

// Find returns the first index file that exists, or "" when none do.
func Find() string {
	for _, p := range DefaultPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// Read parses an easy-rsa index.txt.
//
// The format is one tab-separated record per certificate:
//
//	V  <expiry>          <serial> unknown /CN=alice
//	R  <expiry> <revoked> <serial> unknown /CN=bob
//
// Anything unparseable is skipped rather than failing the whole read: an
// operator's PKI is not ours to validate, and a partial list beats none.
func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading PKI index: %w", err)
	}
	defer f.Close()

	var out []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 6 {
			continue
		}

		cn := commonName(fields[5])
		if cn == "" {
			continue
		}

		e := Entry{CommonName: cn, Serial: fields[3]}
		switch fields[0] {
		case "V":
			e.Status = Valid
		case "R":
			e.Status = Revoked
			e.RevokedAt = parseTime(fields[2])
		case "E":
			e.Status = Expired
		default:
			continue
		}

		e.NotAfter = parseTime(fields[1])
		// easy-rsa does not rewrite V to E as certificates lapse, so check.
		if e.Status == Valid && !e.NotAfter.IsZero() && e.NotAfter.Before(time.Now()) {
			e.Status = Expired
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// commonName pulls CN out of an OpenSSL subject line like "/CN=alice" or
// "/C=KR/O=Example/CN=alice".
func commonName(subject string) string {
	for _, part := range strings.Split(subject, "/") {
		if name, ok := strings.CutPrefix(part, "CN="); ok {
			return strings.TrimSpace(name)
		}
	}
	return ""
}

// parseTime reads an ASN.1 UTCTime such as "360731004653Z".
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{"060102150405Z", "20060102150405Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
