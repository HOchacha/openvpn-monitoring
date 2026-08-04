package pki

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Captured from easy-rsa 3.1.7, with a revoked entry added.
const sample = "V\t360731004653Z\t\tBCF92560DBEA17773D5771DA56CFAA0B\tunknown\t/CN=server\n" +
	"V\t360731004653Z\t\tFBC2C89AE07BA2FF3A665AC36F4AF14B\tunknown\t/CN=alice\n" +
	"R\t360731004653Z\t260803120000Z\t2238677E30D44CB15336B5E809BEE41B\tunknown\t/CN=bob\n" +
	"V\t200101000000Z\t\tAAAA\tunknown\t/CN=lapsed\n" +
	"V\t360731004653Z\t\tBBBB\tunknown\t/C=KR/O=Example/CN=carol\n" +
	"garbage line without tabs\n"

func writeIndex(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "index.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRead(t *testing.T) {
	entries, err := Read(writeIndex(t, sample))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("got %d entries, want 5 (the malformed line is skipped)", len(entries))
	}

	byName := map[string]Entry{}
	for _, e := range entries {
		byName[e.CommonName] = e
	}

	if got := byName["alice"].Status; got != Valid {
		t.Errorf("alice is %q, want valid", got)
	}

	bob := byName["bob"]
	if bob.Status != Revoked {
		t.Errorf("bob is %q, want revoked", bob.Status)
	}
	if bob.RevokedAt.IsZero() {
		t.Error("bob has no revocation time")
	}

	// easy-rsa leaves lapsed certificates marked V; we correct that.
	if got := byName["lapsed"].Status; got != Expired {
		t.Errorf("an expired certificate reads as %q, want expired", got)
	}

	// A full subject line, not just /CN=.
	if _, ok := byName["carol"]; !ok {
		t.Error("CN was not extracted from a multi-component subject")
	}
}

func TestReadMissingFile(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Error("expected an error for a missing index")
	}
}

func TestParseTime(t *testing.T) {
	got := parseTime("360731004653Z")
	if got.Year() != 2036 || got.Month() != time.July || got.Day() != 31 {
		t.Errorf("parsed as %v", got)
	}
	if !parseTime("").IsZero() || !parseTime("nonsense").IsZero() {
		t.Error("unparseable times should come back zero")
	}
}

func TestCommonName(t *testing.T) {
	cases := map[string]string{
		"/CN=alice":                "alice",
		"/C=KR/O=Example/CN=carol": "carol",
		"/O=Example":               "",
		"":                         "",
		"/CN=name with spaces":     "name with spaces",
	}
	for subject, want := range cases {
		if got := commonName(subject); got != want {
			t.Errorf("commonName(%q) = %q, want %q", subject, got, want)
		}
	}
}
