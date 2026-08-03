package resolver

import (
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// captureClientHello produces a genuine ClientHello by starting a handshake
// against a pipe and reading the first record, rather than hand-assembling
// bytes that might not match what a real client sends.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: serverName}).Handshake()
	}()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("reading ClientHello: %v", err)
	}
	return buf[:n]
}

func TestParseSNI(t *testing.T) {
	for _, name := range []string{"example.com", "a.very.long.subdomain.example.org"} {
		hello := captureClientHello(t, name)
		got, err := ParseSNI(hello)
		if err != nil {
			t.Fatalf("ParseSNI(%s): %v", name, err)
		}
		if got != name {
			t.Errorf("ParseSNI returned %q, want %q", got, name)
		}
	}
}

func TestParseSNITruncated(t *testing.T) {
	hello := captureClientHello(t, "example.com")

	// The probe snapshots at most 512 bytes; a hello longer than that must
	// fail cleanly rather than panic or return garbage.
	for _, n := range []int{0, 1, 20, 43, 60, 100, len(hello) - 1} {
		if n > len(hello) {
			continue
		}
		_, _ = ParseSNI(hello[:n]) // must not panic
	}
}

func TestParseSNIRejectsNonTLS(t *testing.T) {
	if _, err := ParseSNI([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err == nil {
		t.Error("expected an error for a non-TLS payload")
	}
}

func buildDNSResponse(t *testing.T, qname string, answers []netip.Addr) []byte {
	t.Helper()

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: 0x1234, Response: true, RecursionDesired: true, RecursionAvailable: true,
	})
	b.EnableCompression()

	name := dnsmessage.MustNewName(qname)
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, a := range answers {
		hdr := dnsmessage.ResourceHeader{
			Name: name, Class: dnsmessage.ClassINET, TTL: 300,
		}
		if a.Is4() {
			if err := b.AResource(hdr, dnsmessage.AResource{A: a.As4()}); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := b.AAAAResource(hdr, dnsmessage.AAAAResource{AAAA: a.As16()}); err != nil {
				t.Fatal(err)
			}
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestParseDNSResponse(t *testing.T) {
	want := []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946"),
	}
	msg := buildDNSResponse(t, "example.com.", want)

	obs, err := ParseDNSResponse(msg)
	if err != nil {
		t.Fatalf("ParseDNSResponse: %v", err)
	}
	if len(obs) != len(want) {
		t.Fatalf("got %d observations, want %d", len(obs), len(want))
	}
	for i, o := range obs {
		if o.IP != want[i] {
			t.Errorf("observation %d has IP %s, want %s", i, o.IP, want[i])
		}
		if o.Name != "example.com." {
			t.Errorf("observation %d has name %q", i, o.Name)
		}
		if o.Source != SourceDNS {
			t.Errorf("observation %d has source %q", i, o.Source)
		}
	}
}

func TestParseDNSIgnoresQueries(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1}) // Response: false
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}

	obs, err := ParseDNSResponse(msg)
	if err != nil {
		t.Fatalf("ParseDNSResponse: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("a query yielded %d observations, want 0", len(obs))
	}
}

func TestParseDNSTruncatedDoesNotPanic(t *testing.T) {
	msg := buildDNSResponse(t, "example.com.",
		[]netip.Addr{netip.MustParseAddr("1.2.3.4")})
	for n := 0; n < len(msg); n++ {
		_, _ = ParseDNSResponse(msg[:n])
	}
}

func TestParseHTTPHost(t *testing.T) {
	cases := map[string]string{
		"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n":    "example.com",
		"POST /x HTTP/1.1\r\nhost: Example.COM:8080\r\n\r\n":            "Example.COM",
		"GET / HTTP/1.1\r\nUser-Agent: c\r\nHost:  spaced.test  \r\n\r": "spaced.test",
	}
	for payload, want := range cases {
		got, err := ParseHTTPHost([]byte(payload))
		if err != nil {
			t.Errorf("ParseHTTPHost(%q): %v", payload, err)
			continue
		}
		if got != want {
			t.Errorf("ParseHTTPHost returned %q, want %q", got, want)
		}
	}
}

func TestParseHTTPHostMissing(t *testing.T) {
	for _, payload := range []string{
		"GET / HTTP/1.0\r\n\r\n",
		"not http at all",
		"",
	} {
		if _, err := ParseHTTPHost([]byte(payload)); err == nil {
			t.Errorf("expected an error for %q", payload)
		}
	}
}

func TestCachePrefersStrongerSource(t *testing.T) {
	c := NewCache(time.Minute, 100)
	client := netip.MustParseAddr("10.8.0.2")
	remote := netip.MustParseAddr("104.20.23.154")

	c.Observe(client, Observation{IP: remote, Name: "cdn.example.net", Source: SourceDNS})
	c.Observe(client, Observation{IP: remote, Name: "real-site.test", Source: SourceSNI})

	name, src, ok := c.Lookup(client, remote)
	if !ok {
		t.Fatal("expected a cached name")
	}
	if name != "real-site.test" || src != SourceSNI {
		t.Errorf("got %q from %q, want real-site.test from sni", name, src)
	}

	// A weaker source must not clobber the stronger one.
	c.Observe(client, Observation{IP: remote, Name: "cdn.example.net", Source: SourceDNS})
	if name, _, _ := c.Lookup(client, remote); name != "real-site.test" {
		t.Errorf("DNS overwrote an SNI entry: got %q", name)
	}
}

func TestCacheNormalisesNames(t *testing.T) {
	c := NewCache(time.Minute, 100)
	client := netip.MustParseAddr("10.8.0.2")
	remote := netip.MustParseAddr("1.2.3.4")

	c.Observe(client, Observation{IP: remote, Name: "  Example.COM.  ", Source: SourceDNS})
	if name, _, _ := c.Lookup(client, remote); name != "example.com" {
		t.Errorf("name stored as %q, want example.com", name)
	}
}

func TestCacheForgetIsolatesClients(t *testing.T) {
	c := NewCache(time.Minute, 100)
	a := netip.MustParseAddr("10.8.0.2")
	b := netip.MustParseAddr("10.8.0.3")
	remote := netip.MustParseAddr("1.2.3.4")

	c.Observe(a, Observation{IP: remote, Name: "a.test", Source: SourceSNI})
	c.Observe(b, Observation{IP: remote, Name: "b.test", Source: SourceSNI})

	c.Forget(a)

	// b's own entry survives, and is what a fallback lookup now finds.
	if name, _, ok := c.Lookup(b, remote); !ok || name != "b.test" {
		t.Errorf("Forget(a) disturbed b: got %q ok=%v", name, ok)
	}
	if c.Len() != 1 {
		t.Errorf("cache holds %d entries after Forget, want 1", c.Len())
	}
}

func TestCacheExpiry(t *testing.T) {
	c := NewCache(10*time.Millisecond, 100)
	client := netip.MustParseAddr("10.8.0.2")
	remote := netip.MustParseAddr("1.2.3.4")

	c.Observe(client, Observation{IP: remote, Name: "a.test", Source: SourceDNS})
	time.Sleep(30 * time.Millisecond)

	if _, _, ok := c.Lookup(client, remote); ok {
		t.Error("expired entry was returned")
	}
	if n := c.Prune(); n != 1 {
		t.Errorf("Prune removed %d entries, want 1", n)
	}
}

func TestCacheRespectsCapacity(t *testing.T) {
	const max = 50
	c := NewCache(time.Minute, max)
	client := netip.MustParseAddr("10.8.0.2")

	for i := range 500 {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
		c.Observe(client, Observation{IP: ip, Name: "x.test", Source: SourceDNS})
	}
	if c.Len() > max {
		t.Errorf("cache grew to %d entries, cap is %d", c.Len(), max)
	}
}
