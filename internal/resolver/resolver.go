// Package resolver turns the payload snapshots the eBPF probe captures into
// human-readable destination names, and remembers the mapping.
//
// An IP address alone rarely answers "where is this user going" - one CDN
// address fronts thousands of sites. Three signals fill that in:
//
//	DNS replies  : name the user asked for, plus every address it resolved to
//	TLS SNI      : the host inside an HTTPS connection, before encryption
//	HTTP Host    : the same for plaintext HTTP
//
// SNI and Host are authoritative for the connection that carried them. DNS is
// a hint that covers everything else the client subsequently talks to.
package resolver

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Source describes how a name was learned, in ascending order of confidence.
type Source string

const (
	SourceDNS  Source = "dns"
	SourceHTTP Source = "http"
	SourceSNI  Source = "sni"
)

func (s Source) rank() int {
	switch s {
	case SourceSNI:
		return 3
	case SourceHTTP:
		return 2
	case SourceDNS:
		return 1
	}
	return 0
}

// Observation is one learned {address -> name} fact.
type Observation struct {
	IP     netip.Addr
	Name   string
	Source Source
}

type entry struct {
	name   string
	source Source
	seen   time.Time
}

// Cache maps destination addresses to names, per VPN client.
//
// It is keyed by client as well as address because two clients behind
// different split-horizon resolvers can legitimately disagree about what an
// address is called.
type Cache struct {
	mu    sync.RWMutex
	names map[key]entry
	ttl   time.Duration
	max   int
}

type key struct {
	client netip.Addr
	remote netip.Addr
}

// NewCache returns a cache that forgets entries after ttl and holds at most
// max of them.
func NewCache(ttl time.Duration, max int) *Cache {
	if max <= 0 {
		max = 65536
	}
	return &Cache{names: make(map[key]entry), ttl: ttl, max: max}
}

// NormalizeName puts a hostname into the form the cache stores and the UI
// shows: lower case, no trailing root dot.
func NormalizeName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// Observe records what a client learned about an address. A weaker source
// never overwrites a stronger one while the stronger entry is still fresh.
func (c *Cache) Observe(client netip.Addr, obs Observation) {
	name := NormalizeName(obs.Name)
	if name == "" || !obs.IP.IsValid() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	k := key{client: client, remote: obs.IP}
	if cur, ok := c.names[k]; ok {
		if cur.source.rank() > obs.Source.rank() && time.Since(cur.seen) < c.ttl {
			return
		}
	}
	if len(c.names) >= c.max {
		c.evictLocked()
	}
	c.names[k] = entry{name: name, source: obs.Source, seen: time.Now()}
}

// Lookup returns the best known name for an address as seen by a client,
// falling back to what any other client learned about it.
func (c *Cache) Lookup(client, remote netip.Addr) (string, Source, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if e, ok := c.names[key{client: client, remote: remote}]; ok && time.Since(e.seen) < c.ttl {
		return e.name, e.source, true
	}
	for k, e := range c.names {
		if k.remote == remote && time.Since(e.seen) < c.ttl {
			return e.name, e.source, true
		}
	}
	return "", "", false
}

// Forget drops everything learned by one client, so a disconnected user's
// split-horizon answers do not leak into the next session on that address.
func (c *Cache) Forget(client netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.names {
		if k.client == client {
			delete(c.names, k)
		}
	}
}

// Prune removes expired entries. Callers run it periodically.
func (c *Cache) Prune() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0
	for k, e := range c.names {
		if time.Since(e.seen) >= c.ttl {
			delete(c.names, k)
			n++
		}
	}
	return n
}

// Len reports how many mappings are held.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.names)
}

// evictLocked drops the oldest tenth of the cache. Called with mu held.
func (c *Cache) evictLocked() {
	oldest := time.Now()
	for _, e := range c.names {
		if e.seen.Before(oldest) {
			oldest = e.seen
		}
	}
	cutoff := oldest.Add(c.ttl / 10)
	target := c.max / 10
	for k, e := range c.names {
		if target <= 0 {
			return
		}
		if e.seen.Before(cutoff) {
			delete(c.names, k)
			target--
		}
	}
	// Nothing was old enough; drop arbitrary entries to stay under the cap.
	for k := range c.names {
		if target <= 0 {
			return
		}
		delete(c.names, k)
		target--
	}
}

// ParseDNSResponse extracts the queried name and every address it resolved to.
//
// The question name is used rather than each record's own owner name so that a
// CNAME chain is reported as the host the user actually asked for.
func ParseDNSResponse(payload []byte) ([]Observation, error) {
	var p dnsmessage.Parser

	hdr, err := p.Start(payload)
	if err != nil {
		return nil, fmt.Errorf("dns header: %w", err)
	}
	if !hdr.Response {
		return nil, nil
	}

	qs, err := p.AllQuestions()
	if err != nil || len(qs) == 0 {
		return nil, nil
	}
	qname := qs[0].Name.String()

	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var out []Observation
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			// The snapshot may be truncated mid-record; keep what we have.
			break
		}

		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out, nil
			}
			out = append(out, Observation{
				IP: netip.AddrFrom4(r.A), Name: qname, Source: SourceDNS,
			})
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out, nil
			}
			out = append(out, Observation{
				IP: netip.AddrFrom16(r.AAAA), Name: qname, Source: SourceDNS,
			})
		default:
			if err := p.SkipAnswer(); err != nil {
				return out, nil
			}
		}
	}
	return out, nil
}

// ParseSNI pulls the server name out of a TLS ClientHello.
func ParseSNI(payload []byte) (string, error) {
	// TLS record header: type(1) version(2) length(2)
	if len(payload) < 43 || payload[0] != 0x16 {
		return "", errors.New("not a TLS handshake record")
	}
	b := payload[5:]

	// Handshake header: type(1) length(3)
	if len(b) < 4 || b[0] != 0x01 {
		return "", errors.New("not a ClientHello")
	}
	b = b[4:]

	// client_version(2) random(32)
	if len(b) < 34 {
		return "", errors.New("truncated ClientHello")
	}
	b = b[34:]

	// session_id
	if len(b) < 1 {
		return "", errors.New("truncated at session id")
	}
	sidLen := int(b[0])
	if len(b) < 1+sidLen {
		return "", errors.New("truncated session id")
	}
	b = b[1+sidLen:]

	// cipher_suites
	if len(b) < 2 {
		return "", errors.New("truncated at cipher suites")
	}
	csLen := int(b[0])<<8 | int(b[1])
	if len(b) < 2+csLen {
		return "", errors.New("truncated cipher suites")
	}
	b = b[2+csLen:]

	// compression_methods
	if len(b) < 1 {
		return "", errors.New("truncated at compression methods")
	}
	cmLen := int(b[0])
	if len(b) < 1+cmLen {
		return "", errors.New("truncated compression methods")
	}
	b = b[1+cmLen:]

	// extensions
	if len(b) < 2 {
		return "", errors.New("no extensions")
	}
	extTotal := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if extTotal < len(b) {
		b = b[:extTotal]
	}

	for len(b) >= 4 {
		extType := int(b[0])<<8 | int(b[1])
		extLen := int(b[2])<<8 | int(b[3])
		b = b[4:]
		if extLen > len(b) {
			break // snapshot ended mid-extension
		}
		if extType != 0x0000 { // server_name
			b = b[extLen:]
			continue
		}

		e := b[:extLen]
		// server_name_list: length(2) then entries of type(1) length(2) name
		if len(e) < 5 {
			return "", errors.New("malformed SNI extension")
		}
		e = e[2:]
		for len(e) >= 3 {
			nameType := e[0]
			nameLen := int(e[1])<<8 | int(e[2])
			e = e[3:]
			if nameLen > len(e) {
				return "", errors.New("truncated SNI host name")
			}
			if nameType == 0 { // host_name
				return string(e[:nameLen]), nil
			}
			e = e[nameLen:]
		}
		return "", errors.New("no host_name in SNI extension")
	}
	return "", errors.New("no SNI extension present")
}

// ParseHTTPHost pulls the Host header out of a plaintext HTTP request.
func ParseHTTPHost(payload []byte) (string, error) {
	// Bound the scan; a Host header this far in is not a real request.
	const maxScan = 2048
	if len(payload) > maxScan {
		payload = payload[:maxScan]
	}

	text := string(payload)
	if i := strings.Index(text, "\r\n"); i < 0 {
		return "", errors.New("no request line")
	}

	for _, line := range strings.Split(text, "\r\n")[1:] {
		if line == "" {
			break // end of headers
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "host") {
			host := strings.TrimSpace(value)
			if h, _, found := strings.Cut(host, ":"); found {
				host = h // strip the port
			}
			if host == "" {
				return "", errors.New("empty Host header")
			}
			return host, nil
		}
	}
	return "", errors.New("no Host header")
}
