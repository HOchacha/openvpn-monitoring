// Package geoip turns a destination address into a place, using a local
// MaxMind GeoLite2 database.
//
// It is deliberately offline: the .mmdb file is read from disk and every
// lookup is a local B-tree walk, so there is no per-destination network round
// trip and no third-party service that sees which addresses a VPN reaches.
// The operator supplies the database; ovpnmon never downloads it.
//
// Only public addresses are looked up. VPN-internal and other private ranges
// have no meaningful geography, so they return nothing rather than a spurious
// answer.
package geoip

import (
	"fmt"
	"net/netip"
	"sync"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// Location is where an address is, as much of it as the database knows.
//
// Fields are omitted when empty so a country-only database (GeoLite2-Country)
// and a city database (GeoLite2-City) both produce sensible output through the
// same struct.
type Location struct {
	CountryISO  string  `json:"country_iso,omitempty"`  // ISO 3166-1 alpha-2, e.g. "US"
	CountryName string  `json:"country_name,omitempty"` // English name, e.g. "United States"
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
}

// record mirrors the subset of the GeoLite2 schema ovpnmon uses. The same
// shape decodes against both the City and Country databases; missing sections
// simply stay zero.
type record struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// DB is an open GeoLite2 database with a small result cache.
//
// The maxminddb reader is safe for concurrent use, so the only lock here
// guards the cache. Lookups happen on the dashboard's path, once per
// destination per refresh; caching keeps a busy client with hundreds of flows
// from re-decoding the same handful of servers every second.
type DB struct {
	reader *maxminddb.Reader

	mu    sync.Mutex
	cache map[netip.Addr]*Location
}

// Open reads the .mmdb file at path. The returned DB must be Closed.
func Open(path string) (*DB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: opening %s: %w", path, err)
	}
	return &DB{reader: r, cache: make(map[netip.Addr]*Location)}, nil
}

// Metadata describes the loaded database, for the health view.
func (db *DB) Metadata() (buildEpoch uint64, dbType string) {
	m := db.reader.Metadata
	return uint64(m.BuildEpoch), m.DatabaseType
}

// Lookup returns where addr is. The second return is false for private and
// otherwise non-global addresses, and for public addresses the database does
// not place.
func (db *DB) Lookup(addr netip.Addr) (Location, bool) {
	if !isGlobal(addr) {
		return Location{}, false
	}

	db.mu.Lock()
	if hit, ok := db.cache[addr]; ok {
		db.mu.Unlock()
		if hit == nil {
			return Location{}, false
		}
		return *hit, true
	}
	db.mu.Unlock()

	loc, ok := db.decode(addr)

	db.mu.Lock()
	// Bound the cache crudely: a VPN reaches far fewer distinct servers than
	// this in practice, and dropping the whole thing is simpler than an LRU
	// for a map that rarely fills.
	if len(db.cache) >= 8192 {
		db.cache = make(map[netip.Addr]*Location)
	}
	if ok {
		l := loc
		db.cache[addr] = &l
	} else {
		db.cache[addr] = nil
	}
	db.mu.Unlock()

	return loc, ok
}

func (db *DB) decode(addr netip.Addr) (Location, bool) {
	var rec record
	if err := db.reader.Lookup(addr).Decode(&rec); err != nil {
		return Location{}, false
	}
	loc := Location{
		CountryISO:  rec.Country.ISOCode,
		CountryName: rec.Country.Names["en"],
		City:        rec.City.Names["en"],
		Latitude:    rec.Location.Latitude,
		Longitude:   rec.Location.Longitude,
	}
	// Nothing placed it: an unknown or reserved address the database carries
	// with an empty record.
	if loc == (Location{}) {
		return Location{}, false
	}
	return loc, true
}

// Close releases the database file.
func (db *DB) Close() error {
	return db.reader.Close()
}

// isGlobal reports whether an address is worth geolocating. Loopback,
// link-local, private, and unspecified addresses are not.
func isGlobal(addr netip.Addr) bool {
	return addr.IsValid() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast()
}
