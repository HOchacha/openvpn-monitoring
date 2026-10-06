package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Filter narrows a history query. Zero values mean "no constraint".
type Filter struct {
	CommonName string
	Hostname   string // matched as a suffix, so "example.com" finds "www.example.com"
	RemoteIP   string
	Kind       string // events only
	From       time.Time
	To         time.Time
	Limit      int
}

func (f Filter) limit() int {
	if f.Limit <= 0 || f.Limit > 10000 {
		return 500
	}
	return f.Limit
}

// where builds a WHERE clause and its arguments from the non-empty fields.
func (f Filter) where(cnCol, hostCol, ipCol, timeCol, kindCol string) (string, []any) {
	var clauses []string
	var args []any

	add := func(clause string, arg any) {
		clauses = append(clauses, clause)
		args = append(args, arg)
	}

	if f.CommonName != "" && cnCol != "" {
		add(cnCol+" = ?", f.CommonName)
	}
	if f.Hostname != "" && hostCol != "" {
		// Suffix match: exact host, or any subdomain of it.
		clauses = append(clauses, "("+hostCol+" = ? OR "+hostCol+" LIKE ?)")
		args = append(args, f.Hostname, "%."+f.Hostname)
	}
	if f.RemoteIP != "" && ipCol != "" {
		add(ipCol+" = ?", f.RemoteIP)
	}
	if f.Kind != "" && kindCol != "" {
		add(kindCol+" = ?", f.Kind)
	}
	if !f.From.IsZero() && timeCol != "" {
		add(timeCol+" >= ?", f.From.Unix())
	}
	if !f.To.IsZero() && timeCol != "" {
		add(timeCol+" <= ?", f.To.Unix())
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// Sessions returns matching session records, newest first.
func (s *Store) Sessions(ctx context.Context, f Filter) ([]Session, error) {
	where, args := f.where("common_name", "", "", "connected_at", "")
	args = append(args, f.limit())

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, common_name, username, virtual_ip, real_address, client_id,
		        cipher, connected_at, disconnected_at, tunnel_rx, tunnel_tx
		 FROM sessions`+where+` ORDER BY connected_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("querying sessions: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var (
			sess         Session
			connected    int64
			disconnected sql.NullInt64
		)
		if err := rows.Scan(&sess.ID, &sess.CommonName, &sess.Username,
			&sess.VirtualIP, &sess.RealAddress, &sess.ClientID, &sess.Cipher,
			&connected, &disconnected, &sess.TunnelRx, &sess.TunnelTx); err != nil {
			return nil, err
		}
		sess.ConnectedAt = time.Unix(connected, 0)
		if disconnected.Valid {
			t := time.Unix(disconnected.Int64, 0)
			sess.DisconnectedAt = &t
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// Destinations returns per-session destination totals, busiest first.
func (s *Store) Destinations(ctx context.Context, f Filter) ([]Destination, error) {
	where, args := f.where("s.common_name", "d.hostname", "d.remote_ip", "d.last_seen", "")
	args = append(args, f.limit())

	rows, err := s.db.QueryContext(ctx,
		`SELECT d.session_id, s.common_name, d.remote_ip, d.port, d.proto,
		        d.hostname, d.name_source, d.country, d.tx_bytes, d.rx_bytes,
		        d.packets, d.connections, d.first_seen, d.last_seen
		 FROM destinations d
		 JOIN sessions s ON s.id = d.session_id`+where+`
		 ORDER BY (d.tx_bytes + d.rx_bytes) DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("querying destinations: %w", err)
	}
	defer rows.Close()

	var out []Destination
	for rows.Next() {
		var (
			d           Destination
			first, last int64
		)
		if err := rows.Scan(&d.SessionID, &d.CommonName, &d.RemoteIP, &d.Port,
			&d.Proto, &d.Hostname, &d.NameSource, &d.Country, &d.TxBytes, &d.RxBytes,
			&d.Packets, &d.Connections, &first, &last); err != nil {
			return nil, err
		}
		d.FirstSeen = time.Unix(first, 0)
		d.LastSeen = time.Unix(last, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Events returns raw observations, newest first.
func (s *Store) Events(ctx context.Context, f Filter) ([]Event, error) {
	where, args := f.where("common_name", "hostname", "remote_ip", "ts", "kind")
	args = append(args, f.limit())

	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, kind, common_name, client_ip, remote_ip, remote_port,
		        proto, hostname, detail
		 FROM events`+where+` ORDER BY ts DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var (
			e  Event
			ts int64
		)
		if err := rows.Scan(&ts, &e.Kind, &e.CommonName, &e.ClientIP,
			&e.RemoteIP, &e.RemotePort, &e.Proto, &e.Hostname, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// HostSummary aggregates one destination across sessions and time.
type HostSummary struct {
	Hostname    string    `json:"hostname"`
	CommonName  string    `json:"common_name,omitempty"`
	Country     string    `json:"country,omitempty"` // ISO 3166-1 alpha-2, from GeoIP
	Sessions    int       `json:"sessions"`
	TxBytes     uint64    `json:"tx_bytes"`
	RxBytes     uint64    `json:"rx_bytes"`
	Connections uint64    `json:"connections"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// TopHosts answers the question this whole package exists for: over some
// window, which destinations did a user reach, and how much did they move?
//
// Destinations that were never named are grouped under their IP so they are
// not silently omitted.
func (s *Store) TopHosts(ctx context.Context, f Filter) ([]HostSummary, error) {
	where, args := f.where("s.common_name", "d.hostname", "d.remote_ip", "d.last_seen", "")
	args = append(args, f.limit())

	// Group by the name when there is one, by the address when there is not.
	nameExpr := `CASE WHEN d.hostname <> '' THEN d.hostname ELSE d.remote_ip END`

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+nameExpr+` AS host, s.common_name, MAX(d.country),
		        COUNT(DISTINCT d.session_id), SUM(d.tx_bytes), SUM(d.rx_bytes),
		        SUM(d.connections), MIN(d.first_seen), MAX(d.last_seen)
		 FROM destinations d
		 JOIN sessions s ON s.id = d.session_id`+where+`
		 GROUP BY host, s.common_name
		 ORDER BY SUM(d.tx_bytes + d.rx_bytes) DESC
		 LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("querying top hosts: %w", err)
	}
	defer rows.Close()

	var out []HostSummary
	for rows.Next() {
		var (
			h           HostSummary
			first, last int64
		)
		if err := rows.Scan(&h.Hostname, &h.CommonName, &h.Country, &h.Sessions,
			&h.TxBytes, &h.RxBytes, &h.Connections, &first, &last); err != nil {
			return nil, err
		}
		h.FirstSeen = time.Unix(first, 0)
		h.LastSeen = time.Unix(last, 0)
		out = append(out, h)
	}
	return out, rows.Err()
}

// CountrySummary aggregates all traffic to one country over a window.
type CountrySummary struct {
	Country     string    `json:"country"` // ISO 3166-1 alpha-2
	Hosts       int       `json:"hosts"`   // distinct destinations placed there
	TxBytes     uint64    `json:"tx_bytes"`
	RxBytes     uint64    `json:"rx_bytes"`
	Connections uint64    `json:"connections"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// TopCountries answers "where in the world did this traffic go", by summing
// destinations that GeoIP placed in each country. Rows with no country (a
// private address, or history recorded before a GeoIP database was configured)
// are excluded rather than lumped into a blank bucket.
func (s *Store) TopCountries(ctx context.Context, f Filter) ([]CountrySummary, error) {
	where, args := f.where("s.common_name", "d.hostname", "d.remote_ip", "d.last_seen", "")
	// Restrict to rows that actually have a country. where() returns "" when
	// nothing was filtered, so start the clause in that case.
	if where == "" {
		where = ` WHERE d.country <> ''`
	} else {
		where += ` AND d.country <> ''`
	}
	args = append(args, f.limit())

	rows, err := s.db.QueryContext(ctx,
		`SELECT d.country,
		        COUNT(DISTINCT d.remote_ip), SUM(d.tx_bytes), SUM(d.rx_bytes),
		        SUM(d.connections), MIN(d.first_seen), MAX(d.last_seen)
		 FROM destinations d
		 JOIN sessions s ON s.id = d.session_id`+where+`
		 GROUP BY d.country
		 ORDER BY SUM(d.tx_bytes + d.rx_bytes) DESC
		 LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("querying top countries: %w", err)
	}
	defer rows.Close()

	var out []CountrySummary
	for rows.Next() {
		var (
			c           CountrySummary
			first, last int64
		)
		if err := rows.Scan(&c.Country, &c.Hosts, &c.TxBytes, &c.RxBytes,
			&c.Connections, &first, &last); err != nil {
			return nil, err
		}
		c.FirstSeen = time.Unix(first, 0)
		c.LastSeen = time.Unix(last, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

// UserSummary is everything the history knows about one common name.
type UserSummary struct {
	CommonName  string    `json:"common_name"`
	Sessions    int       `json:"session_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	TotalTx     uint64    `json:"total_tx_bytes"`
	TotalRx     uint64    `json:"total_rx_bytes"`
	LastAddress string    `json:"last_address,omitempty"`
}

// Counts reports how much history is held.
type Counts struct {
	Sessions     int64      `json:"sessions"`
	Destinations int64      `json:"destinations"`
	Events       int64      `json:"events"`
	Oldest       *time.Time `json:"oldest,omitempty"`
}

// Counts summarises the stored history.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	var c Counts

	for _, q := range []struct {
		sql  string
		dest *int64
	}{
		{`SELECT COUNT(*) FROM sessions`, &c.Sessions},
		{`SELECT COUNT(*) FROM destinations`, &c.Destinations},
		{`SELECT COUNT(*) FROM events`, &c.Events},
	} {
		if err := s.db.QueryRowContext(ctx, q.sql).Scan(q.dest); err != nil {
			return c, err
		}
	}

	var oldest sql.NullInt64
	if err := s.db.QueryRowContext(ctx,
		`SELECT MIN(connected_at) FROM sessions`).Scan(&oldest); err == nil && oldest.Valid {
		t := time.Unix(oldest.Int64, 0)
		c.Oldest = &t
	}
	return c, nil
}

// Users aggregates the history per common name: how often each has connected,
// when, and how much traffic they moved in total.
//
// Destination bytes are summed through a subquery rather than a plain join,
// because joining sessions to destinations directly multiplies each session
// row by its destination count and inflates the session counter.
func (s *Store) Users(ctx context.Context, f Filter) ([]UserSummary, error) {
	where, args := f.where("s.common_name", "", "", "s.connected_at", "")
	args = append(args, f.limit())

	rows, err := s.db.QueryContext(ctx,
		`SELECT s.common_name,
		        COUNT(*),
		        MIN(s.connected_at),
		        MAX(COALESCE(s.disconnected_at, s.connected_at)),
		        COALESCE(SUM(t.tx), 0),
		        COALESCE(SUM(t.rx), 0)
		 FROM sessions s
		 LEFT JOIN (
		     SELECT session_id, SUM(tx_bytes) AS tx, SUM(rx_bytes) AS rx
		     FROM destinations GROUP BY session_id
		 ) t ON t.session_id = s.id`+where+`
		 GROUP BY s.common_name
		 ORDER BY MAX(COALESCE(s.disconnected_at, s.connected_at)) DESC
		 LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("querying users: %w", err)
	}
	defer rows.Close()

	var out []UserSummary
	for rows.Next() {
		var (
			u           UserSummary
			first, last int64
		)
		if err := rows.Scan(&u.CommonName, &u.Sessions, &first, &last,
			&u.TotalTx, &u.TotalRx); err != nil {
			return nil, err
		}
		u.FirstSeen = time.Unix(first, 0)
		u.LastSeen = time.Unix(last, 0)
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The most recent source address per user, for the "last connected from"
	// column. Done separately so the aggregate above stays a single scan.
	for i := range out {
		var addr string
		err := s.db.QueryRowContext(ctx,
			`SELECT real_address FROM sessions
			 WHERE common_name = ? ORDER BY connected_at DESC LIMIT 1`,
			out[i].CommonName).Scan(&addr)
		if err == nil {
			out[i].LastAddress = addr
		}
	}
	return out, nil
}
