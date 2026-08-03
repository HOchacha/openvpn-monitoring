// Package store persists session and destination history.
//
// The kernel flow map is a live view: entries expire once a conversation goes
// quiet, and everything is lost on restart. That is the right behaviour for a
// dashboard and the wrong one for "who visited what last Tuesday". This package
// keeps the durable copy.
//
// Three tables, each answering a different question:
//
//	sessions     : when was each user connected, and from where
//	destinations : per session, how much traffic went to each destination
//	events       : the individual DNS/TLS/HTTP observations, in order
//
// Writes are asynchronous and batched. A monitoring tool must never stall the
// thing it monitors, so a full queue drops records and increments a counter
// rather than applying backpressure to the collector.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

// Dialect is the SQL flavour in use; the schema differs in small ways.
type Dialect string

const (
	SQLite Dialect = "sqlite"
	MySQL  Dialect = "mysql"
)

// Config controls the store.
type Config struct {
	// DSN selects the backend:
	//   sqlite:/var/lib/ovpnmon/ovpnmon.db
	//   mysql://user:pass@tcp(127.0.0.1:3306)/ovpnmon
	DSN string

	// Retention drops rows older than this. Zero keeps everything.
	Retention time.Duration

	// QueueSize bounds the pending write buffer.
	QueueSize int

	// FlushInterval is how often buffered writes are committed.
	FlushInterval time.Duration
}

func (c *Config) defaults() {
	if c.QueueSize <= 0 {
		c.QueueSize = 4096
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 2 * time.Second
	}
}

// Session is one connection's durable record.
type Session struct {
	ID             int64      `json:"id"`
	CommonName     string     `json:"common_name"`
	Username       string     `json:"username,omitempty"`
	VirtualIP      string     `json:"virtual_ip"`
	RealAddress    string     `json:"real_address"`
	ClientID       uint32     `json:"client_id"`
	Cipher         string     `json:"cipher,omitempty"`
	ConnectedAt    time.Time  `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	TunnelRx       uint64     `json:"tunnel_bytes_received"`
	TunnelTx       uint64     `json:"tunnel_bytes_sent"`
}

// Destination is a per-session traffic total for one remote endpoint.
type Destination struct {
	SessionID   int64     `json:"session_id"`
	CommonName  string    `json:"common_name,omitempty"`
	RemoteIP    string    `json:"remote_ip"`
	Port        uint16    `json:"port"`
	Proto       string    `json:"proto"`
	Hostname    string    `json:"hostname,omitempty"`
	NameSource  string    `json:"name_source,omitempty"`
	TxBytes     uint64    `json:"tx_bytes"`
	RxBytes     uint64    `json:"rx_bytes"`
	Packets     uint64    `json:"packets"`
	Connections uint32    `json:"connections"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// Event is one observation worth keeping in order.
type Event struct {
	Time       time.Time `json:"time"`
	Kind       string    `json:"kind"`
	CommonName string    `json:"common_name,omitempty"`
	ClientIP   string    `json:"client_ip,omitempty"`
	RemoteIP   string    `json:"remote_ip,omitempty"`
	RemotePort uint16    `json:"remote_port,omitempty"`
	Proto      string    `json:"proto,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

// Stats reports how the write path is coping.
type Stats struct {
	EventsWritten uint64 `json:"events_written"`
	EventsDropped uint64 `json:"events_dropped"`
	DestsWritten  uint64 `json:"destinations_written"`
	WriteErrors   uint64 `json:"write_errors"`
	QueueDepth    int    `json:"queue_depth"`
	RetentionRuns uint64 `json:"retention_runs"`
	RowsPruned    uint64 `json:"rows_pruned"`
}

// Store is a durable history backend.
type Store struct {
	db      *sql.DB
	dialect Dialect
	cfg     Config
	log     *slog.Logger

	events chan Event
	dests  chan []Destination

	counters struct {
		eventsWritten uint64
		eventsDropped uint64
		destsWritten  uint64
		writeErrors   uint64
		retentionRuns uint64
		rowsPruned    uint64
	}

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// Open connects to the backend and applies the schema.
func Open(ctx context.Context, cfg Config, log *slog.Logger) (*Store, error) {
	cfg.defaults()

	dialect, driver, dsn, err := parseDSN(cfg.DSN)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s store: %w", dialect, err)
	}

	if dialect == SQLite {
		// This file records who visited what. It is created 0644 by default,
		// which is wider than a browsing history warrants even inside a
		// root-only directory.
		if err := restrictPermissions(dsn); err != nil {
			log.Warn("could not restrict history file permissions", "path", dsn, "error", err)
		}

		// One writer, WAL for concurrent readers, and a busy timeout so a
		// reader never turns into a write error.
		db.SetMaxOpenConns(1)
		for _, pragma := range []string{
			"PRAGMA journal_mode=WAL",
			"PRAGMA busy_timeout=5000",
			"PRAGMA synchronous=NORMAL",
			"PRAGMA foreign_keys=ON",
		} {
			if _, err := db.ExecContext(ctx, pragma); err != nil {
				db.Close()
				return nil, fmt.Errorf("applying %q: %w", pragma, err)
			}
		}
	} else {
		db.SetMaxOpenConns(8)
		db.SetConnMaxLifetime(time.Hour)
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to %s store: %w", dialect, err)
	}

	s := &Store{
		db:      db,
		dialect: dialect,
		cfg:     cfg,
		log:     log,
		events:  make(chan Event, cfg.QueueSize),
		dests:   make(chan []Destination, 64),
		done:    make(chan struct{}),
	}

	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}

	s.wg.Add(1)
	go s.writeLoop()

	if cfg.Retention > 0 {
		s.wg.Add(1)
		go s.retentionLoop()
	}

	return s, nil
}

// parseDSN maps our scheme-prefixed DSN onto a driver name and its native DSN.
func parseDSN(dsn string) (Dialect, string, string, error) {
	switch {
	case strings.HasPrefix(dsn, "sqlite:"):
		path := strings.TrimPrefix(dsn, "sqlite:")
		if path == "" {
			return "", "", "", errors.New("sqlite DSN has no path")
		}
		return SQLite, "sqlite", path, nil

	case strings.HasPrefix(dsn, "mysql://"):
		return MySQL, "mysql", strings.TrimPrefix(dsn, "mysql://"), nil

	case strings.HasPrefix(dsn, "mysql:"):
		return MySQL, "mysql", strings.TrimPrefix(dsn, "mysql:"), nil

	case dsn == "":
		return "", "", "", errors.New("empty DSN")

	default:
		// A bare path is a convenience for the common case.
		if strings.HasPrefix(dsn, "/") || strings.HasPrefix(dsn, "./") {
			return SQLite, "sqlite", dsn, nil
		}
		return "", "", "", fmt.Errorf("unrecognised DSN %q: want sqlite:<path> or mysql://<dsn>", dsn)
	}
}

// restrictPermissions narrows the SQLite database and its sidecar files to
// owner-only. Opening the connection creates them, so this runs after Open.
func restrictPermissions(path string) error {
	// Strip any query string a caller appended to the file path.
	if i := strings.IndexAny(path, "?"); i >= 0 {
		path = path[:i]
	}

	var errs []error
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0o600); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close flushes pending writes and shuts down.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.wg.Wait()
	})
	return s.db.Close()
}

// Dialect reports which backend is in use.
func (s *Store) Dialect() Dialect { return s.dialect }

// Stats returns write-path counters.
func (s *Store) Stats() Stats {
	return Stats{
		EventsWritten: atomic.LoadUint64(&s.counters.eventsWritten),
		EventsDropped: atomic.LoadUint64(&s.counters.eventsDropped),
		DestsWritten:  atomic.LoadUint64(&s.counters.destsWritten),
		WriteErrors:   atomic.LoadUint64(&s.counters.writeErrors),
		QueueDepth:    len(s.events),
		RetentionRuns: atomic.LoadUint64(&s.counters.retentionRuns),
		RowsPruned:    atomic.LoadUint64(&s.counters.rowsPruned),
	}
}
