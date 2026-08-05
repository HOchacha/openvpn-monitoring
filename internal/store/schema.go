package store

import (
	"context"
	"fmt"
)

// The two dialects differ enough in column types and index rules that spelling
// each schema out separately is clearer than templating one.

var sqliteSchema = []string{
	`CREATE TABLE IF NOT EXISTS sessions (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		common_name     TEXT    NOT NULL,
		username        TEXT    NOT NULL DEFAULT '',
		virtual_ip      TEXT    NOT NULL,
		real_address    TEXT    NOT NULL,
		client_id       INTEGER NOT NULL DEFAULT 0,
		cipher          TEXT    NOT NULL DEFAULT '',
		connected_at    INTEGER NOT NULL,
		disconnected_at INTEGER,
		tunnel_rx       INTEGER NOT NULL DEFAULT 0,
		tunnel_tx       INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_cn_time ON sessions (common_name, connected_at)`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_open ON sessions (disconnected_at)`,

	`CREATE TABLE IF NOT EXISTS destinations (
		session_id   INTEGER NOT NULL,
		remote_ip    TEXT    NOT NULL,
		port         INTEGER NOT NULL,
		proto        TEXT    NOT NULL,
		hostname     TEXT    NOT NULL DEFAULT '',
		name_source  TEXT    NOT NULL DEFAULT '',
		tx_bytes     INTEGER NOT NULL DEFAULT 0,
		rx_bytes     INTEGER NOT NULL DEFAULT 0,
		packets      INTEGER NOT NULL DEFAULT 0,
		connections  INTEGER NOT NULL DEFAULT 0,
		first_seen   INTEGER NOT NULL,
		last_seen    INTEGER NOT NULL,
		PRIMARY KEY (session_id, remote_ip, port, proto),
		FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
	)`,
	`CREATE INDEX IF NOT EXISTS idx_dest_hostname ON destinations (hostname)`,
	`CREATE INDEX IF NOT EXISTS idx_dest_lastseen ON destinations (last_seen)`,

	`CREATE TABLE IF NOT EXISTS events (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		ts          INTEGER NOT NULL,
		kind        TEXT    NOT NULL,
		common_name TEXT    NOT NULL DEFAULT '',
		client_ip   TEXT    NOT NULL DEFAULT '',
		remote_ip   TEXT    NOT NULL DEFAULT '',
		remote_port INTEGER NOT NULL DEFAULT 0,
		proto       TEXT    NOT NULL DEFAULT '',
		hostname    TEXT    NOT NULL DEFAULT '',
		detail      TEXT    NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts)`,
	`CREATE INDEX IF NOT EXISTS idx_events_cn_ts ON events (common_name, ts)`,
	`CREATE INDEX IF NOT EXISTS idx_events_host ON events (hostname)`,

	// Operator notes about a user. Keyed by common name rather than by
	// session, because the note is about the person, not one connection.
	`CREATE TABLE IF NOT EXISTS user_notes (
		common_name TEXT    NOT NULL PRIMARY KEY,
		note        TEXT    NOT NULL DEFAULT '',
		updated_at  INTEGER NOT NULL
	)`,

	// Temporary blocks. The database is the authority on when a block ends -
	// the file OpenVPN reads carries no expiry, so without this a block would
	// outlive an ovpnmon that was stopped before it expired.
	`CREATE TABLE IF NOT EXISTS user_blocks (
		common_name TEXT    NOT NULL PRIMARY KEY,
		until       INTEGER NOT NULL DEFAULT 0,
		reason      TEXT    NOT NULL DEFAULT '',
		created_by  TEXT    NOT NULL DEFAULT '',
		created_at  INTEGER NOT NULL
	)`,
}

var mysqlSchema = []string{
	`CREATE TABLE IF NOT EXISTS sessions (
		id              BIGINT       NOT NULL AUTO_INCREMENT,
		common_name     VARCHAR(191) NOT NULL,
		username        VARCHAR(191) NOT NULL DEFAULT '',
		virtual_ip      VARCHAR(45)  NOT NULL,
		real_address    VARCHAR(64)  NOT NULL,
		client_id       INT UNSIGNED NOT NULL DEFAULT 0,
		cipher          VARCHAR(64)  NOT NULL DEFAULT '',
		connected_at    BIGINT       NOT NULL,
		disconnected_at BIGINT       NULL,
		tunnel_rx       BIGINT UNSIGNED NOT NULL DEFAULT 0,
		tunnel_tx       BIGINT UNSIGNED NOT NULL DEFAULT 0,
		PRIMARY KEY (id),
		KEY idx_sessions_cn_time (common_name, connected_at),
		KEY idx_sessions_open (disconnected_at)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS destinations (
		session_id   BIGINT       NOT NULL,
		remote_ip    VARCHAR(45)  NOT NULL,
		port         SMALLINT UNSIGNED NOT NULL,
		proto        VARCHAR(8)   NOT NULL,
		hostname     VARCHAR(255) NOT NULL DEFAULT '',
		name_source  VARCHAR(8)   NOT NULL DEFAULT '',
		tx_bytes     BIGINT UNSIGNED NOT NULL DEFAULT 0,
		rx_bytes     BIGINT UNSIGNED NOT NULL DEFAULT 0,
		packets      BIGINT UNSIGNED NOT NULL DEFAULT 0,
		connections  INT UNSIGNED NOT NULL DEFAULT 0,
		first_seen   BIGINT       NOT NULL,
		last_seen    BIGINT       NOT NULL,
		PRIMARY KEY (session_id, remote_ip, port, proto),
		KEY idx_dest_hostname (hostname),
		KEY idx_dest_lastseen (last_seen),
		CONSTRAINT fk_dest_session FOREIGN KEY (session_id)
			REFERENCES sessions(id) ON DELETE CASCADE
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS events (
		id          BIGINT       NOT NULL AUTO_INCREMENT,
		ts          BIGINT       NOT NULL,
		kind        VARCHAR(24)  NOT NULL,
		common_name VARCHAR(191) NOT NULL DEFAULT '',
		client_ip   VARCHAR(45)  NOT NULL DEFAULT '',
		remote_ip   VARCHAR(45)  NOT NULL DEFAULT '',
		remote_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
		proto       VARCHAR(8)   NOT NULL DEFAULT '',
		hostname    VARCHAR(255) NOT NULL DEFAULT '',
		detail      VARCHAR(512) NOT NULL DEFAULT '',
		PRIMARY KEY (id),
		KEY idx_events_ts (ts),
		KEY idx_events_cn_ts (common_name, ts),
		KEY idx_events_host (hostname)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS user_notes (
		common_name VARCHAR(191) NOT NULL,
		note        TEXT         NOT NULL,
		updated_at  BIGINT       NOT NULL,
		PRIMARY KEY (common_name)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS user_blocks (
		common_name VARCHAR(191) NOT NULL,
		until       BIGINT       NOT NULL DEFAULT 0,
		reason      VARCHAR(512) NOT NULL DEFAULT '',
		created_by  VARCHAR(191) NOT NULL DEFAULT '',
		created_at  BIGINT       NOT NULL,
		PRIMARY KEY (common_name)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
}

func (s *Store) migrate(ctx context.Context) error {
	stmts := sqliteSchema
	if s.dialect == MySQL {
		stmts = mysqlSchema
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("applying schema: %w\nstatement: %s", err, stmt)
		}
	}
	return nil
}

// upsertDestinationSQL returns the dialect's flavour of "insert or accumulate".
//
// The values bound to the counter columns are *deltas*, not running totals.
// A flow can be pruned from the kernel map and then reappear when the client
// contacts the same destination again, at which point the kernel counter
// restarts from zero. Taking the maximum would silently discard everything
// after such a restart, so the collector reports increments and the database
// sums them.
//
// A name only overwrites a stored one when the new observation actually has
// one, so a later flow with no SNI does not erase an earlier identification.
func (s *Store) upsertDestinationSQL() string {
	const cols = `INSERT INTO destinations
		(session_id, remote_ip, port, proto, hostname, name_source,
		 tx_bytes, rx_bytes, packets, connections, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) `

	if s.dialect == MySQL {
		return cols + `ON DUPLICATE KEY UPDATE
			hostname    = IF(VALUES(hostname) <> '', VALUES(hostname), hostname),
			name_source = IF(VALUES(hostname) <> '', VALUES(name_source), name_source),
			tx_bytes    = tx_bytes    + VALUES(tx_bytes),
			rx_bytes    = rx_bytes    + VALUES(rx_bytes),
			packets     = packets     + VALUES(packets),
			connections = connections + VALUES(connections),
			first_seen  = LEAST(first_seen, VALUES(first_seen)),
			last_seen   = GREATEST(last_seen, VALUES(last_seen))`
	}

	return cols + `ON CONFLICT (session_id, remote_ip, port, proto) DO UPDATE SET
		hostname    = CASE WHEN excluded.hostname <> '' THEN excluded.hostname ELSE destinations.hostname END,
		name_source = CASE WHEN excluded.hostname <> '' THEN excluded.name_source ELSE destinations.name_source END,
		tx_bytes    = destinations.tx_bytes    + excluded.tx_bytes,
		rx_bytes    = destinations.rx_bytes    + excluded.rx_bytes,
		packets     = destinations.packets     + excluded.packets,
		connections = destinations.connections + excluded.connections,
		first_seen  = MIN(destinations.first_seen, excluded.first_seen),
		last_seen   = MAX(destinations.last_seen, excluded.last_seen)`
}
