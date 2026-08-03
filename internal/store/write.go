package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// ResumeOrStartSession returns the history row for a connected client,
// reusing the existing one when this is the same VPN session seen again.
//
// ovpnmon restarting does not disconnect anybody, so on startup it rediscovers
// clients that have been online for hours. Inserting a fresh row each time
// would split one connection into several and make the history read as
// repeated logins. OpenVPN reports the true connection time, which survives
// our restarts, so {common name, virtual IP, connected_at} identifies the
// session across them.
func (s *Store) ResumeOrStartSession(ctx context.Context, sess Session) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM sessions
		 WHERE common_name = ? AND virtual_ip = ? AND connected_at = ?
		 ORDER BY id DESC LIMIT 1`,
		sess.CommonName, sess.VirtualIP, sess.ConnectedAt.Unix()).Scan(&id)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return s.StartSession(ctx, sess)
	case err != nil:
		atomic.AddUint64(&s.counters.writeErrors, 1)
		return 0, fmt.Errorf("looking up existing session: %w", err)
	}

	// Reopen it: the client never actually went away.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET disconnected_at = NULL, real_address = ?, client_id = ?
		 WHERE id = ?`,
		sess.RealAddress, sess.ClientID, id); err != nil {
		atomic.AddUint64(&s.counters.writeErrors, 1)
		return 0, fmt.Errorf("resuming session: %w", err)
	}
	return id, nil
}

// StartSession records a client connecting and returns the row id that later
// destination and disconnect records refer to.
func (s *Store) StartSession(ctx context.Context, sess Session) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions
		 (common_name, username, virtual_ip, real_address, client_id, cipher,
		  connected_at, tunnel_rx, tunnel_tx)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.CommonName, sess.Username, sess.VirtualIP, sess.RealAddress,
		sess.ClientID, sess.Cipher, sess.ConnectedAt.Unix(),
		sess.TunnelRx, sess.TunnelTx)
	if err != nil {
		atomic.AddUint64(&s.counters.writeErrors, 1)
		return 0, fmt.Errorf("recording session start: %w", err)
	}
	return res.LastInsertId()
}

// EndSession closes a session and stores its final tunnel counters.
func (s *Store) EndSession(ctx context.Context, id int64, at time.Time, rx, tx uint64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET disconnected_at = ?, tunnel_rx = ?, tunnel_tx = ?
		 WHERE id = ? AND disconnected_at IS NULL`,
		at.Unix(), rx, tx, id)
	if err != nil {
		atomic.AddUint64(&s.counters.writeErrors, 1)
		return fmt.Errorf("recording session end: %w", err)
	}
	return nil
}

// UpdateSessionCounters refreshes the tunnel byte totals of a live session.
func (s *Store) UpdateSessionCounters(ctx context.Context, id int64, rx, tx uint64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET tunnel_rx = ?, tunnel_tx = ? WHERE id = ?`,
		rx, tx, id)
	return err
}

// CloseOrphanedSessions closes sessions left open by a crash or an abrupt
// shutdown, dating them from the last destination activity seen for that
// session so the history does not claim the user stayed connected for days.
//
// It runs at startup, before any new session is recorded.
func (s *Store) CloseOrphanedSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions
		 SET disconnected_at = COALESCE(
			 (SELECT MAX(d.last_seen) FROM destinations d WHERE d.session_id = sessions.id),
			 connected_at)
		 WHERE disconnected_at IS NULL`)
	if err != nil {
		return 0, fmt.Errorf("closing orphaned sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// RecordEvent queues one observation. It never blocks; if the queue is full the
// event is dropped and counted, because stalling here would stall the ring
// buffer reader and ultimately lose kernel events instead.
func (s *Store) RecordEvent(ev Event) {
	select {
	case s.events <- ev:
	default:
		atomic.AddUint64(&s.counters.eventsDropped, 1)
	}
}

// RecordDestinations queues a batch of per-destination deltas.
func (s *Store) RecordDestinations(batch []Destination) {
	if len(batch) == 0 {
		return
	}
	select {
	case s.dests <- batch:
	default:
		atomic.AddUint64(&s.counters.eventsDropped, uint64(len(batch)))
	}
}

// writeLoop batches queued rows into transactions.
func (s *Store) writeLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	var pendingEvents []Event
	var pendingDests []Destination

	flush := func() {
		if len(pendingEvents) == 0 && len(pendingDests) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := s.commit(ctx, pendingEvents, pendingDests); err != nil {
			atomic.AddUint64(&s.counters.writeErrors, 1)
			s.log.Warn("history write failed",
				"error", err, "events", len(pendingEvents), "destinations", len(pendingDests))
		} else {
			atomic.AddUint64(&s.counters.eventsWritten, uint64(len(pendingEvents)))
			atomic.AddUint64(&s.counters.destsWritten, uint64(len(pendingDests)))
		}
		cancel()
		pendingEvents = pendingEvents[:0]
		pendingDests = pendingDests[:0]
	}

	for {
		select {
		case ev := <-s.events:
			pendingEvents = append(pendingEvents, ev)
			if len(pendingEvents) >= 512 {
				flush()
			}

		case batch := <-s.dests:
			pendingDests = append(pendingDests, batch...)
			if len(pendingDests) >= 512 {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-s.done:
			// Drain whatever is still queued before giving up.
			for {
				select {
				case ev := <-s.events:
					pendingEvents = append(pendingEvents, ev)
					continue
				case batch := <-s.dests:
					pendingDests = append(pendingDests, batch...)
					continue
				default:
				}
				break
			}
			flush()
			return
		}
	}
}

func (s *Store) commit(ctx context.Context, events []Event, dests []Destination) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if len(events) > 0 {
		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO events
			 (ts, kind, common_name, client_ip, remote_ip, remote_port, proto, hostname, detail)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		for _, e := range events {
			if _, err := stmt.ExecContext(ctx,
				e.Time.Unix(), e.Kind, e.CommonName, e.ClientIP, e.RemoteIP,
				e.RemotePort, e.Proto, e.Hostname, truncate(e.Detail, 512),
			); err != nil {
				stmt.Close()
				return err
			}
		}
		stmt.Close()
	}

	if len(dests) > 0 {
		stmt, err := tx.PrepareContext(ctx, s.upsertDestinationSQL())
		if err != nil {
			return err
		}
		for _, d := range dests {
			if _, err := stmt.ExecContext(ctx,
				d.SessionID, d.RemoteIP, d.Port, d.Proto, d.Hostname, d.NameSource,
				d.TxBytes, d.RxBytes, d.Packets, d.Connections,
				d.FirstSeen.Unix(), d.LastSeen.Unix(),
			); err != nil {
				// A destination whose session row is gone (pruned by
				// retention) is not worth failing the whole batch for.
				if isForeignKeyViolation(err) {
					continue
				}
				stmt.Close()
				return err
			}
		}
		stmt.Close()
	}

	return tx.Commit()
}

// retentionLoop deletes history past the configured horizon.
func (s *Store) retentionLoop() {
	defer s.wg.Done()

	// Run soon after startup, then daily.
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			if err := s.prune(); err != nil {
				s.log.Warn("retention pruning failed", "error", err)
			}
			timer.Reset(24 * time.Hour)
		case <-s.done:
			return
		}
	}
}

func (s *Store) prune() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cutoff := time.Now().Add(-s.cfg.Retention).Unix()
	var total int64

	// Events first: they are the bulk, and are not referenced by anything.
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("pruning events: %w", err)
	}
	n, _ := res.RowsAffected()
	total += n

	// Then closed sessions; destinations follow via ON DELETE CASCADE.
	res, err = s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE disconnected_at IS NOT NULL AND disconnected_at < ?`,
		cutoff)
	if err != nil {
		return fmt.Errorf("pruning sessions: %w", err)
	}
	n, _ = res.RowsAffected()
	total += n

	atomic.AddUint64(&s.counters.retentionRuns, 1)
	atomic.AddUint64(&s.counters.rowsPruned, uint64(total))

	if total > 0 {
		s.log.Info("pruned history past retention horizon",
			"rows", total, "retention", s.cfg.Retention)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func isForeignKeyViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "FOREIGN KEY constraint failed") || // sqlite
		strings.Contains(msg, "a foreign key constraint fails") // mysql
}
