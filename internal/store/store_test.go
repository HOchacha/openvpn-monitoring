package store

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T, retention time.Duration) *Store {
	t.Helper()

	dsn := "sqlite:" + filepath.Join(t.TempDir(), "test.db")
	s, err := Open(context.Background(), Config{
		DSN:           dsn,
		Retention:     retention,
		FlushInterval: 10 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// sync forces queued writes out and waits for them to land.
func drain(t *testing.T, s *Store) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.events) == 0 && len(s.dests) == 0 {
			time.Sleep(40 * time.Millisecond) // let the in-flight batch commit
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("queued writes never drained")
}

func TestParseDSN(t *testing.T) {
	cases := []struct {
		in      string
		dialect Dialect
		driver  string
		dsn     string
		wantErr bool
	}{
		{in: "sqlite:/var/lib/ovpnmon.db", dialect: SQLite, driver: "sqlite", dsn: "/var/lib/ovpnmon.db"},
		{in: "/var/lib/ovpnmon.db", dialect: SQLite, driver: "sqlite", dsn: "/var/lib/ovpnmon.db"},
		{in: "./local.db", dialect: SQLite, driver: "sqlite", dsn: "./local.db"},
		{in: "mysql://u:p@tcp(127.0.0.1:3306)/db", dialect: MySQL, driver: "mysql", dsn: "u:p@tcp(127.0.0.1:3306)/db"},
		{in: "mysql:u:p@/db", dialect: MySQL, driver: "mysql", dsn: "u:p@/db"},
		{in: "", wantErr: true},
		{in: "sqlite:", wantErr: true},
		{in: "postgres://x", wantErr: true},
	}
	for _, c := range cases {
		d, drv, dsn, err := parseDSN(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseDSN(%q) should have failed", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDSN(%q): %v", c.in, err)
			continue
		}
		if d != c.dialect || drv != c.driver || dsn != c.dsn {
			t.Errorf("parseDSN(%q) = %q/%q/%q, want %q/%q/%q",
				c.in, d, drv, dsn, c.dialect, c.driver, c.dsn)
		}
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := newTestStore(t, 0)
	ctx := context.Background()
	start := time.Now().Add(-time.Hour).Truncate(time.Second)

	id, err := s.StartSession(ctx, Session{
		CommonName: "alice", VirtualIP: "10.8.0.2",
		RealAddress: "203.0.113.9:1194", ClientID: 3,
		Cipher: "AES-256-GCM", ConnectedAt: start,
	})
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	rows, err := s.Sessions(ctx, Filter{})
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d sessions, want 1", len(rows))
	}
	if rows[0].DisconnectedAt != nil {
		t.Error("a live session should have no disconnect time")
	}
	if !rows[0].ConnectedAt.Equal(start) {
		t.Errorf("connected_at is %v, want %v", rows[0].ConnectedAt, start)
	}

	end := start.Add(30 * time.Minute)
	if err := s.EndSession(ctx, id, end, 111, 222); err != nil {
		t.Fatalf("EndSession: %v", err)
	}

	rows, _ = s.Sessions(ctx, Filter{})
	if rows[0].DisconnectedAt == nil {
		t.Fatal("session was not closed")
	}
	if rows[0].TunnelRx != 111 || rows[0].TunnelTx != 222 {
		t.Errorf("final counters are %d/%d", rows[0].TunnelRx, rows[0].TunnelTx)
	}

	// Closing twice must not move the timestamp.
	if err := s.EndSession(ctx, id, end.Add(time.Hour), 999, 999); err != nil {
		t.Fatalf("second EndSession: %v", err)
	}
	rows, _ = s.Sessions(ctx, Filter{})
	if !rows[0].DisconnectedAt.Equal(end) {
		t.Errorf("re-closing changed disconnected_at to %v", rows[0].DisconnectedAt)
	}
}

// TestDestinationDeltasAccumulate is the important one: the collector reports
// increments, so repeated writes for the same destination must add up rather
// than overwrite.
func TestDestinationDeltasAccumulate(t *testing.T) {
	s := newTestStore(t, 0)
	ctx := context.Background()

	id, err := s.StartSession(ctx, Session{
		CommonName: "alice", VirtualIP: "10.8.0.2",
		RealAddress: "203.0.113.9:1194", ConnectedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	base := time.Now().Truncate(time.Second)
	mk := func(tx, rx uint64, conns uint32, host string, seen time.Time) Destination {
		return Destination{
			SessionID: id, RemoteIP: "104.16.0.1", Port: 443, Proto: "tcp",
			Hostname: host, NameSource: "sni",
			TxBytes: tx, RxBytes: rx, Packets: tx + rx, Connections: conns,
			FirstSeen: base, LastSeen: seen,
		}
	}

	s.RecordDestinations([]Destination{mk(100, 1000, 1, "example.com", base)})
	drain(t, s)
	s.RecordDestinations([]Destination{mk(50, 500, 2, "example.com", base.Add(time.Minute))})
	drain(t, s)

	got, err := s.Destinations(ctx, Filter{})
	if err != nil {
		t.Fatalf("Destinations: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d destination rows, want 1 (they should have merged)", len(got))
	}
	d := got[0]
	if d.TxBytes != 150 || d.RxBytes != 1500 {
		t.Errorf("bytes are %d/%d, want 150/1500", d.TxBytes, d.RxBytes)
	}
	if d.Connections != 3 {
		t.Errorf("connections is %d, want 3", d.Connections)
	}
	if !d.LastSeen.Equal(base.Add(time.Minute)) {
		t.Errorf("last_seen is %v, want the later value", d.LastSeen)
	}
	if !d.FirstSeen.Equal(base) {
		t.Errorf("first_seen moved to %v", d.FirstSeen)
	}
	if d.CommonName != "alice" {
		t.Errorf("join to sessions lost the common name: %q", d.CommonName)
	}
}

// TestDestinationNameNotErased covers a real ordering hazard: the first flow
// carries an SNI, a later one for the same destination does not, and the
// stored name must survive.
func TestDestinationNameNotErased(t *testing.T) {
	s := newTestStore(t, 0)
	ctx := context.Background()

	id, _ := s.StartSession(ctx, Session{
		CommonName: "alice", VirtualIP: "10.8.0.2",
		RealAddress: "x", ConnectedAt: time.Now(),
	})
	now := time.Now().Truncate(time.Second)

	s.RecordDestinations([]Destination{{
		SessionID: id, RemoteIP: "1.2.3.4", Port: 443, Proto: "tcp",
		Hostname: "known.example", NameSource: "sni",
		TxBytes: 10, FirstSeen: now, LastSeen: now,
	}})
	drain(t, s)

	s.RecordDestinations([]Destination{{
		SessionID: id, RemoteIP: "1.2.3.4", Port: 443, Proto: "tcp",
		Hostname: "", NameSource: "",
		TxBytes: 5, FirstSeen: now, LastSeen: now.Add(time.Second),
	}})
	drain(t, s)

	got, _ := s.Destinations(ctx, Filter{})
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].Hostname != "known.example" {
		t.Errorf("hostname became %q; an unnamed flow erased it", got[0].Hostname)
	}
	if got[0].TxBytes != 15 {
		t.Errorf("bytes are %d, want 15", got[0].TxBytes)
	}
}

func TestEventsRoundTripAndFilter(t *testing.T) {
	s := newTestStore(t, 0)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	s.RecordEvent(Event{Time: now, Kind: "tls", CommonName: "alice",
		ClientIP: "10.8.0.2", RemoteIP: "1.2.3.4", RemotePort: 443,
		Proto: "tcp", Hostname: "www.example.com"})
	s.RecordEvent(Event{Time: now.Add(time.Second), Kind: "dns", CommonName: "bob",
		ClientIP: "10.8.0.3", Hostname: "other.test"})
	drain(t, s)

	all, err := s.Events(ctx, Filter{})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d events, want 2", len(all))
	}
	if all[0].CommonName != "bob" {
		t.Error("events should come back newest first")
	}

	only, _ := s.Events(ctx, Filter{CommonName: "alice"})
	if len(only) != 1 || only[0].Hostname != "www.example.com" {
		t.Errorf("common_name filter returned %d rows: %+v", len(only), only)
	}

	// Suffix matching: searching for the parent domain finds the subdomain.
	suffix, _ := s.Events(ctx, Filter{Hostname: "example.com"})
	if len(suffix) != 1 {
		t.Errorf("suffix search for example.com returned %d rows, want 1", len(suffix))
	}

	byKind, _ := s.Events(ctx, Filter{Kind: "dns"})
	if len(byKind) != 1 || byKind[0].CommonName != "bob" {
		t.Errorf("kind filter returned %d rows", len(byKind))
	}

	future, _ := s.Events(ctx, Filter{From: now.Add(time.Hour)})
	if len(future) != 0 {
		t.Errorf("a future window returned %d rows", len(future))
	}
}

func TestTopHosts(t *testing.T) {
	s := newTestStore(t, 0)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	// Two sessions for the same user, both reaching the same host.
	for range 2 {
		id, _ := s.StartSession(ctx, Session{
			CommonName: "alice", VirtualIP: "10.8.0.2",
			RealAddress: "x", ConnectedAt: now,
		})
		s.RecordDestinations([]Destination{
			{SessionID: id, RemoteIP: "1.1.1.1", Port: 443, Proto: "tcp",
				Hostname: "busy.example", TxBytes: 100, RxBytes: 900,
				Connections: 2, FirstSeen: now, LastSeen: now},
			{SessionID: id, RemoteIP: "2.2.2.2", Port: 443, Proto: "tcp",
				Hostname: "", TxBytes: 1, RxBytes: 1,
				FirstSeen: now, LastSeen: now},
		})
	}
	drain(t, s)

	hosts, err := s.TopHosts(ctx, Filter{CommonName: "alice"})
	if err != nil {
		t.Fatalf("TopHosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(hosts))
	}

	top := hosts[0]
	if top.Hostname != "busy.example" {
		t.Errorf("busiest host is %q", top.Hostname)
	}
	if top.Sessions != 2 {
		t.Errorf("host spans %d sessions, want 2", top.Sessions)
	}
	if top.TxBytes != 200 || top.RxBytes != 1800 {
		t.Errorf("aggregate bytes are %d/%d, want 200/1800", top.TxBytes, top.RxBytes)
	}

	// The unnamed destination must still appear, keyed by its address.
	if hosts[1].Hostname != "2.2.2.2" {
		t.Errorf("unnamed destination came back as %q, want its IP", hosts[1].Hostname)
	}
}

func TestTopCountries(t *testing.T) {
	s := newTestStore(t, 0)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	id, _ := s.StartSession(ctx, Session{
		CommonName: "alice", VirtualIP: "10.8.0.2",
		RealAddress: "x", ConnectedAt: now,
	})
	s.RecordDestinations([]Destination{
		{SessionID: id, RemoteIP: "1.1.1.1", Port: 443, Proto: "tcp",
			Hostname: "a.us", Country: "US", TxBytes: 100, RxBytes: 900,
			Connections: 1, FirstSeen: now, LastSeen: now},
		{SessionID: id, RemoteIP: "2.2.2.2", Port: 443, Proto: "tcp",
			Hostname: "b.us", Country: "US", TxBytes: 10, RxBytes: 90,
			Connections: 1, FirstSeen: now, LastSeen: now},
		{SessionID: id, RemoteIP: "3.3.3.3", Port: 443, Proto: "tcp",
			Hostname: "c.de", Country: "DE", TxBytes: 5, RxBytes: 5,
			Connections: 1, FirstSeen: now, LastSeen: now},
		// A private destination with no country must not form a blank bucket.
		{SessionID: id, RemoteIP: "10.0.0.9", Port: 22, Proto: "tcp",
			Hostname: "", Country: "", TxBytes: 3, RxBytes: 3,
			FirstSeen: now, LastSeen: now},
	})
	drain(t, s)

	rows, err := s.TopCountries(ctx, Filter{})
	if err != nil {
		t.Fatalf("TopCountries: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d countries, want 2 (blank excluded)", len(rows))
	}

	top := rows[0]
	if top.Country != "US" {
		t.Errorf("busiest country is %q, want US", top.Country)
	}
	if top.Hosts != 2 {
		t.Errorf("US spans %d hosts, want 2", top.Hosts)
	}
	if top.TxBytes != 110 || top.RxBytes != 990 {
		t.Errorf("US bytes are %d/%d, want 110/990", top.TxBytes, top.RxBytes)
	}
	if rows[1].Country != "DE" {
		t.Errorf("second country is %q, want DE", rows[1].Country)
	}
}

func TestCloseOrphanedSessions(t *testing.T) {
	s := newTestStore(t, 0)
	ctx := context.Background()
	start := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	lastSeen := start.Add(10 * time.Minute)

	id, _ := s.StartSession(ctx, Session{
		CommonName: "alice", VirtualIP: "10.8.0.2",
		RealAddress: "x", ConnectedAt: start,
	})
	s.RecordDestinations([]Destination{{
		SessionID: id, RemoteIP: "1.2.3.4", Port: 443, Proto: "tcp",
		TxBytes: 1, FirstSeen: start, LastSeen: lastSeen,
	}})
	drain(t, s)

	// A session with no traffic at all falls back to its connect time.
	bare, _ := s.StartSession(ctx, Session{
		CommonName: "bob", VirtualIP: "10.8.0.3",
		RealAddress: "y", ConnectedAt: start,
	})

	n, err := s.CloseOrphanedSessions(ctx)
	if err != nil {
		t.Fatalf("CloseOrphanedSessions: %v", err)
	}
	if n != 2 {
		t.Errorf("closed %d sessions, want 2", n)
	}

	rows, _ := s.Sessions(ctx, Filter{})
	for _, r := range rows {
		if r.DisconnectedAt == nil {
			t.Fatalf("session %d is still open", r.ID)
		}
		switch r.ID {
		case id:
			if !r.DisconnectedAt.Equal(lastSeen) {
				t.Errorf("orphan closed at %v, want last activity %v",
					r.DisconnectedAt, lastSeen)
			}
		case bare:
			if !r.DisconnectedAt.Equal(start) {
				t.Errorf("traffic-free orphan closed at %v, want connect time %v",
					r.DisconnectedAt, start)
			}
		}
	}

	// Running again must be a no-op.
	if n, _ := s.CloseOrphanedSessions(ctx); n != 0 {
		t.Errorf("second run closed %d sessions, want 0", n)
	}
}

// TestResumeSessionAcrossRestart reproduces what happens when ovpnmon is
// restarted while clients stay connected: the same VPN session must continue
// in one row, not appear as a second login.
func TestResumeSessionAcrossRestart(t *testing.T) {
	s := newTestStore(t, 0)
	ctx := context.Background()
	connected := time.Now().Add(-3 * time.Hour).Truncate(time.Second)

	sess := Session{
		CommonName: "alice", VirtualIP: "10.8.0.2",
		RealAddress: "203.0.113.9:1194", ClientID: 0, ConnectedAt: connected,
	}

	first, err := s.ResumeOrStartSession(ctx, sess)
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	// Simulate the restart: orphan cleanup, then rediscovery of the same client.
	if _, err := s.CloseOrphanedSessions(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := s.ResumeOrStartSession(ctx, sess)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if first != second {
		t.Errorf("restart created session %d instead of resuming %d", second, first)
	}

	rows, _ := s.Sessions(ctx, Filter{})
	if len(rows) != 1 {
		t.Fatalf("history holds %d sessions, want 1", len(rows))
	}
	if rows[0].DisconnectedAt != nil {
		t.Error("resumed session should be open again")
	}

	// A genuinely new connection - a later connect time - is a new row.
	sess.ConnectedAt = connected.Add(time.Hour)
	third, err := s.ResumeOrStartSession(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Error("a reconnect at a new time reused the old session row")
	}
	if rows, _ := s.Sessions(ctx, Filter{}); len(rows) != 2 {
		t.Errorf("history holds %d sessions, want 2", len(rows))
	}
}

func TestRetentionPrune(t *testing.T) {
	s := newTestStore(t, time.Hour)
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now()

	oldID, _ := s.StartSession(ctx, Session{
		CommonName: "old", VirtualIP: "10.8.0.9", RealAddress: "x", ConnectedAt: old,
	})
	s.RecordDestinations([]Destination{{
		SessionID: oldID, RemoteIP: "1.2.3.4", Port: 443, Proto: "tcp",
		TxBytes: 1, FirstSeen: old, LastSeen: old,
	}})
	s.RecordEvent(Event{Time: old, Kind: "dns", CommonName: "old"})
	s.RecordEvent(Event{Time: recent, Kind: "dns", CommonName: "new"})
	drain(t, s)

	if err := s.EndSession(ctx, oldID, old.Add(time.Minute), 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.prune(); err != nil {
		t.Fatalf("prune: %v", err)
	}

	counts, _ := s.Counts(ctx)
	if counts.Sessions != 0 {
		t.Errorf("%d sessions survived retention, want 0", counts.Sessions)
	}
	if counts.Destinations != 0 {
		t.Errorf("%d destinations survived; ON DELETE CASCADE did not fire", counts.Destinations)
	}
	if counts.Events != 1 {
		t.Errorf("%d events remain, want only the recent one", counts.Events)
	}
}

// TestRecordEventNeverBlocks guards the promise that monitoring never stalls
// the thing being monitored.
func TestRecordEventNeverBlocks(t *testing.T) {
	s := newTestStore(t, 0)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20000; i++ {
			s.RecordEvent(Event{Time: time.Now(), Kind: "dns", CommonName: "flood"})
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RecordEvent blocked under load")
	}

	if s.Stats().EventsDropped == 0 {
		t.Log("no events dropped; the writer kept up with the flood")
	}
}

func TestNotes(t *testing.T) {
	s := newTestStore(t, 0)
	ctx := context.Background()

	if err := s.SetNote(ctx, "alice", "contractor, review in Q3"); err != nil {
		t.Fatalf("SetNote: %v", err)
	}

	notes, err := s.Notes(ctx)
	if err != nil {
		t.Fatalf("Notes: %v", err)
	}
	if got := notes["alice"].Note; got != "contractor, review in Q3" {
		t.Errorf("note is %q", got)
	}
	if notes["alice"].UpdatedAt.IsZero() {
		t.Error("note has no timestamp")
	}

	// Writing again replaces rather than duplicating.
	if err := s.SetNote(ctx, "alice", "revoked"); err != nil {
		t.Fatal(err)
	}
	notes, _ = s.Notes(ctx)
	if len(notes) != 1 || notes["alice"].Note != "revoked" {
		t.Errorf("second write produced %+v", notes)
	}

	// Blank clears it, so there is no way to leave an empty row behind.
	if err := s.SetNote(ctx, "alice", "   "); err != nil {
		t.Fatal(err)
	}
	if notes, _ = s.Notes(ctx); len(notes) != 0 {
		t.Errorf("a blank note left %d rows", len(notes))
	}

	// Oversized input is truncated, not rejected: it arrives from an
	// unauthenticated endpoint.
	if err := s.SetNote(ctx, "bob", strings.Repeat("x", MaxNoteLength+500)); err != nil {
		t.Fatal(err)
	}
	notes, _ = s.Notes(ctx)
	if got := len(notes["bob"].Note); got != MaxNoteLength {
		t.Errorf("stored %d characters, want the %d cap", got, MaxNoteLength)
	}

	if err := s.SetNote(ctx, "", "no name"); err == nil {
		t.Error("a note without a common name was accepted")
	}
}
