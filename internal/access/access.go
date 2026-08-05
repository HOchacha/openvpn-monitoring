// Package access temporarily bars a user from connecting, without touching
// their certificate.
//
// The mechanism is OpenVPN's own: a file named after the common name in
// --client-config-dir containing --disable. OpenVPN consults that directory on
// every connection attempt, so a block takes effect - and lifts - with no
// restart and no interruption to anyone else.
//
// This is deliberately not revocation. Revoking means regenerating a CRL and
// is meant for a compromised key; it does not expire, and undoing it is
// awkward. A block expires by itself and is undone by deleting a file, which
// is what "suspend this account until Monday" actually calls for. OpenVPN's
// own documentation draws the same line.
package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ubuntu/openvpn-monitoring/internal/pki"
	"github.com/ubuntu/openvpn-monitoring/internal/store"
)

// marker is the first line of every file this package writes.
//
// It is what makes a file ours. A client-config file can legitimately exist
// for other reasons - a fixed address, a per-client route - and silently
// overwriting one would delete an operator's configuration to enforce a
// temporary block. Without this marker, a file is left strictly alone.
const marker = "# ovpnmon-block"

// Killer ends a live session. The collector implements it.
//
// Blocking only governs the next connection attempt; a client that is already
// connected stays connected. Ending the current session is a separate act, and
// keeping it behind an interface is what stops this package from depending on
// the collector.
type Killer interface {
	KillByCommonName(ctx context.Context, commonName, who string) (int, error)
}

// Manager enforces blocks in a client-config directory.
type Manager struct {
	dir    string
	store  *store.Store
	killer Killer
	log    *slog.Logger

	mu sync.Mutex // serialises reconcile against block/unblock
}

// New builds a Manager over an existing client-config directory.
//
// The directory must already exist and be the one named by client-config-dir
// in the OpenVPN server configuration. Creating it here would produce a
// directory OpenVPN never reads, and blocks that silently do nothing.
func New(dir string, st *store.Store, k Killer, log *slog.Logger) (*Manager, error) {
	if dir == "" {
		return nil, errors.New("no client-config directory")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("client-config directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("client-config path %s is not a directory", dir)
	}
	if st == nil {
		return nil, errors.New("blocking needs history enabled, to record when a block ends")
	}
	return &Manager{dir: dir, store: st, killer: k, log: log}, nil
}

// Dir returns the directory being managed.
func (m *Manager) Dir() string { return m.dir }

func (m *Manager) path(commonName string) string {
	return filepath.Join(m.dir, commonName)
}

// Block bars a user from connecting until `until`, or indefinitely if zero,
// and ends any session they currently hold.
//
// The order matters: the file goes down before the kill. Killing first leaves
// a window in which the client's automatic retry - a second, in practice -
// reconnects before the block exists.
func (m *Manager) Block(ctx context.Context, commonName string, until time.Time, reason, by string) (store.Block, error) {
	if err := pki.ValidateName(commonName); err != nil {
		return store.Block{}, err
	}
	if !until.IsZero() && !until.After(time.Now()) {
		return store.Block{}, errors.New("the block would expire immediately")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	b := store.Block{
		CommonName: commonName,
		Until:      until.UTC().Truncate(time.Second),
		Reason:     reason,
		CreatedBy:  by,
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	if until.IsZero() {
		b.Until = time.Time{}
	}

	if err := m.writeFile(b); err != nil {
		return store.Block{}, err
	}
	// The database is what survives a restart, so a block that is enforced but
	// not recorded would never expire. Undo the file if it cannot be stored.
	if err := m.store.SetBlock(ctx, b); err != nil {
		if rmErr := os.Remove(m.path(commonName)); rmErr != nil {
			m.log.Error("could not roll back a block file after a failed write",
				"common_name", commonName, "error", rmErr)
		}
		return store.Block{}, fmt.Errorf("recording the block: %w", err)
	}

	killed := 0
	if m.killer != nil {
		var err error
		if killed, err = m.killer.KillByCommonName(ctx, commonName, by); err != nil {
			// The block itself is in place; the live session outliving it is
			// worth reporting but does not undo anything.
			m.log.Warn("blocked, but the current session could not be ended",
				"common_name", commonName, "error", err)
		}
	}

	m.log.Warn("user blocked",
		"common_name", commonName, "until", untilText(b), "by", by,
		"reason", reason, "sessions_ended", killed)
	return b, nil
}

// Unblock lifts a block.
func (m *Manager) Unblock(ctx context.Context, commonName, by string) error {
	if err := pki.ValidateName(commonName); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.removeFile(commonName); err != nil {
		return err
	}
	if err := m.store.DeleteBlock(ctx, commonName); err != nil {
		return fmt.Errorf("clearing the recorded block: %w", err)
	}

	m.log.Info("user unblocked", "common_name", commonName, "by", by)
	return nil
}

// writeFile puts the disable directive in place, refusing to clobber a
// client-config file this package did not write.
func (m *Manager) writeFile(b store.Block) error {
	path := m.path(b.CommonName)

	if existing, err := os.ReadFile(path); err == nil {
		if !strings.HasPrefix(string(existing), marker) {
			return fmt.Errorf("%s already has a client-config file that ovpnmon did not write; "+
				"refusing to overwrite it - add %q to it by hand to block this user", b.CommonName, "disable")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	var sb strings.Builder
	sb.WriteString(marker + "\n")
	// Not "delete this to unblock": while ovpnmon is running it puts this
	// file back within a reconcile interval, because a file lost to a botched
	// deploy must not silently unblock anyone. By hand only works with
	// ovpnmon stopped.
	sb.WriteString("# written by ovpnmon; lift this block from the dashboard\n")
	sb.WriteString("# (removing this file by hand only holds while ovpnmon is stopped)\n")
	fmt.Fprintf(&sb, "# blocked at %s by %s\n",
		b.CreatedAt.Format(time.RFC3339), orNone(b.CreatedBy))
	fmt.Fprintf(&sb, "# until %s\n", untilText(b))
	if b.Reason != "" {
		fmt.Fprintf(&sb, "# reason %s\n", singleLine(b.Reason))
	}
	sb.WriteString("disable\n")

	// Written whole and renamed into place: OpenVPN reads this directory on
	// every connection, and a half-written file would be a config error at
	// exactly the wrong moment.
	tmp, err := os.CreateTemp(m.dir, "."+b.CommonName+".*")
	if err != nil {
		return fmt.Errorf("writing the block file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(sb.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("writing the block file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing the block file: %w", err)
	}
	// OpenVPN drops privileges to nobody, so it has to be able to read this.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("setting permissions on the block file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("installing the block file: %w", err)
	}
	return nil
}

// removeFile deletes our file, leaving a foreign one alone.
func (m *Manager) removeFile(commonName string) error {
	path := m.path(commonName)
	existing, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if !strings.HasPrefix(string(existing), marker) {
		return fmt.Errorf("%s has a client-config file that ovpnmon did not write; leaving it alone", commonName)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing %s: %w", path, err)
	}
	return nil
}

// Active returns the blocks in force right now, expired ones excluded.
func (m *Manager) Active(ctx context.Context) (map[string]store.Block, error) {
	all, err := m.store.Blocks(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make(map[string]store.Block, len(all))
	for cn, b := range all {
		if !b.Expired(now) {
			out[cn] = b
		}
	}
	return out, nil
}

// Reconcile makes the directory agree with the database.
//
// Three things are put right: blocks that have expired are lifted, blocks that
// are recorded but whose file is missing are re-enforced, and files this
// package wrote for users with no recorded block are removed. The last case is
// what stops a block from becoming permanent when ovpnmon is stopped between
// writing the file and recording it, or when the database is reset.
func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	recorded, err := m.store.Blocks(ctx)
	if err != nil {
		return err
	}
	now := time.Now()

	for cn, b := range recorded {
		if b.Expired(now) {
			if err := m.removeFile(cn); err != nil {
				m.log.Warn("could not lift an expired block", "common_name", cn, "error", err)
				continue
			}
			if err := m.store.DeleteBlock(ctx, cn); err != nil {
				m.log.Warn("could not clear an expired block", "common_name", cn, "error", err)
				continue
			}
			m.log.Info("block expired", "common_name", cn, "until", untilText(b))
			continue
		}
		// Recorded and still in force: make sure OpenVPN is actually enforcing
		// it. A file removed by hand would otherwise leave the dashboard
		// claiming a block that does not exist.
		if _, err := os.Stat(m.path(cn)); errors.Is(err, os.ErrNotExist) {
			if err := m.writeFile(b); err != nil {
				m.log.Warn("could not re-enforce a block", "common_name", cn, "error", err)
				continue
			}
			m.log.Info("re-enforced a block whose file was missing", "common_name", cn)
		}
	}

	// Files we wrote that nothing accounts for.
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", m.dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if _, ok := recorded[e.Name()]; ok {
			continue
		}
		body, err := os.ReadFile(filepath.Join(m.dir, e.Name()))
		if err != nil || !strings.HasPrefix(string(body), marker) {
			continue // not ours
		}
		if err := os.Remove(filepath.Join(m.dir, e.Name())); err != nil {
			m.log.Warn("could not remove an orphaned block file", "file", e.Name(), "error", err)
			continue
		}
		m.log.Info("removed an orphaned block file", "common_name", e.Name())
	}
	return nil
}

// Run reconciles on an interval until ctx is cancelled.
//
// The interval is how late a block can lift, so it wants to be short relative
// to the shortest block anyone would set.
func (m *Manager) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 15 * time.Second
	}
	if err := m.Reconcile(ctx); err != nil {
		m.log.Warn("initial block reconciliation failed", "error", err)
	}

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := m.Reconcile(ctx); err != nil {
				m.log.Warn("block reconciliation failed", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func untilText(b store.Block) string {
	if b.Indefinite() {
		return "further notice"
	}
	return b.Until.Format(time.RFC3339)
}

func orNone(s string) string {
	if s == "" {
		return "an operator"
	}
	return s
}

// singleLine keeps operator text from becoming extra directives in a file
// OpenVPN parses.
func singleLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.TrimSpace(s)
}
