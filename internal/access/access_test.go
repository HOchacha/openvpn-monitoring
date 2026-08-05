package access

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubuntu/openvpn-monitoring/internal/store"
)

type fakeKiller struct {
	killed []string
	err    error
}

func (f *fakeKiller) KillByCommonName(_ context.Context, cn, _ string) (int, error) {
	f.killed = append(f.killed, cn)
	return 1, f.err
}

func newManager(t *testing.T) (*Manager, string, *fakeKiller) {
	t.Helper()

	dir := t.TempDir()
	st, err := store.Open(context.Background(),
		store.Config{DSN: "sqlite:" + filepath.Join(t.TempDir(), "h.db")},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	k := &fakeKiller{}
	m, err := New(dir, st, k, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m, dir, k
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

// The directory has to exist already: creating it would produce one OpenVPN
// never reads, and blocks that silently do nothing.
func TestNewRequiresAnExistingDirectory(t *testing.T) {
	log0 := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(),
		store.Config{DSN: "sqlite:" + filepath.Join(t.TempDir(), "h.db")}, log0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if _, err := New(filepath.Join(t.TempDir(), "absent"), st, nil, log); err == nil {
		t.Error("expected an error for a missing directory")
	}
	if _, err := New("", st, nil, log); err == nil {
		t.Error("expected an error for an empty path")
	}
}

// Without history a block has nowhere to expire from, so it would become
// permanent - which is what blocking exists not to be.
func TestNewRequiresAStore(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(t.TempDir(), nil, nil, log); err == nil {
		t.Error("expected an error when history is disabled")
	}
}

func TestBlockWritesDisableAndKills(t *testing.T) {
	m, dir, k := newManager(t)
	until := time.Now().Add(time.Hour)

	b, err := m.Block(context.Background(), "alice", until, "offboarding", "admin")
	if err != nil {
		t.Fatalf("Block: %v", err)
	}

	body := readFile(t, filepath.Join(dir, "alice"))
	if !strings.HasPrefix(body, marker) {
		t.Errorf("file is not marked as ours:\n%s", body)
	}
	// The directive OpenVPN acts on has to be on its own line, unindented.
	var found bool
	for _, line := range strings.Split(body, "\n") {
		if line == "disable" {
			found = true
		}
	}
	if !found {
		t.Errorf("no bare disable directive:\n%s", body)
	}
	if !strings.Contains(body, "offboarding") {
		t.Errorf("reason not recorded:\n%s", body)
	}

	if len(k.killed) != 1 || k.killed[0] != "alice" {
		t.Errorf("kill was not issued: %v", k.killed)
	}

	stored, ok, err := m.store.GetBlock(context.Background(), "alice")
	if err != nil || !ok {
		t.Fatalf("block was not recorded: ok=%v err=%v", ok, err)
	}
	if stored.Until.Unix() != b.Until.Unix() {
		t.Errorf("stored expiry %v != returned %v", stored.Until, b.Until)
	}
	if stored.CreatedBy != "admin" {
		t.Errorf("created_by = %q", stored.CreatedBy)
	}
}

// A client-config file can legitimately exist for other reasons. Overwriting
// one would delete an operator's configuration to enforce a temporary block.
func TestBlockRefusesToClobberAForeignFile(t *testing.T) {
	m, dir, _ := newManager(t)

	original := "ifconfig-push 10.8.0.50 255.255.255.0\n"
	if err := os.WriteFile(filepath.Join(dir, "alice"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := m.Block(context.Background(), "alice", time.Now().Add(time.Hour), "", "admin")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if got := readFile(t, filepath.Join(dir, "alice")); got != original {
		t.Errorf("the existing file was modified:\n%s", got)
	}
	// And nothing was recorded, so the dashboard does not claim a block that
	// is not being enforced.
	if _, ok, _ := m.store.GetBlock(context.Background(), "alice"); ok {
		t.Error("a refused block was still recorded")
	}
}

func TestUnblockLeavesAForeignFileAlone(t *testing.T) {
	m, dir, _ := newManager(t)

	original := "ifconfig-push 10.8.0.50 255.255.255.0\n"
	if err := os.WriteFile(filepath.Join(dir, "alice"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Unblock(context.Background(), "alice", "admin"); err == nil {
		t.Error("expected a refusal")
	}
	if got := readFile(t, filepath.Join(dir, "alice")); got != original {
		t.Error("a foreign file was removed")
	}
}

func TestUnblockRemovesTheFileAndTheRecord(t *testing.T) {
	m, dir, _ := newManager(t)
	ctx := context.Background()

	if _, err := m.Block(ctx, "alice", time.Now().Add(time.Hour), "", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := m.Unblock(ctx, "alice", "admin"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "alice")); !os.IsNotExist(err) {
		t.Error("the block file survived")
	}
	if _, ok, _ := m.store.GetBlock(ctx, "alice"); ok {
		t.Error("the record survived")
	}
}

// Unblocking someone who is not blocked is what the caller wanted.
func TestUnblockIsIdempotent(t *testing.T) {
	m, _, _ := newManager(t)
	if err := m.Unblock(context.Background(), "nobody", "admin"); err != nil {
		t.Errorf("Unblock: %v", err)
	}
}

func TestBlockRejectsBadInput(t *testing.T) {
	m, _, _ := newManager(t)
	ctx := context.Background()

	// Path traversal would write a disable file anywhere on the filesystem.
	if _, err := m.Block(ctx, "../../etc/passwd", time.Now().Add(time.Hour), "", "admin"); err == nil {
		t.Error("a traversing name was accepted")
	}
	// An expiry in the past would be enforced until the next reconcile and
	// then lift, which is not what anyone meant to ask for.
	if _, err := m.Block(ctx, "alice", time.Now().Add(-time.Minute), "", "admin"); err == nil {
		t.Error("an expiry in the past was accepted")
	}
}

// Operator text must not become extra OpenVPN directives.
func TestReasonCannotInjectDirectives(t *testing.T) {
	m, dir, _ := newManager(t)

	_, err := m.Block(context.Background(), "alice", time.Now().Add(time.Hour),
		"bad\npush \"redirect-gateway def1\"", "admin")
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(readFile(t, filepath.Join(dir, "alice")), "\n") {
		if line != "disable" && line != "" && !strings.HasPrefix(line, "#") {
			t.Errorf("uncommented line other than disable: %q", line)
		}
	}
}

func TestIndefiniteBlock(t *testing.T) {
	m, dir, _ := newManager(t)

	b, err := m.Block(context.Background(), "alice", time.Time{}, "", "admin")
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !b.Indefinite() {
		t.Error("expected an indefinite block")
	}
	if !strings.Contains(readFile(t, filepath.Join(dir, "alice")), "further notice") {
		t.Error("the file does not say the block is indefinite")
	}

	// And it must survive reconciliation rather than being treated as expired.
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "alice")); err != nil {
		t.Error("an indefinite block was lifted by reconciliation")
	}
}

func TestReconcileLiftsExpiredBlocks(t *testing.T) {
	m, dir, _ := newManager(t)
	ctx := context.Background()

	// Write it directly with an expiry in the past: Block refuses to create
	// one, but ovpnmon being stopped past the expiry produces exactly this.
	past := store.Block{
		CommonName: "alice",
		Until:      time.Now().Add(-time.Minute),
		CreatedBy:  "admin",
		CreatedAt:  time.Now().Add(-time.Hour),
	}
	if err := m.writeFile(past); err != nil {
		t.Fatal(err)
	}
	if err := m.store.SetBlock(ctx, past); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "alice")); !os.IsNotExist(err) {
		t.Error("an expired block was not lifted")
	}
	if _, ok, _ := m.store.GetBlock(ctx, "alice"); ok {
		t.Error("an expired block is still recorded")
	}
}

// A file removed by hand would otherwise leave the dashboard claiming a block
// that OpenVPN is not enforcing.
func TestReconcileReEnforcesAMissingFile(t *testing.T) {
	m, dir, _ := newManager(t)
	ctx := context.Background()

	if _, err := m.Block(ctx, "alice", time.Now().Add(time.Hour), "", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "alice")); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !strings.Contains(readFile(t, filepath.Join(dir, "alice")), "disable") {
		t.Error("the block was not re-enforced")
	}
}

// A file written but never recorded - ovpnmon stopped between the two steps,
// or the database was reset - would otherwise block someone forever.
func TestReconcileRemovesOrphanedFiles(t *testing.T) {
	m, dir, _ := newManager(t)

	orphan := store.Block{CommonName: "ghost", Until: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	if err := m.writeFile(orphan); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ghost")); !os.IsNotExist(err) {
		t.Error("an orphaned block file survived")
	}
}

func TestReconcileLeavesForeignFilesAlone(t *testing.T) {
	m, dir, _ := newManager(t)

	original := "ifconfig-push 10.8.0.50 255.255.255.0\n"
	if err := os.WriteFile(filepath.Join(dir, "static"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := readFile(t, filepath.Join(dir, "static")); got != original {
		t.Error("reconciliation touched a file it did not write")
	}
}

func TestActiveExcludesExpired(t *testing.T) {
	m, _, _ := newManager(t)
	ctx := context.Background()

	if _, err := m.Block(ctx, "live", time.Now().Add(time.Hour), "", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := m.store.SetBlock(ctx, store.Block{
		CommonName: "stale", Until: time.Now().Add(-time.Hour), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	active, err := m.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if _, ok := active["live"]; !ok {
		t.Error("a live block is missing")
	}
	if _, ok := active["stale"]; ok {
		t.Error("an expired block is reported as active")
	}
}

// OpenVPN drops privileges to nobody, so it has to be able to read these.
func TestBlockFileIsWorldReadable(t *testing.T) {
	m, dir, _ := newManager(t)

	if _, err := m.Block(context.Background(), "alice", time.Now().Add(time.Hour), "", "admin"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o044 == 0 {
		t.Errorf("mode %v is not readable by OpenVPN after it drops privileges", info.Mode().Perm())
	}
}

// Reconcile must not leave the temporary files it writes behind, or they
// accumulate in a directory OpenVPN scans.
func TestNoTempFilesLeftBehind(t *testing.T) {
	m, dir, _ := newManager(t)
	ctx := context.Background()

	if _, err := m.Block(ctx, "alice", time.Now().Add(time.Hour), "", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}
