package mgmt

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hexAddr renders an address the way /proc/net/tcp does.
func hexAddr(t *testing.T, s string) string {
	t.Helper()
	ap := netip.MustParseAddrPort(s)
	b := ap.Addr().As4()
	// Each 32-bit word appears in host byte order, so the four bytes reverse.
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", b[3], b[2], b[1], b[0], ap.Port())
}

// fakeProc builds a /proc tree containing the given TCP rows, and optionally a
// process owning one of the socket inodes.
type row struct {
	local, remote string
	state         int
	inode         string
}

func fakeProc(t *testing.T, rows []row, owners map[string]struct {
	pid  int
	comm string
}) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}

	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	for i, r := range rows {
		fmt.Fprintf(&b, "%4d: %s %s %02X 00000000:00000000 00:00000000 00000000     0        0 %s 1 0000 0 0 0 0 0\n",
			i, hexAddr(t, r.local), hexAddr(t, r.remote), r.state, r.inode)
	}
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	for inode, o := range owners {
		dir := filepath.Join(root, fmt.Sprint(o.pid), "fd")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// A symlink to a socket, exactly as the kernel presents it.
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(dir, "7")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, fmt.Sprint(o.pid), "comm"),
			[]byte(o.comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// The case that cost an hour: OpenVPN is up, the port is open, and a stale
// process is holding the only management slot. Retrying cannot fix it, so the
// error has to say what is actually wrong.
func TestDiagnoseNamesTheProcessHoldingTheSlot(t *testing.T) {
	root := fakeProc(t, []row{
		{"127.0.0.1:7505", "0.0.0.0:0", tcpListen, "1000"},
		{"127.0.0.1:7505", "127.0.0.1:40436", tcpEstablished, "1001"}, // OpenVPN's end
		{"127.0.0.1:40436", "127.0.0.1:7505", tcpEstablished, "1002"}, // the client's end
	}, map[string]struct {
		pid  int
		comm string
	}{"1002": {428876, "ovpnmon"}})

	got := diagnoser{procRoot: root}.diagnose("127.0.0.1:7505", 9999)
	for _, want := range []string{"another client", "428876", "ovpnmon", "one at a time"} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnosis %q does not mention %q", got, want)
		}
	}
}

// A connection we are holding ourselves is a different bug with a different
// fix, so it must not be reported as somebody else's process.
func TestDiagnoseRecognisesOurOwnConnection(t *testing.T) {
	root := fakeProc(t, []row{
		{"127.0.0.1:7505", "0.0.0.0:0", tcpListen, "1000"},
		{"127.0.0.1:7505", "127.0.0.1:40436", tcpEstablished, "1001"},
		{"127.0.0.1:40436", "127.0.0.1:7505", tcpEstablished, "1002"},
	}, map[string]struct {
		pid  int
		comm string
	}{"1002": {4242, "ovpnmon"}})

	got := diagnoser{procRoot: root}.diagnose("127.0.0.1:7505", 4242)
	if !strings.Contains(got, "this ovpnmon already holds") {
		t.Errorf("diagnosis %q does not identify the connection as our own", got)
	}
}

// Nothing listening is the other common cause, and it needs the opposite
// action: start OpenVPN, or add the management directive.
func TestDiagnoseReportsNothingListening(t *testing.T) {
	root := fakeProc(t, []row{
		{"127.0.0.1:22", "0.0.0.0:0", tcpListen, "1000"},
	}, nil)

	got := diagnoser{procRoot: root}.diagnose("127.0.0.1:7505", 1)
	for _, want := range []string{"nothing is listening", "management 127.0.0.1 7505"} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnosis %q does not mention %q", got, want)
		}
	}
}

// Listening and free is not a diagnosis - the failure was something else, and
// inventing a cause would send the operator down the wrong path.
func TestDiagnoseSaysNothingWhenTheSlotIsFree(t *testing.T) {
	root := fakeProc(t, []row{
		{"127.0.0.1:7505", "0.0.0.0:0", tcpListen, "1000"},
	}, nil)

	if got := (diagnoser{procRoot: root}).diagnose("127.0.0.1:7505", 1); got != "" {
		t.Errorf("expected no diagnosis, got %q", got)
	}
}

// A daemon listening on 0.0.0.0 answers for 127.0.0.1 too; treating that as
// "nothing is listening" would be a confident wrong answer.
func TestDiagnoseAcceptsAWildcardListener(t *testing.T) {
	root := fakeProc(t, []row{
		{"0.0.0.0:7505", "0.0.0.0:0", tcpListen, "1000"},
	}, nil)

	if got := (diagnoser{procRoot: root}).diagnose("127.0.0.1:7505", 1); got != "" {
		t.Errorf("expected no diagnosis, got %q", got)
	}
}

// Falls back to naming the endpoint when the holding process cannot be
// identified - a container, or a process that exited between the two reads.
func TestDiagnoseWithoutAnIdentifiableOwner(t *testing.T) {
	root := fakeProc(t, []row{
		{"127.0.0.1:7505", "0.0.0.0:0", tcpListen, "1000"},
		{"127.0.0.1:7505", "127.0.0.1:40436", tcpEstablished, "1001"},
	}, nil)

	got := diagnoser{procRoot: root}.diagnose("127.0.0.1:7505", 1)
	if !strings.Contains(got, "another client holds") || !strings.Contains(got, "127.0.0.1:40436") {
		t.Errorf("diagnosis %q", got)
	}
}

func TestDiagnoseIgnoresAnUnreadableProc(t *testing.T) {
	if got := (diagnoser{procRoot: filepath.Join(t.TempDir(), "absent")}).
		diagnose("127.0.0.1:7505", 1); got != "" {
		t.Errorf("expected no diagnosis, got %q", got)
	}
	if got := (diagnoser{procRoot: "/proc"}).diagnose("not-an-address", 1); got != "" {
		t.Errorf("expected no diagnosis for a bad address, got %q", got)
	}
}

// /proc encodes each 32-bit word in host byte order. Reversing an IPv6 address
// as one 128-bit value produces something that looks plausible and is wrong.
func TestParseHexAddrPort(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0100007F:1D51", "127.0.0.1:7505"},
		{"00000000:0000", "0.0.0.0:0"},
		{"0101A8C0:01BB", "192.168.1.1:443"},
		{"00000000000000000000000001000000:1D51", "[::1]:7505"},
		{"0000000000000000FFFF00000101A8C0:01BB", "192.168.1.1:443"}, // v4-mapped
	} {
		got, ok := parseHexAddrPort(tc.in)
		if !ok {
			t.Errorf("%s did not parse", tc.in)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("%s = %s, want %s", tc.in, got, tc.want)
		}
	}

	for _, bad := range []string{"", "zzzz:0000", "0100007F", "0100007:1D51"} {
		if _, ok := parseHexAddrPort(bad); ok {
			t.Errorf("%q parsed but should not have", bad)
		}
	}
}

// The live table has to parse, whatever is in it.
func TestParseProcNetTCPOnThisHost(t *testing.T) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		t.Skip("no /proc/net/tcp")
	}
	defer f.Close()

	rows, err := parseProcNetTCP(f)
	if err != nil {
		t.Fatalf("parsing the live table: %v", err)
	}
	for _, r := range rows {
		if !r.local.Addr().IsValid() {
			t.Errorf("row with an invalid local address: %+v", r)
		}
	}
}
