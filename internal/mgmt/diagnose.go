package mgmt

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// OpenVPN serves one management client at a time, with a listen backlog of one.
// A second client does not get refused - it gets accepted by the kernel and
// then ignored, so the symptom is a connection that opens and never greets, or
// a dial that times out once the backlog is full too.
//
// Read literally, that looks like the network being slow. It is not: something
// else is holding the slot, and no amount of retrying will help until it lets
// go. This turned a stale ovpnmon left running two days earlier into an hour of
// confusion, so the failure now says what it actually is.

const (
	tcpEstablished = 0x01
	tcpListen      = 0x0A
)

// diagnoser looks at the host's TCP tables. procRoot exists so tests can point
// it at a fixture instead of the live /proc.
type diagnoser struct{ procRoot string }

// Diagnose explains, in one clause, why the management interface could not be
// reached. It returns "" when it cannot tell, so a caller can append it to an
// error only when it adds something.
func Diagnose(addr string) string {
	return diagnoser{procRoot: "/proc"}.diagnose(addr, os.Getpid())
}

func (d diagnoser) diagnose(addr string, self int) string {
	want, err := netip.ParseAddrPort(addr)
	if err != nil {
		return ""
	}

	conns, err := d.connections()
	if err != nil {
		return ""
	}

	var listening bool
	var holders []conn
	for _, c := range conns {
		switch c.state {
		case tcpListen:
			// A daemon listening on 0.0.0.0 answers for every local address.
			if c.local.Port() == want.Port() &&
				(c.local.Addr() == want.Addr() || c.local.Addr().IsUnspecified()) {
				listening = true
			}
		case tcpEstablished:
			// The management side of an established pair: its *local* endpoint
			// is the address we are trying to reach.
			if c.local == want {
				holders = append(holders, c)
			}
		}
	}

	if !listening {
		return fmt.Sprintf("nothing is listening on %s - is OpenVPN running, "+
			"and does its config have 'management %s %d'?",
			addr, want.Addr(), want.Port())
	}
	if len(holders) == 0 {
		return ""
	}

	// Name the process on the other end of the slot. Its peer endpoint is what
	// identifies the client's own socket.
	for _, h := range holders {
		pid, name := d.ownerOf(h.remote, want)
		switch {
		case pid == self:
			return fmt.Sprintf("this ovpnmon already holds the management interface "+
				"from %s; the previous connection was not closed", h.remote)
		case pid > 0:
			return fmt.Sprintf("another client holds the management interface "+
				"(pid %d, %s, from %s); OpenVPN serves one at a time",
				pid, name, h.remote)
		}
	}
	return fmt.Sprintf("another client holds the management interface (from %s); "+
		"OpenVPN serves one at a time", holders[0].remote)
}

// ownerOf finds the process whose socket connects remote -> local.
func (d diagnoser) ownerOf(remote, local netip.AddrPort) (int, string) {
	conns, err := d.connections()
	if err != nil {
		return 0, ""
	}
	var inode string
	for _, c := range conns {
		if c.state == tcpEstablished && c.local == remote && c.remote == local {
			inode = c.inode
			break
		}
	}
	if inode == "" {
		return 0, ""
	}
	return d.pidForInode(inode)
}

// pidForInode maps a socket inode to the process holding it, the way lsof does.
func (d diagnoser) pidForInode(inode string) (int, string) {
	target := "socket:[" + inode + "]"

	entries, err := os.ReadDir(d.procRoot)
	if err != nil {
		return 0, ""
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a process directory
		}
		fds, err := os.ReadDir(filepath.Join(d.procRoot, e.Name(), "fd"))
		if err != nil {
			continue // exited, or not ours to look at
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(d.procRoot, e.Name(), "fd", fd.Name()))
			if err != nil || link != target {
				continue
			}
			name, _ := os.ReadFile(filepath.Join(d.procRoot, e.Name(), "comm"))
			return pid, strings.TrimSpace(string(name))
		}
	}
	return 0, ""
}

// conn is one row of the kernel's TCP table.
type conn struct {
	local  netip.AddrPort
	remote netip.AddrPort
	state  int
	inode  string
}

func (d diagnoser) connections() ([]conn, error) {
	var all []conn
	var lastErr error
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		f, err := os.Open(filepath.Join(d.procRoot, name))
		if err != nil {
			lastErr = err
			continue // IPv6 may not be configured
		}
		rows, err := parseProcNetTCP(f)
		f.Close()
		if err != nil {
			lastErr = err
			continue
		}
		all = append(all, rows...)
	}
	if len(all) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return all, nil
}

// parseProcNetTCP reads the kernel's TCP table.
//
//	sl  local_address rem_address st ... inode
//	 0: 0100007F:1D51 00000000:0000 0A ... 12345
func parseProcNetTCP(r io.Reader) ([]conn, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var out []conn
	first := true
	for sc.Scan() {
		if first { // column headings
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, ok := parseHexAddrPort(f[1])
		if !ok {
			continue
		}
		remote, ok := parseHexAddrPort(f[2])
		if !ok {
			continue
		}
		state, err := strconv.ParseInt(f[3], 16, 32)
		if err != nil {
			continue
		}
		out = append(out, conn{local: local, remote: remote, state: int(state), inode: f[9]})
	}
	return out, sc.Err()
}

// parseHexAddrPort decodes an address of the form 0100007F:1D51.
//
// The address is a sequence of 32-bit words in host byte order, which on every
// platform this runs on means each word is byte-reversed relative to the wire.
// IPv6 is four such words, not one 128-bit value - reversing the whole thing
// would produce an address that looks plausible and is wrong.
func parseHexAddrPort(s string) (netip.AddrPort, bool) {
	host, portStr, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portStr, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(host)
	if err != nil || len(raw)%4 != 0 || len(raw) == 0 {
		return netip.AddrPort{}, false
	}

	be := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(be[i:i+4], binary.LittleEndian.Uint32(raw[i:i+4]))
	}

	addr, ok := netip.AddrFromSlice(be)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true
}
