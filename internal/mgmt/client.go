// Package mgmt speaks the OpenVPN management interface protocol.
//
// The protocol multiplexes two things over one connection: replies to commands
// we send, and asynchronous notifications the daemon pushes at any moment.
// Notifications always start with '>', which is the only reliable way to tell
// them apart, so a single reader goroutine demultiplexes and everything else
// talks to it over channels.
package mgmt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Session is one connected OpenVPN client.
type Session struct {
	CommonName     string         `json:"common_name"`
	Username       string         `json:"username,omitempty"`
	RealAddr       string         `json:"real_address"`
	VirtualIP      netip.Addr     `json:"virtual_ip"`
	BytesReceived  uint64         `json:"bytes_received"`
	BytesSent      uint64         `json:"bytes_sent"`
	ConnectedSince time.Time      `json:"connected_since"`
	ClientID       uint32         `json:"client_id"`
	PeerID         uint32         `json:"peer_id"`
	Cipher         string         `json:"cipher,omitempty"`
	Routes         []netip.Prefix `json:"routes,omitempty"`
}

// Notification is an asynchronous message pushed by the daemon.
type Notification struct {
	Kind string // e.g. "CLIENT", "BYTECOUNT_CLI", "INFO", "LOG"
	Body string
}

// Client is a connection to one OpenVPN management interface.
type Client struct {
	addr string

	mu     sync.Mutex // serialises commands
	conn   net.Conn
	reader *bufio.Reader

	replies chan []string
	notes   chan Notification
	errs    chan error

	closeOnce sync.Once
	closed    chan struct{}
}

// Dial connects to the management interface and starts demultiplexing.
//
// password is used when the daemon was started with a password file
// ("management <host> <port> <pwfile>"); pass an empty string when it was not.
func Dial(ctx context.Context, addr, password string) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to management interface %s: %w", addr, err)
	}

	c := &Client{
		addr:    addr,
		conn:    conn,
		reader:  bufio.NewReaderSize(conn, 64*1024),
		replies: make(chan []string, 4),
		notes:   make(chan Notification, 256),
		errs:    make(chan error, 1),
		closed:  make(chan struct{}),
	}

	if err := c.authenticate(ctx, password); err != nil {
		conn.Close()
		return nil, err
	}

	go c.readLoop()
	return c, nil
}

// authenticate handles the password prompt, if there is one.
//
// A daemon without a password file sends its greeting banner straight away, so
// the prompt is what distinguishes the two cases. Anything read here that is
// not a prompt stays buffered for readLoop, which is why the client owns the
// bufio.Reader rather than creating one there.
func (c *Client) authenticate(ctx context.Context, password string) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(deadline)
		_ = c.conn.SetWriteDeadline(deadline)
		defer func() {
			_ = c.conn.SetReadDeadline(time.Time{})
			_ = c.conn.SetWriteDeadline(time.Time{})
		}()
	}

	// Only a password-protected daemon speaks first with a prompt; peeking
	// avoids consuming the greeting when it does not.
	const prompt = "ENTER PASSWORD:"
	head, err := c.reader.Peek(len(prompt))
	if err != nil {
		return fmt.Errorf("reading management greeting: %w", err)
	}
	if string(head) != prompt {
		// No prompt: the interface is unprotected. A configured password is
		// simply unused - worth knowing, but not worth refusing to start over.
		return nil
	}

	if password == "" {
		return fmt.Errorf(
			"management interface %s requires a password; set mgmt-password-file", c.addr)
	}

	if _, err := c.reader.Discard(len(prompt)); err != nil {
		return fmt.Errorf("consuming password prompt: %w", err)
	}
	if _, err := fmt.Fprintf(c.conn, "%s\n", password); err != nil {
		return fmt.Errorf("sending management password: %w", err)
	}

	// The daemon answers "SUCCESS: password is correct" or "ERROR: bad password".
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading password response: %w", err)
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "SUCCESS:"):
			return nil
		case strings.HasPrefix(line, "ERROR:"):
			return fmt.Errorf("management authentication rejected: %s", line)
		default:
			// Some builds echo a blank line or a banner first.
			continue
		}
	}
}

// Notifications yields asynchronous daemon messages. It is never closed while
// the client is alive; slow consumers drop messages rather than stall the
// reader.
func (c *Client) Notifications() <-chan Notification { return c.notes }

// Err reports why the connection ended.
func (c *Client) Err() <-chan error { return c.errs }

func (c *Client) readLoop() {
	sc := bufio.NewScanner(c.reader)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var pending []string
	collecting := false

	finish := func() {
		out := pending
		pending = nil
		collecting = false
		select {
		case c.replies <- out:
		case <-c.closed:
		}
	}

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")

		if strings.HasPrefix(line, ">") {
			kind, body, _ := strings.Cut(strings.TrimPrefix(line, ">"), ":")
			select {
			case c.notes <- Notification{Kind: kind, Body: body}:
			default: // never let a stalled consumer block the protocol
			}
			continue
		}

		switch {
		case line == "END":
			if collecting {
				finish()
			}
		case strings.HasPrefix(line, "SUCCESS:"), strings.HasPrefix(line, "ERROR:"):
			pending = append(pending, line)
			finish()
		default:
			collecting = true
			pending = append(pending, line)
		}
	}

	err := sc.Err()
	if err == nil {
		err = errors.New("management connection closed")
	}
	select {
	case c.errs <- err:
	default:
	}
	c.Close()
}

// command sends one line and returns the reply block.
func (c *Client) command(ctx context.Context, cmd string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.closed:
		return nil, net.ErrClosed
	default:
	}

	// Drop any reply left over from a timed-out predecessor so it cannot be
	// mistaken for this command's answer.
	select {
	case <-c.replies:
	default:
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(deadline)
		defer c.conn.SetWriteDeadline(time.Time{})
	}
	if _, err := fmt.Fprintf(c.conn, "%s\n", cmd); err != nil {
		return nil, fmt.Errorf("sending %q: %w", cmd, err)
	}

	select {
	case reply := <-c.replies:
		return reply, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

// Close ends the management session and shuts the connection down. It is safe
// to call more than once.
//
// Ending the session cleanly matters more than it looks. OpenVPN serves one
// management client at a time and its listen backlog is 1, so a dead session
// the daemon has not noticed blocks every subsequent connection: new attempts
// sit unaccepted in the queue and time out. The interface is then unusable
// until OpenVPN itself restarts.
//
// Sending "exit" is not enough on its own - closing immediately afterwards can
// tear the socket down before the daemon's event loop reads the command, which
// is exactly the state that leaves it stuck. The brief pause gives it a chance
// to observe the end of the session.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		_ = c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = fmt.Fprint(c.conn, "exit\n")

		close(c.closed)

		// Half-close rather than closing outright: the daemon then sees a
		// clean EOF on its read side while its own writes still work, which
		// is what prompts it to release the management slot. A plain close
		// can reset the connection before it gets that far.
		if tcp, ok := c.conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		time.Sleep(200 * time.Millisecond)
		err = c.conn.Close()
	})
	return err
}

// EnableBytecount asks the daemon to push per-client byte counters every
// interval seconds. Zero turns it off.
func (c *Client) EnableBytecount(ctx context.Context, interval int) error {
	reply, err := c.command(ctx, fmt.Sprintf("bytecount %d", interval))
	if err != nil {
		return err
	}
	for _, l := range reply {
		if strings.HasPrefix(l, "ERROR:") {
			return fmt.Errorf("bytecount rejected: %s", l)
		}
	}
	return nil
}

// Status returns every currently connected client.
func (c *Client) Status(ctx context.Context) ([]Session, error) {
	reply, err := c.command(ctx, "status 3")
	if err != nil {
		return nil, err
	}
	return parseStatus3(reply)
}

// parseStatus3 decodes the tab-separated "status 3" format. Field positions
// differ between OpenVPN releases, so the HEADER lines - which name each
// column - drive the mapping rather than fixed indices.
func parseStatus3(lines []string) ([]Session, error) {
	headers := map[string]map[string]int{}
	byVirtualIP := map[netip.Addr]*Session{}
	var order []*Session

	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "HEADER":
			idx := map[string]int{}
			for i, name := range fields[2:] {
				idx[name] = i
			}
			headers[fields[1]] = idx

		case "CLIENT_LIST":
			idx, ok := headers["CLIENT_LIST"]
			if !ok {
				return nil, errors.New("CLIENT_LIST row before its HEADER")
			}
			row := fields[1:]
			get := func(name string) string {
				i, ok := idx[name]
				if !ok || i >= len(row) {
					return ""
				}
				return row[i]
			}

			s := &Session{
				CommonName: get("Common Name"),
				RealAddr:   get("Real Address"),
				Cipher:     get("Data Channel Cipher"),
			}
			if u := get("Username"); u != "" && u != "UNDEF" {
				s.Username = u
			}
			if ip, err := netip.ParseAddr(get("Virtual Address")); err == nil {
				s.VirtualIP = ip
			}
			s.BytesReceived, _ = strconv.ParseUint(get("Bytes Received"), 10, 64)
			s.BytesSent, _ = strconv.ParseUint(get("Bytes Sent"), 10, 64)
			if secs, err := strconv.ParseInt(get("Connected Since (time_t)"), 10, 64); err == nil {
				s.ConnectedSince = time.Unix(secs, 0)
			}
			if v, err := strconv.ParseUint(get("Client ID"), 10, 32); err == nil {
				s.ClientID = uint32(v)
			}
			if v, err := strconv.ParseUint(get("Peer ID"), 10, 32); err == nil {
				s.PeerID = uint32(v)
			}

			order = append(order, s)
			if s.VirtualIP.IsValid() {
				byVirtualIP[s.VirtualIP] = s
			}

		case "ROUTING_TABLE":
			idx, ok := headers["ROUTING_TABLE"]
			if !ok {
				continue
			}
			row := fields[1:]
			get := func(name string) string {
				i, ok := idx[name]
				if !ok || i >= len(row) {
					return ""
				}
				return row[i]
			}

			// A client may own more than its own address via iroute.
			virt := get("Virtual Address")
			cn := get("Common Name")
			pfx, err := parseRoute(virt)
			if err != nil {
				continue
			}
			for _, s := range order {
				if s.CommonName != cn {
					continue
				}
				if pfx.IsSingleIP() && pfx.Addr() == s.VirtualIP {
					break // already the session's own address
				}
				s.Routes = append(s.Routes, pfx)
				break
			}
		}
	}

	out := make([]Session, 0, len(order))
	for _, s := range order {
		out = append(out, *s)
	}
	return out, nil
}

// parseRoute accepts both "10.8.0.2" and "10.8.1.0/24" forms.
func parseRoute(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
