package mgmt

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Captured verbatim from OpenVPN 2.6.19's "status 3" output.
const realStatus3 = `TITLE	OpenVPN 2.6.19 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL]
TIME	2026-08-03 01:03:11	1785718991
HEADER	CLIENT_LIST	Common Name	Real Address	Virtual Address	Virtual IPv6 Address	Bytes Received	Bytes Sent	Connected Since	Connected Since (time_t)	Username	Client ID	Peer ID	Data Channel Cipher
CLIENT_LIST	alice	192.168.222.2:33153	10.8.0.2		13551	144610	2026-08-03 01:02:32	1785718952	UNDEF	0	0	AES-256-GCM
CLIENT_LIST	bob	203.0.113.9:51820	10.8.0.3		999	1024	2026-08-03 01:02:40	1785718960	bobuser	1	1	CHACHA20-POLY1305
HEADER	ROUTING_TABLE	Virtual Address	Common Name	Real Address	Last Ref	Last Ref (time_t)
ROUTING_TABLE	10.8.0.2	alice	192.168.222.2:33153	2026-08-03 01:03:10	1785718990
ROUTING_TABLE	192.168.99.0/24	bob	203.0.113.9:51820	2026-08-03 01:03:09	1785718989
GLOBAL_STATS	Max bcast/mcast queue length	0
GLOBAL_STATS	dco_enabled	0`

func TestParseStatus3(t *testing.T) {
	sessions, err := parseStatus3(strings.Split(realStatus3, "\n"))
	if err != nil {
		t.Fatalf("parseStatus3: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}

	alice := sessions[0]
	if alice.CommonName != "alice" {
		t.Errorf("common name is %q", alice.CommonName)
	}
	if alice.VirtualIP != netip.MustParseAddr("10.8.0.2") {
		t.Errorf("virtual IP is %s", alice.VirtualIP)
	}
	if alice.RealAddr != "192.168.222.2:33153" {
		t.Errorf("real address is %q", alice.RealAddr)
	}
	if alice.BytesReceived != 13551 || alice.BytesSent != 144610 {
		t.Errorf("byte counters are %d/%d", alice.BytesReceived, alice.BytesSent)
	}
	if alice.Cipher != "AES-256-GCM" {
		t.Errorf("cipher is %q", alice.Cipher)
	}
	if alice.Username != "" {
		t.Errorf("UNDEF username should be empty, got %q", alice.Username)
	}
	if got := alice.ConnectedSince.Unix(); got != 1785718952 {
		t.Errorf("connected since is %d", got)
	}
	// alice's routing entry is just her own address, so it is not a route.
	if len(alice.Routes) != 0 {
		t.Errorf("alice has routes %v, want none", alice.Routes)
	}

	bob := sessions[1]
	if bob.Username != "bobuser" {
		t.Errorf("bob's username is %q", bob.Username)
	}
	if bob.ClientID != 1 || bob.PeerID != 1 {
		t.Errorf("bob's ids are %d/%d", bob.ClientID, bob.PeerID)
	}
	if len(bob.Routes) != 1 || bob.Routes[0].String() != "192.168.99.0/24" {
		t.Errorf("bob's routes are %v, want [192.168.99.0/24]", bob.Routes)
	}
}

// TestParseStatus3ReordersByHeader proves the parser follows the HEADER line
// instead of fixed column positions, which is what makes it survive an
// OpenVPN upgrade that adds or moves a field.
func TestParseStatus3ReordersByHeader(t *testing.T) {
	swapped := []string{
		"HEADER\tCLIENT_LIST\tVirtual Address\tCommon Name\tBytes Sent\tBytes Received\tSomething New\tReal Address",
		"CLIENT_LIST\t10.8.0.7\tcarol\t222\t111\tignored\t198.51.100.4:1234",
	}
	sessions, err := parseStatus3(swapped)
	if err != nil {
		t.Fatalf("parseStatus3: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(sessions))
	}

	s := sessions[0]
	if s.CommonName != "carol" {
		t.Errorf("common name is %q", s.CommonName)
	}
	if s.VirtualIP != netip.MustParseAddr("10.8.0.7") {
		t.Errorf("virtual IP is %s", s.VirtualIP)
	}
	if s.BytesSent != 222 || s.BytesReceived != 111 {
		t.Errorf("byte counters are sent=%d received=%d", s.BytesSent, s.BytesReceived)
	}
	if s.RealAddr != "198.51.100.4:1234" {
		t.Errorf("real address is %q", s.RealAddr)
	}
}

func TestParseStatus3Empty(t *testing.T) {
	lines := []string{
		"TITLE\tOpenVPN 2.6.19",
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address",
		"HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name",
		"GLOBAL_STATS\tMax bcast/mcast queue length\t0",
	}
	sessions, err := parseStatus3(lines)
	if err != nil {
		t.Fatalf("parseStatus3: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("got %d sessions from an idle server, want 0", len(sessions))
	}
}

func TestParseStatus3RowBeforeHeader(t *testing.T) {
	lines := []string{"CLIENT_LIST\talice\t1.2.3.4:5\t10.8.0.2"}
	if _, err := parseStatus3(lines); err == nil {
		t.Error("expected an error when a row precedes its HEADER")
	}
}

// fakeServer speaks just enough of the protocol to exercise the client.
func fakeServer(t *testing.T, handle func(cmd string, w func(string))) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		write := func(s string) { _, _ = conn.Write([]byte(s + "\n")) }
		write(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")

		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			for _, line := range strings.Split(strings.TrimSpace(string(buf[:n])), "\n") {
				handle(strings.TrimSpace(line), write)
			}
		}
	}()
	return ln.Addr().String()
}

func TestClientStatus(t *testing.T) {
	addr := fakeServer(t, func(cmd string, w func(string)) {
		if cmd == "status 3" {
			// Interleave an async notification to prove it does not get
			// mistaken for part of the reply.
			w(">BYTECOUNT_CLI:0,1234,5678")
			for _, l := range strings.Split(realStatus3, "\n") {
				w(l)
			}
			w("END")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := Dial(ctx, addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	sessions, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}
	if sessions[0].CommonName != "alice" || sessions[1].CommonName != "bob" {
		t.Errorf("unexpected sessions: %q, %q",
			sessions[0].CommonName, sessions[1].CommonName)
	}

	// The greeting banner is a notification too, so scan past it.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case n := <-c.Notifications():
			if n.Kind == "BYTECOUNT_CLI" {
				if n.Body != "0,1234,5678" {
					t.Errorf("notification body is %q", n.Body)
				}
				return
			}
		case <-deadline:
			t.Fatal("the interleaved notification was never delivered")
		}
	}
}

func TestClientCommandError(t *testing.T) {
	addr := fakeServer(t, func(cmd string, w func(string)) {
		if strings.HasPrefix(cmd, "bytecount") {
			w("ERROR: unknown command")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := Dial(ctx, addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.EnableBytecount(ctx, 5); err == nil {
		t.Error("expected an error from a rejected command")
	}
}

func TestClientStatusTimeout(t *testing.T) {
	addr := fakeServer(t, func(cmd string, w func(string)) {}) // never replies

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(dialCtx, addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if _, err := c.Status(ctx); err == nil {
		t.Error("expected a timeout when the daemon never answers")
	}
}
