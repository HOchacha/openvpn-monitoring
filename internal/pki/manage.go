package pki

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Manager issues and revokes client certificates through easy-rsa.
//
// This drives the same easyrsa commands an operator would run by hand, in the
// same directory, so a PKI created by any of the common installers keeps
// working and nothing here invents its own layout.
type Manager struct {
	// Dir is the easy-rsa directory holding the easyrsa script and pki/.
	Dir string

	// ServerDir is where OpenVPN reads ca.crt, tls-crypt.key and crl.pem.
	// Revocation has to copy the regenerated CRL here or it has no effect.
	ServerDir string

	// Remote is what a generated profile connects to.
	RemoteHost string
	RemotePort int
	Proto      string
}

// validName bounds what can become a filename, a certificate subject, and an
// argument to a subprocess.
//
// This is not about trusting the operator. A common name reaches the
// filesystem as pki/issued/<name>.crt, so "../../etc/whatever" has to be
// impossible regardless of who typed it.
var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ValidateName reports whether a common name is safe to use.
func ValidateName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("name is empty")
	case !validName.MatchString(name):
		return fmt.Errorf("name %q must be 1-64 characters of letters, digits, dot, dash or underscore, starting with a letter or digit", name)
	case name == "ca", name == "server":
		return fmt.Errorf("%q is reserved for the CA and server certificates", name)
	case strings.Contains(name, ".."):
		return fmt.Errorf("name may not contain %q", "..")
	}
	return nil
}

// FindManager locates an easy-rsa installation, given an index path or by
// searching the usual places.
func FindManager(indexPath string) *Manager {
	if indexPath == "" {
		indexPath = Find()
	}
	if indexPath == "" {
		return nil
	}

	// index.txt lives at <dir>/pki/index.txt.
	dir := filepath.Dir(filepath.Dir(indexPath))
	if _, err := os.Stat(filepath.Join(dir, "easyrsa")); err != nil {
		return nil
	}

	m := &Manager{Dir: dir, RemotePort: 1194, Proto: "udp"}

	// OpenVPN's own directory is usually the parent, or a sibling "server".
	for _, candidate := range []string{
		filepath.Dir(dir),
		filepath.Join(filepath.Dir(dir), "server"),
	} {
		if _, err := os.Stat(filepath.Join(candidate, "ca.crt")); err == nil {
			m.ServerDir = candidate
			break
		}
	}
	if m.ServerDir == "" {
		m.ServerDir = filepath.Dir(dir)
	}
	return m
}

// run executes easyrsa with the arguments given. Arguments are passed as a
// slice, never through a shell, so a name cannot become a command.
func (m *Manager) run(ctx context.Context, args ...string) (string, error) {
	// easy-rsa 3.1 requires EASYRSA_TEMP_DIR to be set *and* to exist; it fails
	// with "secure_session failed" otherwise. Interactive use inherits a
	// working value from the shell, which is why this only shows up under a
	// service manager.
	//
	// It has to sit beside the PKI rather than in /tmp: easyrsa moves finished
	// keys out of it, and with PrivateTmp the system /tmp is a different
	// filesystem, which fails with "Failed to move key temp-file".
	tmp, err := os.MkdirTemp(m.Dir, ".easyrsa-tmp-")
	if err != nil {
		return "", fmt.Errorf("creating easyrsa temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	cmd := exec.CommandContext(ctx, "./easyrsa", args...)
	cmd.Dir = m.Dir
	cmd.Env = append(os.Environ(),
		"EASYRSA_BATCH=1",
		"EASYRSA_CERT_EXPIRE=3650",
		"EASYRSA_TEMP_DIR="+tmp,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("easyrsa %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// Issue creates a client certificate. It is an error if one already exists,
// because silently reusing a name would hand out a second profile for an
// identity someone already holds.
func (m *Manager) Issue(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "pki", "issued", name+".crt")); err == nil {
		return fmt.Errorf("a certificate for %q already exists", name)
	}

	if out, err := m.run(ctx, "build-client-full", name, "nopass"); err != nil {
		return fmt.Errorf("%w\n%s", err, easyrsaError(out))
	}
	return nil
}

// Revoke invalidates a certificate and republishes the CRL.
//
// Regenerating the CRL is not enough on its own: OpenVPN reads the copy in its
// own directory, and does so on every client connection after dropping
// privileges, so the file has to be placed there and be readable by the user
// it runs as. Skipping either step leaves a revocation that looks successful
// and changes nothing.
func (m *Manager) Revoke(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "pki", "issued", name+".crt")); err != nil {
		return fmt.Errorf("no certificate for %q", name)
	}

	if out, err := m.run(ctx, "revoke", name); err != nil {
		return fmt.Errorf("%w\n%s", err, easyrsaError(out))
	}
	if out, err := m.run(ctx, "--days=3650", "gen-crl"); err != nil {
		return fmt.Errorf("%w\n%s", err, easyrsaError(out))
	}

	src := filepath.Join(m.Dir, "pki", "crl.pem")
	dst := filepath.Join(m.ServerDir, "crl.pem")
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading regenerated CRL: %w", err)
	}
	// 0644 rather than chown: OpenVPN re-reads this file on every client
	// connection, after dropping to an unprivileged user, so it has to be
	// world-readable one way or the other. A CRL is public by design - it is
	// published so clients can check it - and chown would need CAP_CHOWN,
	// which this process deliberately does not hold.
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return fmt.Errorf("publishing CRL to %s: %w", dst, err)
	}
	return nil
}

// CRLActive reports whether the server config actually verifies the CRL.
//
// Without crl-verify a revocation is recorded and enforced by nothing: the
// holder keeps connecting. Worth surfacing, because the operation otherwise
// reports success.
func (m *Manager) CRLActive(serverConf string) bool {
	data, err := os.ReadFile(serverConf)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "crl-verify") {
			return true
		}
	}
	return false
}

// Profile renders a client .ovpn with the certificate and key inlined.
func (m *Manager) Profile(ctx context.Context, name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}

	read := func(parts ...string) (string, error) {
		b, err := os.ReadFile(filepath.Join(parts...))
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\n"), nil
	}

	ca, err := read(m.Dir, "pki", "ca.crt")
	if err != nil {
		return "", fmt.Errorf("reading CA certificate: %w", err)
	}
	key, err := read(m.Dir, "pki", "private", name+".key")
	if err != nil {
		return "", fmt.Errorf("reading private key for %q: %w", name, err)
	}

	// The issued file carries the full text of the signing session; keep only
	// the certificate itself so clients that parse strictly are happy.
	rawCert, err := read(m.Dir, "pki", "issued", name+".crt")
	if err != nil {
		return "", fmt.Errorf("reading certificate for %q: %w", name, err)
	}
	cert := rawCert
	if i := strings.Index(cert, "-----BEGIN CERTIFICATE-----"); i >= 0 {
		cert = cert[i:]
	}

	var b strings.Builder
	fmt.Fprintf(&b, "client\ndev tun\nproto %s\nremote %s %d\n",
		m.Proto, m.RemoteHost, m.RemotePort)
	b.WriteString("resolv-retry infinite\nnobind\npersist-key\npersist-tun\n")
	b.WriteString("remote-cert-tls server\nverb 3\n")
	fmt.Fprintf(&b, "# issued by ovpnmon %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "<ca>\n%s\n</ca>\n<cert>\n%s\n</cert>\n<key>\n%s\n</key>\n", ca, cert, key)

	// tls-crypt or tls-auth, whichever this server uses.
	for _, tc := range []struct{ file, tag string }{
		{"tls-crypt.key", "tls-crypt"},
		{"tc.key", "tls-crypt"},
		{"ta.key", "tls-auth"},
	} {
		if v, err := read(m.ServerDir, tc.file); err == nil {
			fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", tc.tag, v, tc.tag)
			if tc.tag == "tls-auth" {
				b.WriteString("key-direction 1\n")
			}
			break
		}
	}
	return b.String(), nil
}

// easyrsaError pulls the useful part out of easyrsa's output.
//
// It prints "Easy-RSA error:" with the reason, then a version banner. The
// banner comes last, so taking the tail of the output shows the build date and
// hides what went wrong.
func easyrsaError(out string) string {
	if i := strings.Index(out, "Easy-RSA error:"); i >= 0 {
		msg := out[i:]
		if j := strings.Index(msg, "Generated:"); j > 0 {
			msg = msg[:j]
		}
		return strings.TrimSpace(msg)
	}
	return lastLines(out, 12)
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
