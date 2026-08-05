// Command ovpnmon reports who is connected to an OpenVPN server and where
// their traffic is going.
//
// Identity comes from the OpenVPN management interface; traffic comes from an
// eBPF probe attached to the tun device. Run it as root on the VPN server:
//
//	ovpnmon -iface tun0 -subnet 10.8.0.0/24 -mgmt 127.0.0.1:7505
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/ubuntu/openvpn-monitoring/internal/access"
	"github.com/ubuntu/openvpn-monitoring/internal/api"
	"github.com/ubuntu/openvpn-monitoring/internal/cloudstack"
	"github.com/ubuntu/openvpn-monitoring/internal/collector"
	"github.com/ubuntu/openvpn-monitoring/internal/enrich"
	"github.com/ubuntu/openvpn-monitoring/internal/metrics"
	"github.com/ubuntu/openvpn-monitoring/internal/pki"
	"github.com/ubuntu/openvpn-monitoring/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ovpnmon: %v\n", err)
		os.Exit(1)
	}
}

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usageText = `ovpnmon %s - who is on the VPN, and where their traffic is going.

Identity comes from the OpenVPN management interface; traffic comes from an
eBPF probe attached to the tun device. Both are joined into a live dashboard,
a JSON API and Prometheus metrics.

Usage:
  ovpnmon [options]

Requires root (or CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON), Linux 6.6 or newer
for TCX attachment, and an OpenVPN server with "management" enabled. On
OpenVPN 2.6 the server also needs "disable-dco", otherwise the data channel
bypasses the tun device this probe watches.

Options:
`

const examplesText = `
Once running, on the -listen address:
  /                 live dashboard
  /api/snapshot     sessions, destinations and probe stats as JSON
  /api/stream       WebSocket event stream
  /metrics          Prometheus metrics
  /healthz          management interface reachability

Examples:
  # Defaults: tun0, 10.8.0.0/24, dashboard on localhost:9090
  sudo ovpnmon

  # A server using a different subnet and management port
  sudo ovpnmon -iface tun1 -subnet 10.9.0.0/22 -mgmt 127.0.0.1:5555

  # Expose the dashboard on the LAN; put authentication in front of it,
  # since this endpoint reveals every user's browsing destinations.
  sudo ovpnmon -listen 0.0.0.0:9090

  # Keep metric cardinality down on a busy server
  sudo ovpnmon -top-destinations 5

  # Retain 90 days of audit history in SQLite. Without -store nothing is
  # written to disk and history disappears on restart.
  sudo ovpnmon -store sqlite:/var/lib/ovpnmon/history.db -retention 2160h

  # Use an existing MySQL server instead
  sudo ovpnmon -store 'mysql://ovpnmon:secret@tcp(127.0.0.1:3306)/ovpnmon'
`

func run() error {
	var (
		iface      = flag.String("iface", "tun0", "tun interface to attach the eBPF probe to")
		subnet     = flag.String("subnet", "10.8.0.0/24", "VPN client subnet, in CIDR form")
		mgmtAddr   = flag.String("mgmt", "127.0.0.1:7505", "OpenVPN management interface address")
		mgmtPwFile = flag.String("mgmt-password-file", "", "file holding the management password, when OpenVPN was started with one")
		listen     = flag.String("listen", "127.0.0.1:9090", "address for the dashboard, API and metrics")
		topDest    = flag.Int("top-destinations", 20, "per-client destinations to expose as metrics (0 disables)")
		flowIdle   = flag.Duration("flow-idle", 5*time.Minute, "drop flows idle for longer than this")
		nameTTL    = flag.Duration("name-ttl", 30*time.Minute, "how long a resolved destination name stays valid")
		poll       = flag.Duration("poll", time.Second, "how often to poll the management interface")
		logLevel   = flag.String("log-level", "info", "debug, info, warn or error")
		showVer    = flag.Bool("version", false, "print the version and exit")

		storeDSN  = flag.String("store", "", "history database: sqlite:<path> or mysql://<dsn> (empty disables history)")
		retention = flag.Duration("retention", 30*24*time.Hour, "delete history older than this (0 keeps everything)")

		pkiIndex = flag.String("pki-index", "", "easy-rsa index.txt, for listing users who have never connected (auto-detected when empty)")
		serverCN = flag.String("server-cn", "server", "common name of the server's own certificate, excluded from the user list")

		authUser     = flag.String("auth-user", "admin", "dashboard login name")
		authHash     = flag.String("auth-password-hash", "", "bcrypt hash of the dashboard password; empty leaves the dashboard open")
		authTTL      = flag.Duration("auth-session-ttl", 12*time.Hour, "how long a dashboard login lasts")
		metricsToken = flag.String("metrics-token", "", "bearer token letting Prometheus scrape /metrics without a login")
		hashPassword = flag.String("hash-password", "", "print a bcrypt hash for the given password and exit")

		csURL      = flag.String("cloudstack-url", "", "CloudStack API endpoint, e.g. http://cs:8080/client/api (empty disables the integration)")
		csKey      = flag.String("cloudstack-api-key", "", "CloudStack API key")
		csSecret   = flag.String("cloudstack-secret-key", "", "CloudStack secret key")
		csRefresh  = flag.Duration("cloudstack-refresh", time.Minute, "how often to reload the CloudStack view")
		csInsecure = flag.Bool("cloudstack-insecure", false, "skip TLS verification for the CloudStack endpoint")

		ccdDir = flag.String("ccd-dir", "",
			"OpenVPN's client-config-dir, enabling temporary blocking (auto-detected from the server config when empty)")
		blockCheck = flag.Duration("block-check", 15*time.Second,
			"how often expired blocks are lifted")

		manageCerts = flag.Bool("manage-certificates", false, "allow issuing and revoking client certificates from the dashboard")
		serverConf  = flag.String("server-conf", "/etc/openvpn/server/server.conf", "OpenVPN config, checked for crl-verify when revoking")
		vpnHost     = flag.String("vpn-host", "", "address clients use to reach this VPN, written into generated profiles (defaults to this host's outbound address)")
		vpnPort     = flag.Int("vpn-port", 1194, "port written into generated profiles")
		vpnProto    = flag.String("vpn-proto", "udp", "protocol written into generated profiles")

		configPath = flag.String("config", defaultConfigPath, "configuration file; command-line flags win over it")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usageText, version)
		flag.PrintDefaults()
		fmt.Fprint(flag.CommandLine.Output(), examplesText)
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("ovpnmon %s\n", version)
		return nil
	}
	if *hashPassword != "" {
		h, err := api.HashPassword(*hashPassword)
		if err != nil {
			return fmt.Errorf("hashing password: %w", err)
		}
		fmt.Printf("auth-password-hash = %s\n", h)
		return nil
	}
	if flag.NArg() > 0 {
		flag.Usage()
		return fmt.Errorf("unexpected argument %q", flag.Arg(0))
	}
	if err := applyConfig(*configPath); err != nil {
		return err
	}

	level := slog.LevelInfo
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("invalid -log-level %q: want debug, info, warn or error", *logLevel)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	prefix, err := netip.ParsePrefix(*subnet)
	if err != nil {
		return fmt.Errorf("invalid -subnet %q: %w", *subnet, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var hist *store.Store
	if *storeDSN != "" {
		hist, err = store.Open(ctx, store.Config{
			DSN:       *storeDSN,
			Retention: *retention,
		}, log)
		if err != nil {
			return err
		}
		defer hist.Close()
		log.Info("history enabled",
			"backend", hist.Dialect(), "retention", *retention)
	}

	// OpenVPN's management password lives in a file so it never appears in a
	// process listing or in this config.
	var mgmtPassword string
	if *mgmtPwFile != "" {
		raw, err := os.ReadFile(*mgmtPwFile)
		if err != nil {
			return fmt.Errorf("reading -mgmt-password-file: %w", err)
		}
		mgmtPassword = strings.TrimRight(string(raw), "\r\n")
	}

	// An identity source is optional. Without one the core has no idea
	// CloudStack exists; with one, users and destinations gain a second
	// dimension - who they are in the infrastructure, not just on the wire.
	var enricher enrich.Provider
	if *csURL != "" {
		p, err := cloudstack.NewProvider(cloudstack.Config{
			URL:                *csURL,
			APIKey:             *csKey,
			SecretKey:          *csSecret,
			InsecureSkipVerify: *csInsecure,
		}, log)
		if err != nil {
			return fmt.Errorf("cloudstack: %w", err)
		}

		probe, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = p.Ping(probe)
		cancel()
		if err != nil {
			// Not fatal: the VPN is still worth watching if CloudStack is
			// unreachable, and the provider retries on its own schedule.
			log.Warn("cloudstack unreachable; continuing without it", "error", err)
		}

		go p.Run(ctx, *csRefresh)
		enricher = p
		log.Info("cloudstack integration enabled", "url", *csURL, "refresh", *csRefresh)
	}

	col, err := collector.New(collector.Config{
		Interface:    *iface,
		VPNSubnet:    prefix,
		MgmtAddr:     *mgmtAddr,
		MgmtPassword: mgmtPassword,
		PollInterval: *poll,
		FlowIdle:     *flowIdle,
		NameTTL:      *nameTTL,
		Store:        hist,
		Enricher:     enricher,
	}, log)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("%w\n\nLoading and attaching the probe needs root, "+
				"or CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON", err)
		}
		return err
	}
	defer col.Close()

	log.Info("eBPF probe attached", "interface", *iface, "subnet", prefix)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		metrics.NewExporter(col, *topDest),
	)
	if hist != nil {
		reg.MustRegister(metrics.NewStoreExporter(hist))
	}

	guard, err := api.NewAuth(api.AuthConfig{
		User:         *authUser,
		PasswordHash: *authHash,
		MetricsToken: *metricsToken,
		TTL:          *authTTL,
	})
	if err != nil {
		return err
	}
	if guard == nil {
		log.Warn("dashboard has no authentication",
			"hint", "set auth-password-hash; generate one with 'ovpnmon -hash-password <password>'")
	} else {
		log.Info("dashboard authentication enabled", "user", *authUser)
	}

	// Temporary blocking needs somewhere OpenVPN actually reads. Without a
	// client-config-dir the feature stays off rather than accepting blocks it
	// cannot enforce.
	var blocker *access.Manager
	if dir := resolveCCD(*ccdDir, *serverConf, log); dir != "" {
		if hist == nil {
			log.Warn("ignoring client-config-dir: blocking needs history enabled (-store), "+
				"so a block has somewhere to expire from", "dir", dir)
		} else if m, err := access.New(dir, hist, col, log); err != nil {
			log.Warn("temporary blocking unavailable", "error", err)
		} else {
			blocker = m
			go blocker.Run(ctx, *blockCheck)
			log.Info("temporary blocking enabled", "client_config_dir", dir)
		}
	}

	// Certificate management stays off unless asked for: it runs easyrsa as
	// root and hands out private keys, which is a different level of authority
	// from watching traffic.
	var certMgr *pki.Manager
	if *manageCerts {
		certMgr = pki.FindManager(*pkiIndex)
		switch {
		case certMgr == nil:
			log.Warn("certificate management requested but no easy-rsa installation was found",
				"hint", "set pki-index to the index.txt of the PKI to manage")
		default:
			certMgr.RemoteHost = *vpnHost
			if certMgr.RemoteHost == "" {
				certMgr.RemoteHost = outboundAddr()
			}
			certMgr.RemotePort, certMgr.Proto = *vpnPort, *vpnProto
			log.Info("certificate management enabled",
				"pki", certMgr.Dir, "profiles_point_at", certMgr.RemoteHost)
			if !certMgr.CRLActive(*serverConf) {
				log.Warn("server config has no crl-verify; revoking a certificate will not stop that client connecting",
					"config", *serverConf)
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var runErr, srvErr error
	go func() {
		defer wg.Done()
		runErr = col.Run(ctx)
	}()
	go func() {
		defer wg.Done()
		srv := api.New(col, reg, hist, log).
			WithPKI(*pkiIndex, *serverCN).
			WithAuth(guard).
			WithCertManager(certMgr, *serverConf).
			WithEnricher(enricher).
			WithBlocking(blocker)
		srvErr = api.Serve(ctx, *listen, srv.Handler(), log)
	}()

	wg.Wait()

	if srvErr != nil {
		return srvErr
	}
	if runErr != nil && ctx.Err() == nil {
		return runErr
	}
	log.Info("shut down cleanly")
	return nil
}

// outboundAddr reports the address this host uses to reach the internet, which
// is the best guess for what a client should connect to.
func outboundAddr() string {
	c, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		return ""
	}
	defer c.Close()
	host, _, _ := net.SplitHostPort(c.LocalAddr().String())
	return host
}

// resolveCCD finds the client-config directory OpenVPN is actually using.
//
// Reading it out of the server configuration rather than asking the operator
// to repeat it means the two cannot drift apart - a directory ovpnmon writes
// to but OpenVPN does not read would make every block silently do nothing.
func resolveCCD(explicit, serverConf string, log *slog.Logger) string {
	if explicit != "" {
		return explicit
	}
	if serverConf == "" {
		return ""
	}

	f, err := os.Open(serverConf)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "client-config-dir") {
			continue
		}
		dir := strings.TrimSpace(strings.TrimPrefix(line, "client-config-dir"))
		dir = strings.Trim(dir, `"'`)
		if dir == "" {
			continue
		}
		// OpenVPN resolves a relative path against its own working directory,
		// which is where the server config lives.
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(serverConf), dir)
		}
		log.Debug("found client-config-dir", "dir", dir, "from", serverConf)
		return dir
	}
	return ""
}
