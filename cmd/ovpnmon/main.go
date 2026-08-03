// Command ovpnmon reports who is connected to an OpenVPN server and where
// their traffic is going.
//
// Identity comes from the OpenVPN management interface; traffic comes from an
// eBPF probe attached to the tun device. Run it as root on the VPN server:
//
//	ovpnmon -iface tun0 -subnet 10.8.0.0/24 -mgmt 127.0.0.1:7505
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/ubuntu/openvpn-monitoring/internal/api"
	"github.com/ubuntu/openvpn-monitoring/internal/collector"
	"github.com/ubuntu/openvpn-monitoring/internal/metrics"
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

	col, err := collector.New(collector.Config{
		Interface:    *iface,
		VPNSubnet:    prefix,
		MgmtAddr:     *mgmtAddr,
		MgmtPassword: mgmtPassword,
		PollInterval: *poll,
		FlowIdle:     *flowIdle,
		NameTTL:      *nameTTL,
		Store:        hist,
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

	var wg sync.WaitGroup
	wg.Add(2)

	var runErr, srvErr error
	go func() {
		defer wg.Done()
		runErr = col.Run(ctx)
	}()
	go func() {
		defer wg.Done()
		srv := api.New(col, reg, hist, log)
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
