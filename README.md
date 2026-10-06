# ovpnmon

Tracks, in real time, **who is connected** to an OpenVPN server and **where
those users are going** through the VPN.

<img width="1086" height="546" alt="image" src="https://github.com/user-attachments/assets/07629af2-1eac-438f-ad66-674483cc5196" />


## Requirements

Check first — this installs nothing and only reports the current state:

```bash
make deps-check
```

```
==> Kernel
  ok      kernel 6.8.0           TCX attachment needs >= 6.6
  ok      BTF                    /sys/kernel/btf/vmlinux present
==> Build toolchain
  ok      go 1.26.5              go.mod needs 1.26.5
  ...
```

If something is missing:

```bash
make deps            # build toolchain (installs Go from the official tarball if needed)
make deps-dev        # test and benchmark tools (bpftrace, iperf3, jq …)
make deps-all        # both of the above
```

`make deps` decides the required Go version by **reading it from `go.mod`**. If
the distribution's Go is too old (Ubuntu 24.04 ships 1.22, for example), it
downloads the official tarball, verifies its sha256, and installs it to
`/usr/local/go`. If the existing Go is new enough, it does nothing. It knows
apt, dnf, yum and pacman; on other distributions it prints the list of packages
you need.

In short, the requirements are:

- Linux kernel **6.6 or newer** (TCX hooks). BTF (`/sys/kernel/btf/vmlinux`) required
- OpenVPN 2.4 or newer, with the management interface enabled
- Build: Go (version per `go.mod`)
- **Only to recompile the eBPF**: clang 15+, `libbpf-dev`. The compiled object
  is checked into the repository, so you do not need these unless you edit
  `bpf/ovpnmon.bpf.c`
- Runtime: root, or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`

> **OpenVPN 2.6 DCO caveat.** When Data Channel Offload is on, the data path
> moves into the `ovpn-dco` kernel module and no longer passes through the tun
> device. The server config then needs `disable-dco`, and `make preflight`
> checks for it.

> **The management interface accepts only one connection at a time.** While
> ovpnmon is attached, connecting directly with `telnet 127.0.0.1 7505` will
> succeed but hang with no reply. If you need to diagnose by hand, either
> `systemctl stop ovpnmon` first and then attach, or read the same data from
> `/api/snapshot`. For the same reason ovpnmon cannot share the port with
> another OpenVPN monitoring tool.

## Quick start

**Building the OpenVPN server itself is out of scope for this repository.** Use
whatever you already use — if you have nothing,
[Nyr/openvpn-install](https://github.com/Nyr/openvpn-install) is a good default.
It handles NAT, IP forwarding and persistent firewall rules for you.

Assuming the VPN is already running:

```bash
git clone https://github.com/HOchacha/openvpn-monitoring
cd openvpn-monitoring

make preflight       # what the OpenVPN side needs, and whether a restart is required
make install         # build + install into /opt/ovpnmon
sudo systemctl enable --now ovpnmon
```

As `make preflight` reports, you may need to add **two lines** to the OpenVPN
config. That is all:

```
management 127.0.0.1 7505     # required — without it there is no "who"
disable-dco                   # only on OpenVPN 2.6+
```

> The `server.conf` the Nyr script generates has neither line, so you will need
> to add them. After adding them OpenVPN must be restarted once, and **that
> disconnects everyone.** Installing, starting or stopping ovpnmon itself has no
> effect on existing connections.

## Deployment detail

### 1. Inspect — changes nothing

```bash
make deps-check   # kernel, BTF, toolchain
make preflight    # what the OpenVPN side needs, and whether it interrupts
```

`make preflight` only reads state. The most important thing it tells you is
**whether OpenVPN needs a restart** — a restart disconnects every client.

```
Kernel
  ok       kernel 6.8.0             TCX attachment requires >= 6.6
  ok       BTF                      present
OpenVPN
  ok       openvpn 2.6.19           pid 439876
  ok       config                   /etc/openvpn/server/server.conf
  ok       management               127.0.0.1:7505
  ok       DCO                      already disabled in config
Tunnel
  ok       tun0                     10.8.0.1/24
           suggested ovpnmon settings:  iface = tun0   subnet = 10.8.0.0/24

Verdict
  Ready. OpenVPN needs no changes, so nothing disconnects.
```

### Changes needed on the OpenVPN side

**Two lines is all it is.** And if they are already there, you change nothing.

```
management 127.0.0.1 7505     # required — without it there is no "who"
disable-dco                   # only on OpenVPN 2.6+
```

`disable-dco` is needed because when Data Channel Offload is on, the data path
moves into a kernel module and **no longer passes through the tun device**. The
probe still attaches fine but counts nothing.

If the server has a password on its management interface
(`management <host> <port> <pwfile>`), point ovpnmon at the same file:

```ini
mgmt-password-file = /etc/openvpn/mgmt-password
```

**Nothing else changes:**

- No `status`/`status-version` settings needed — it requests `status 3` over
  management directly
- It does not touch PKI, certificates, or the auth flow
- It does not touch routing, firewall or NAT (a running server already has those)
- It cannot disconnect or block clients — the only commands it sends are
  `status 3` and `exit`

> The management interface accepts **only one connection at a time**. If another
> tool (openvpn-monitor, your own script, …) is already attached, they cannot
> coexist and you must remove the other one. And because this interface can kill
> sessions, always bind it to loopback.

### When it interrupts and when it does not

| Action | Effect |
|---|---|
| Install / start / stop ovpnmon | **No interruption.** Attaching the eBPF probe does not touch existing connections |
| Add `management` to OpenVPN | **All clients disconnect** (OpenVPN restart required) |
| Add `disable-dco` to OpenVPN | **All clients disconnect** (same) |

If preflight says `Ready`, you do not need to touch OpenVPN and nobody is
disconnected. If it says a change is needed, schedule a maintenance window. You
can reduce interruptions to a single one by **making the OpenVPN change first
and installing ovpnmon whenever you like afterward.**

### 2. Install — no interruption

```bash
make deps                    # build tools such as Go (only if missing)
make install                 # build, then install into /opt/ovpnmon
```

Adjust the config and start it. `preflight.sh` will already have told you the
`iface` and `subnet` for this host:

```bash
sudo vi /opt/ovpnmon/etc/ovpnmon.conf
sudo systemctl enable --now ovpnmon
```

Verify:

```bash
curl -s localhost:9095/healthz
curl -s localhost:9095/api/snapshot | jq '.sessions[].common_name'
```

### 3. Optional — Prometheus / Grafana

```bash
make observability
```

### Upgrading

```bash
git pull
make install
sudo systemctl restart ovpnmon
```

`make install` **does not overwrite your existing config** — it drops the new
defaults alongside as `ovpnmon.conf.default` so you can diff them. The history
DB is left as is too. During the restart, flow aggregation pauses briefly (the
kernel map is cleared), but everything already recorded to history survives.

**Do not restart OpenVPN** — it is not needed, and it is the only thing that
disconnects users.

> If you would rather not keep build tools on the production server, you can
> copy just the single `ovpnmon` binary built with `make build` on a build
> machine. The eBPF object is embedded inside it, so the target server needs
> neither Go, nor clang, nor kernel headers. Pull the rest of the files (the
> sample config, the systemd unit) from the repository.

### Test client

The server config pushes `redirect-gateway`, so **simply starting a client on
the same host moves the host's default route into the tunnel and kills your SSH
session.** `dev/test-client.sh` isolates the client in a network namespace to
remove that risk.

```bash
sudo ./dev/test-client.sh up alice
sudo ./dev/test-client.sh exec alice -- curl -s https://example.com -o /dev/null
sudo ./dev/test-client.sh down alice
```

## Interfaces

| Path | Contents |
|---|---|
| `/` | Live web dashboard (Live / History tabs) |
| `/api/snapshot` | Full sessions, destinations and probe stats |
| `/api/sessions` | Session list (filter with `?common_name=alice`) |
| `/api/events` | Recent live events (in memory) |
| `/api/users` | **All users** — PKI issued + connection history + currently connected |
| `PUT /api/users/{cn}/note` | Save a user note (empty value deletes it) |
| `POST /api/login` · `/api/logout` | Dashboard login |
| `POST /api/sessions/{cid}/kill` | Force-disconnect a session |
| `POST /api/certificates` | Issue a certificate |
| `DELETE /api/certificates/{cn}` | Revoke a certificate (+ refresh the CRL) |
| `GET /api/certificates/{cn}/profile` | Download the `.ovpn` |
| `/api/stream` | WebSocket live stream |
| `/api/history/hosts` | **Who went where** — per-destination aggregate |
| `/api/history/countries` | **Where in the world** — per-country aggregate (needs a GeoIP database) |
| `/api/history/sessions` | Connection history |
| `/api/history/destinations` | Per-session destination detail |
| `/api/history/events` | Stored DNS/TLS/HTTP observations |
| `/api/history/stats` | Storage status and write health |
| `/api/enrichment` | State of the optional identity source, if one is wired |
| `/metrics` | Prometheus metrics |
| `/healthz` | Management interface reachability |

`/api/history/*` exists only when `-store` is set.

Key metrics:

```
openvpn_sessions                                            currently connected users
openvpn_session_info{common_name,virtual_ip,real_address}   connected-user identity
openvpn_client_bytes{common_name,direction}                 cleartext bytes inside the tunnel
openvpn_tunnel_bytes{common_name,direction}                 encrypted bytes as counted by OpenVPN
openvpn_destination_bytes{common_name,hostname,port,...}    per-destination bytes
openvpn_probe_events_lost                                   ring-buffer loss (should be 0)
```

`openvpn_destination_bytes` can blow up cardinality, so it exposes only the top
N per client and sums the rest into `hostname="other"` (`-top-destinations`,
default 20, `0` disables).

## What gets installed

### Daemon

| Unit | Runs as | Role |
|---|---|---|
| `ovpnmon` | root | eBPF probe + dashboard/API/metrics |

The OpenVPN server itself and its firewall rules are managed by the OpenVPN
install script.

### Files

Everything ovpnmon owns lives **in one place, under `/opt/ovpnmon`**. Nothing is
scattered across system directories.

```
/opt/ovpnmon/
├── bin/ovpnmon                 binary (eBPF object embedded, ~25MB)
├── etc/ovpnmon.conf            ★ config (0640) — this is the only file you edit
├── etc/firewall.conf           subnet and interface
├── data/history.db{,-wal,-shm} ★ connection history (0600, dir 0700)
└── README.md
```

By OS convention, the only thing that has to live elsewhere is the systemd unit:

```
/etc/systemd/system/ovpnmon.service
```

The unit passes only `-config` and keeps all other settings in
`etc/ovpnmon.conf`, so **you never edit the unit file to change configuration.**

Removal leaves no trace:

```bash
make uninstall   # remove binary, config and unit; keep data/ history
make purge       # delete /opt/ovpnmon entirely
```

> The files below are created by the OpenVPN install script. They are unrelated
> to ovpnmon and not managed here.
>
> ```
> /etc/openvpn/server/{server.conf,ca.crt,server.crt}
> /etc/openvpn/server/server.key            ★ server private key
> /etc/openvpn/server/tls-crypt.key         ★ control-channel pre-shared key
> /etc/openvpn/easy-rsa/pki/                ★★ the whole PKI, including the CA private key
> /etc/openvpn/client-profiles/*.ovpn       ★★ contain client private keys
> /var/log/openvpn/{server,status}.log, ipp.txt
> /etc/sysctl.d/99-openvpn-forward.conf     net.ipv4.ip_forward = 1
> /etc/logrotate.d/openvpn                  weekly rotation, 8 weeks retained
> ```
>
> Of the ★★ items, if `easy-rsa/pki/private/ca.key` leaks, anyone can issue a
> valid client certificate and the entire authentication scheme collapses. In
> production the standard practice is to keep the CA on an offline machine.

### State that exists only in the kernel (not files)

```
tun0                       VPN interface
2 eBPF programs            TCX ingress/egress on tun0
5 BPF maps                 flows, sessions, events, probe_stats, scratch
```

These vanish on reboot and are re-attached when the `ovpnmon` service starts.
The VPN's NAT and forwarding rules are managed by the OpenVPN install script.

### Build-only requirements

`/usr/local/go` and the `clang`/`libbpf-dev` packages are build-only. Because
the eBPF object is embedded in the binary, **the deployment target does not need
them.**

### Disk usage

The history DB is the only thing that keeps growing. Roughly, it is on the order
of a few hundred KB per user per day, with `-retention` (default 30 days)
setting the ceiling. Most of it is the `events` table, so if space is a concern,
shortening the retention window is the most effective lever.

## Prometheus / Grafana

You can scrape `/metrics` directly, but to get dashboards and alerting in one
step:

```bash
make observability      # install Prometheus + Grafana, provisioning included
```

| | Address | Note |
|---|---|---|
| ovpnmon | `127.0.0.1:9095` | yields 9090 to Prometheus and moves |
| Prometheus | `127.0.0.1:9090` | |
| Grafana | `127.0.0.1:3000` | first login `admin` / `admin` |

The default is loopback. Reach it over an SSH tunnel:

```bash
ssh -N -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 ubuntu@<host>
```

### To expose it externally

Edit `deploy/observability/observability.conf` and re-apply:

```ini
bind_addr       = 0.0.0.0
prometheus_port = 9091      # if 9090 is already taken
```

```bash
make observability-config
```

**Before exposing it, without fail:**

1. **Change the Grafana password.** Leaving the default `admin/admin` open is an
   immediate risk.
   ```bash
   sudo grafana-cli admin reset-admin-password '<new password>'
   ```
2. **ovpnmon and Prometheus have no authentication at all.** Restrict access by
   address with a firewall, or put a reverse proxy in front. Both endpoints hand
   out the list of destination hostnames per user verbatim.
   ```bash
   sudo iptables -A INPUT -p tcp --dport 9095 -s <admin range> -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 9095 -j DROP
   ```

### The repository is the source of truth for configuration

Dashboards made by clicking around disappear with the Grafana DB. Here
everything is a file:

```
deploy/observability/
├── install.sh
├── prometheus/
│   ├── ovpnmon-scrape.yml      scrape config
│   └── ovpnmon.rules.yml       alerting + recording rules
└── grafana/
    ├── datasource.yml
    ├── dashboard-provider.yml
    └── dashboards/ovpnmon.json
```

The dashboard is provisioned with `allowUiUpdates: false` — edits made in the UI
revert to the file contents within 30 seconds. **Edit the JSON and run `make
observability-config`.** That way the same dashboard reappears even if you
rebuild the host.

On the Prometheus side too, rather than editing `prometheus.yml` directly, it
references drop-ins via `scrape_config_files` and `rule_files`, so a package
upgrade or another job is unaffected.

### Dashboard

`VPN / OpenVPN — sessions and destinations`. Filterable by server and user
variables.

- **Health** — connected users, management reachability, up/download **rate and
  cumulative**, tracked flows, lost events
- **Who** — per-user throughput (download drawn negative to separate direction),
  connected-user table (certificate CN, VPN IP, connection source, cipher,
  connection time)
- **Where** — top-20 destination table, per-destination traffic trend, new
  connections per user
- **Probe and history** — packets inspected, name-resolution status, history
  write status

### Alerting

It watches whether the monitor itself can be trusted. **A monitor that has gone
silently blind is worse than none** — because the dashboard still looks fine.

| Alert | Meaning |
|---|---|
| `OvpnmonDown` | Collection fully stopped (if the process dies, the eBPF drops too) |
| `OvpnmonManagementUnreachable` | Traffic is counted but not attributed to users |
| `OvpnmonRingBufferOverflow` | DNS/TLS observations lost → destinations remain IP-only |
| `OvpnmonProbeSeeingNoTraffic` | Users are connected but no packets are seen (wrong interface or DCO) |
| `OvpnmonHistoryWritesFailing` | Holes in the audit log |
| `OvpnmonHistoryEventsDropped` | History lost under load (writes are non-blocking by design) |

Alertmanager is a separate setup. Install the `prometheus-alertmanager` package
and check `alerting.alertmanagers` in `/etc/prometheus/prometheus.yml`.

## History (audit log)

The kernel flow map holds **only the current state**. A conversation that goes
quiet disappears after `-flow-idle`, and everything is gone on restart. Turning
on `-store` keeps that content in a database, so you can ask "who connected to
what last week".

```bash
# SQLite (the recommended default — one file, no external dependency)
ovpnmon -store sqlite:/var/lib/ovpnmon/history.db -retention 720h

# Use an existing MySQL
ovpnmon -store 'mysql://ovpnmon:secret@tcp(127.0.0.1:3306)/ovpnmon?parseTime=true'
```

Three tables answer three different questions:

| Table | Contents |
|---|---|
| `sessions` | who connected, from which IP, and for how long |
| `destinations` | per session, how much traffic went to which destination |
| `events` | individual DNS lookups, TLS connections, HTTP requests |

Query examples:

```bash
# Destinations alice reached in the last 7 days
curl -s 'localhost:9090/api/history/hosts?common_name=alice&since=7d' | jq

# Everyone who reached a given domain (subdomains included)
curl -s 'localhost:9090/api/history/hosts?hostname=example.com&since=30d' | jq

# Raw observations for a given window
curl -s 'localhost:9090/api/history/events?from=2026-08-01&to=2026-08-02' | jq
```

`since` accepts `30m` `24h` `7d` `2w`; `from`/`to` accept RFC3339,
`YYYY-MM-DD`, unix time and `-7d` forms. You can run the same queries from a form
on the dashboard's **History** tab.

Design notes worth knowing:

- **Writes are asynchronous.** Monitoring must never stall the thing it watches,
  so when the queue fills it drops records and increments a counter. If
  `openvpn_history_events_dropped` is non-zero, there is a hole in the audit log,
  so alert on it.
- **Bytes accumulate incrementally.** When a kernel flow expires and comes back,
  the counter restarts from zero, so it adds the increment rather than the
  maximum.
- **Restarting ovpnmon does not split sessions.** It keys on the real connection
  time OpenVPN reports and continues the existing record. Conversely, a session
  left open by an abnormal exit is closed at its last-activity time on the next
  startup.
- Records past `-retention` (default 30 days) are deleted once a day. `0` keeps
  them forever.
- The SQLite file is created `0600`.

## Configuration

Configuration lives in `/opt/ovpnmon/etc/ovpnmon.conf`. Key names match flag
names, so anything shown by `ovpnmon -help` can also go in the file.

```ini
iface  = tun0
subnet = 10.8.0.0/24
mgmt   = 127.0.0.1:7505
listen = 127.0.0.1:9090

store     = sqlite:/opt/ovpnmon/data/history.db
retention = 720h

top-destinations = 20
flow-idle        = 5m
name-ttl         = 30m
log-level        = info
```

Precedence is **command line > config file > defaults**. To change one thing
temporarily, pass a flag; you do not need to edit the file.

**A typo is not silently ignored — it fails startup.** Otherwise a typo in the
config file means discovering "why isn't this setting taking effect" much later.

```
$ ovpnmon -config /opt/ovpnmon/etc/ovpnmon.conf
ovpnmon: reading config: /opt/ovpnmon/etc/ovpnmon.conf:24: unknown setting "retenshun"
```

The full set of options is in `ovpnmon -help`.

`listen` defaults to loopback. If you expose it externally, put authentication
in front — this endpoint holds every user's connection history.

## Limitations

- **IPv4 only.** IPv6 flows are not aggregated (DNS AAAA replies are still cached).
- **QUIC / HTTP3** (UDP 443) ClientHellos are encrypted, so the SNI is not
  visible. Such traffic is named only from DNS replies.
- Connections using **Encrypted Client Hello (ECH)** hide the SNI.
- Clients using **DoH/DoT** leave no DNS signal either. Their destinations
  remain IP-only.
- The payload snapshot is **512 bytes**; an SNI extension beyond that is
  truncated (observable via the `probe.truncated` counter). If a ClientHello is
  split across segments, only the first is seen.
- The flow map is a 65536-entry LRU. The kernel evicts the oldest entries above
  that.

## Privacy

This tool produces a per-hostname record of the hosts VPN users visit. Whether
the operator has the authority to do so, whether users have been notified, and
whether the retention period is appropriate are things to settle before
deployment. Payload bodies are never stored.

Used without `-store`, everything is in memory only and disappears on restart.
From the moment you enable `-store`, an irreversible record is kept, so **decide
the retention period before turning it on** (`-retention`, default 30 days). This
also includes users' real connection IPs, which are more sensitive than
destinations — they reveal location and ISP.

## Structure

```
bpf/ovpnmon.bpf.c        eBPF dataplane (flow aggregation + payload sampling)
internal/ebpfx/          program load, TCX attach, map access
internal/mgmt/           OpenVPN management-protocol client
internal/resolver/       DNS/SNI/HTTP parsers and the name cache
internal/geoip/          MaxMind GeoLite2 lookups for destination geolocation
internal/collector/      joins the sources into a snapshot
internal/api/            HTTP, WebSocket, dashboard
internal/metrics/        Prometheus exporter
deploy/                  server setup scripts, systemd unit, test client
```

After editing `bpf/ovpnmon.bpf.c` you must recompile with `make generate`. The
compiled object is embedded in the binary, so the deployment target needs
neither clang nor kernel headers.

## Development

```bash
make generate     # recompile eBPF + regenerate Go bindings
make vet          # go vet + gofmt check
make test-root    # full tests including kernel-verifier tests
```

## Login

The default is **no authentication**. If you expose the dashboard beyond
loopback, turn it on without fail — this screen holds every user's connection
history.

```bash
ovpnmon -hash-password '<password>'      # print a hash
```

Put the printed value in `/opt/ovpnmon/etc/ovpnmon.conf` and restart:

```ini
auth-user          = admin
auth-password-hash = $2a$10$...
metrics-token      = <long random string>
```

- Sessions are **in memory only**. Restarting ovpnmon logs everyone out and
  invalidates stolen cookies along with them
- Cookies are `HttpOnly` + `SameSite=Strict`. This stops another site from using
  an operator's cookie to edit notes
- Only `/healthz` is public (for load-balancer health checks). The rest of
  `/api/*` and `/metrics` require a session
- **Prometheus has no browser session**, so it uses `metrics-token`. `make
  observability-config` copies this value into the scrape config. If you enable
  auth without a token, Prometheus gets a 401 and the dashboard stays empty

There is no TLS yet. Passwords travel in cleartext, so if you expose this on an
untrusted network, put HTTPS in front with a reverse proxy.

## Certificate management

Off by default. It runs easyrsa as root and exports private keys, so it is a
different kind of privilege from merely watching traffic.

```ini
manage-certificates = true
server-conf = /etc/openvpn/server/server.conf
vpn-host = vpn.example.com      # address the generated profile connects to
```

Issue from the top of the Users tab, and **Profile** download and **Revoke**
next to each user. All of it is recorded in the audit history (`cert_issue`,
`cert_revoke`, `profile_download`).

### For revocation to actually take effect

**If `server.conf` has no `crl-verify` line, revocation blocks nothing.** A
revoked user simply reconnects. Verified in practice:

```
without crl-verify  → connects successfully even after revocation
with crl-verify     → VERIFY ERROR: certificate revoked: CN=testuser
```

The revoke response tells you this state, and `make preflight` checks it too.

```json
{"revoked": true, "crl_enforced": false, "still_online": true,
 "advice": "The server config has no crl-verify line, so this revocation is not enforced..."}
```

Revoking a currently-connected user **does not drop that connection** — the CRL
is checked at connect time. To apply it immediately, also press Disconnect.

> **A `.ovpn` contains the client private key.** With no TLS today, that key
> crosses the network in cleartext. Do not use this over an untrusted network.

Turning on `manage-certificates` requires the systemd unit to be able to write
to `/etc/openvpn` (it is included in `ReadWritePaths`). With it off, that path is
never written.

## Force-disconnect

From the Users tab, the **Disconnect** button next to a connected user drops the
connection. It sends `client-kill <CID>`, using the client id rather than the
common name because several devices may hold a certificate with the same name.

> **This is a disconnect, not a block.** The certificate stays valid, so a client
> configured to reconnect (the default) comes back within seconds. To actually
> stop it, revoke the certificate. The confirmation dialog says as much.

Who disconnected whom, and when, is recorded as `kill` in the activity feed and
the audit history:

```
02:09:05  kill  bob  disconnected by admin
```

## GeoIP (optional)

Point `-geoip-db` at a MaxMind GeoLite2 database and public destinations gain a
location on the dashboard — a country (and, with the City edition, a city). The
lookup is fully offline: the file is read locally and no address is ever sent to
a third party.

```ini
# ovpnmon.conf
geoip-db = /var/lib/ovpnmon/GeoLite2-City.mmdb
```

Download `GeoLite2-City.mmdb` (or `GeoLite2-Country.mmdb`) from MaxMind with a
free account; ovpnmon never fetches it for you. Without it, destinations are
shown exactly as observed. Private and VPN-internal addresses are never looked
up — they have no meaningful geography.

> **Identity sources are pluggable.** The core depends only on the
> `enrich.Provider` interface (`internal/enrich`), which can annotate a user or a
> destination with who they are in your own infrastructure. No provider ships in
> this repository; the interface is the extension point for your own.

## Temporarily blocking a user

From the `⋮` menu on the Users tab, **Block temporarily…** blocks a user for a
chosen duration and reason. The current session is dropped and reconnection is
refused until expiry.

> **The certificate stays valid.** If a key has leaked, use revocation, not a
> block. A block is the equivalent of "keep them out until Friday", and it
> expires on its own.

It uses OpenVPN's own feature of placing a one-line `disable` file in
`client-config-dir`. OpenVPN re-reads that directory on every connection, so
**neither blocking nor unblocking needs a restart.** Expiry is handled by
ovpnmon checking every 15 seconds.

```
02:30:38  block    boan  blocked by admin until 2026-08-05T02:32:08Z: investigating misuse
02:32:08  (expiry) block expired  common_name=boan
```

A blocked user is shown in red at the top of the list even when not connected —
they are offline *because* they were blocked, so sorting only by connection
status would sink the row you just acted on to the bottom.

To use it, `server.conf` must have the following, and adding it needs one
OpenVPN restart (`preflight.sh` checks for it):

```
client-config-dir /etc/openvpn/ccd
```

Where the decision is made, what happens if ovpnmon dies, and how to unblock by
hand are written up in **[docs/blocking.md](docs/blocking.md)**.

## Live-update control

The header controls adjust how fast the screen is redrawn.

| | |
|---|---|
| **⏸ / ▶** | Pause. The table does not change while you read it or copy a value |
| **Interval** | 2s · 5s · 10s · 30s (default 5s) |
| **↻** | Refresh now (releases pause if it was paused) |
| **🖥 / ☀️ / 🌙** | Theme: system → light → dark. The choice is saved in the browser |

The WebSocket receiver itself never stops — **events that occur while paused are
buffered and shown all at once on resume**, so there is no hole in the activity
record. Server load is unchanged too; the only thing that changes is how often
the browser redraws the DOM.

The theme follows your operating system by default; the toggle lets you pin it
to light or dark, and the choice persists across reloads.

The throttle is skipped when the page first opens. The server sends the snapshot
and recent events all at once right after connecting, and delaying that would
leave the first screen blank for a while.

## Users tab

The user list is built by joining easy-rsa `index.txt` (all issued users and
their certificate status), the history DB (connection count and cumulative
traffic) and management (currently connected). **A user does not disappear from
the list when they disconnect.**

The PKI path is auto-detected from the conventional locations, and you can
specify it if it is elsewhere:

```ini
pki-index = /path/to/pki/index.txt
server-cn = server              # exclude the server certificate from the user list
```

It works even if it cannot read the PKI — the list narrows to "users who have
connected before".

Expanding a user lets you leave a **note** (stored in the history DB, 2000
characters). This is the only write endpoint — if there is no auth in front,
anyone who can reach it on the network can edit it, so account for that if you
expose the dashboard externally. All a note can do is store text; it cannot
disconnect anyone or change settings.

Traffic shows both the **current rate** (the large number) and the **cumulative
since the session started** (the small number). `tunnel_bytes_*` is the
encrypted bytes OpenVPN counts, `flow_*` is the cleartext bytes the probe sees
inside the tunnel, and it is the latter that is attributed per destination.
