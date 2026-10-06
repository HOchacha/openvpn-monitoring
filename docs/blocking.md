# Temporarily blocking a user

This feature keeps a user out for a while without revoking their certificate.
This document explains **where and by whom the block decision is made**, and the
properties that follow from that choice.

For usage see "Temporarily blocking a user" in the README; for the API see
`PUT`/`DELETE /api/users/{cn}/block`.

## Why a separate feature

Previously there were only two options.

| | Duration | Reversal |
|---|---|---|
| **Disconnect** (`client-kill`) | ~1 second | client reconnects on its own |
| **Certificate revocation** (CRL) | permanent | the CRL has to be rebuilt |

For a request like "keep this account out until Friday", revocation was the only
tool available — but revocation is **a tool for a leaked key**. The OpenVPN
documentation draws the same line under `--disable`: use the CRL for a key
compromise, and use this for everything else.

| | Mechanism | Duration | Reversal | Certificate |
|---|---|---|---|---|
| Disconnect | `client-kill` | ~1 second | automatic | valid |
| **Temporary block** | ccd `disable` | until expiry | delete the file | **valid** |
| Revocation | CRL | permanent | hard | invalid |

## Three decisions, three actors

A block looks like a single decision but is really three. Each is made by a
different actor, and that is what determines this feature's failure
characteristics.

### 1. Policy decision — by the operator, once

**There is no automatic blocking.** There is no path by which ovpnmon watches
traffic and blocks someone on its own. Every block is an explicit human
decision, and who set it, when, and why is recorded in the DB and the audit
history.

```
operator → Block → enter duration and reason → PUT /api/users/{cn}/block
                                          │
        access.Manager.Block(cn, until, reason, by)
             ├─ 1. write ccd/<cn> file   "disable"
             ├─ 2. record expiry time in the DB
             └─ 3. end the current session
```

**Order matters.** The file comes first, the disconnect second. Do it the other
way around and the disconnected client's automatic retry (~1 second, measured)
arrives before the block file and it simply gets back in.

If the file write succeeds but the DB record fails, the file is rolled back. A
block that is enforced but not recorded **has no way to expire**.

### 2. Enforcement decision — by OpenVPN, on every connection

This is the crux. **ovpnmon is not in the authentication path.** It only places
a file; the refusal is decided by OpenVPN alone, at connection time. Because
`client-config-dir` is re-read on every connection, neither blocking nor
unblocking needs a restart.

The order in an actual refusal log:

```
02:30:39  Control Channel: TLSv1.3 ... peer certificate: 256 bits   ← certificate verified
02:30:39  [server] Peer Connection Initiated                        ← connection established
02:30:40  SENT CONTROL [server]: 'PUSH_REQUEST'
02:30:40  AUTH: Received control message: AUTH_FAILED               ← refused
02:30:40  SIGTERM[soft,auth-failure] received, process exiting
```

So it is **certificate verification (+CRL) → extract CN → look up `ccd/<CN>` →
`disable` → AUTH_FAILED**. A revoked certificate is cut earlier (at the CRL);
a block is only evaluated once the certificate is valid.

The outcome differs from a disconnect. A disconnect is
`SIGUSR1[soft,server-pushed-connection-reset]`, so the client comes back a
second later, whereas a block is `AUTH_FAILED`, so **the client process exits**.
That is why, even after a block is lifted, it does not come back on its own and
the user has to reconnect (behavior differs if `auth-retry` is configured).

#### Why not the management interface's `client-deny`

The management interface has a deny command too, but using it requires
`management-client-auth`. That would route **all authentication through
ovpnmon** — the moment ovpnmon dies, nobody can connect. Tying VPN availability
to a monitoring tool is unacceptable, so it was left out.

In the current design, even if ovpnmon dies, OpenVPN keeps working as usual.

### 3. Lift decision — by the reconcile loop, every 15 seconds

Nothing lets the file enforce its own expiry. The time is written in a comment,
but OpenVPN does not read it. **The DB is the sole owner of expiry**, and a
separate loop reconciles the DB against the directory.

`Run()` performs a reconcile **once first** before starting the ticker. So
restarting ovpnmon immediately clears any overdue expiries.

The three things reconcile fixes:

| Situation | Handling | Without it |
|---|---|---|
| Expired but file remains | delete file and record | a temporary block becomes permanent |
| Record exists but no file | rewrite the file | only the dashboard claims a block |
| File exists but no record | delete the file | dying before recording means a permanent block |

The interval (`block-check`, default 15 seconds) is **the maximum a block can be
late to lift**.

```
02:30:38  user blocked  until=02:32:08  by=admin  sessions_ended=1
02:32:08  block expired  common_name=boan
```

## It never touches someone else's file

`client-config-dir` may hold legitimate settings such as a fixed-IP assignment
(`ifconfig-push`) or per-client routes. Wiping the operator's config just to set
one temporary block is an unacceptable trade.

So the file ovpnmon writes carries a marker on its first line:

```
# ovpnmon-block
# written by ovpnmon; lift this block from the dashboard
# (removing this file by hand only holds while ovpnmon is stopped)
# blocked at 2026-08-05T04:22:14Z by admin
# until 2026-08-05T04:32:14Z
# reason reconcile check
disable
```

A file without the marker is refused — **not read, not deleted, not
overwritten**. To block that user, the error tells you to add `disable` to that
file by hand.

The reason string has newlines stripped so it is a single line. Because OpenVPN
parses this file, putting something like `push "redirect-gateway def1"` in the
reason would turn it into a directive.

The file is written to a temp file and moved into place with rename. In a
directory read on every connection, a half-written file would be a config error
at that instant. The permission is 0644 — OpenVPN drops privileges to `nobody`,
so it must remain readable.

## How to unblock by hand

Deleting the file makes OpenVPN let the user through from the next connection.
But **if ovpnmon is running and the block has not yet expired, it re-creates the
file within 15 seconds** (the second row of the table above). Deleting by hand
works only in two cases.

- while ovpnmon is stopped
- when the block has already expired

The normal way to lift a block while ovpnmon is alive is the dashboard's
**Unblock** or `DELETE /api/users/{cn}/block`. If you must lift it urgently
without ovpnmon:

```bash
sudo systemctl stop ovpnmon
sudo rm /etc/openvpn/ccd/<common-name>
# no OpenVPN restart needed — the next connection passes
```

In this case the block record remains in the DB, so if you start ovpnmon again
before expiry it **is re-enforced**. To lift it completely, start ovpnmon and
lift it from the dashboard.

## Behavior per failure scenario

| Situation | Result |
|---|---|
| ovpnmon stopped | existing blocks stay **enforced** (the file remains), but **do not expire**. No new blocks or lifts |
| ovpnmon restarted | reconcile at startup → overdue expiries cleared all at once |
| OpenVPN restarted | blocks persist (file-based, so unaffected) |
| history DB reset | judged as orphan files at the next reconcile → **all lifted** |
| ccd file lost | **rewritten** at the next reconcile |
| ovpnmon dies | OpenVPN keeps working as usual — it is not in the auth path |

The first row is the price of this design. Set a 1-hour block and leave ovpnmon
down for a week, and the user is blocked for a week. That is because ovpnmon is
the only actor that can decide expiry, and "How to unblock by hand" above is the
escape hatch for that case.

## Requirements

- `client-config-dir` in `server.conf` (without it the feature is off entirely)
- History enabled (`store`) — the expiry time must live in the DB
- Write permission for that directory (`ReadWritePaths=-/etc/openvpn`)

If you leave `ccd-dir` empty it is auto-detected from `server-conf`. If the two
disagree, OpenVPN would not read the directory ovpnmon writes and **blocks would
silently become void**, so the recommendation is not to set it by hand.

Adding a new `client-config-dir` requires an OpenVPN restart, and that
disconnects all clients. You pay it once; there is no restart for blocks or lifts
afterward. `preflight.sh` checks whether it is configured.

## Limitations

- **Expiry depends on ovpnmon.** The first row of the failure table above.
- **Lifting can be up to `block-check` late.** Default 15 seconds.
- **A block stops the next connection.** An already-connected session is dropped
  by the separate disconnect step.
- **The MySQL backend is unverified.** The schema is written for both, but only
  SQLite has been checked.
