#!/usr/bin/env bash
# Reset the local test lab to a known-good state.
#
# Two things in this setup do not survive being restarted repeatedly:
#
#   * OpenVPN's management interface serves one client at a time with a listen
#     backlog of 1. Restarting ovpnmon in quick succession can leave the daemon
#     holding sockets it never reads or closes, after which it stops accepting
#     connections entirely. Only restarting OpenVPN clears that.
#
#   * The namespaced test clients do not reliably renegotiate when the server
#     restarts under them; they sit with the control channel open and never
#     finish. Recreating them is faster than waiting.
#
# Neither affects a normal deployment, where nothing restarts minute to minute.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENTS="${CLIENTS:-alice bob}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

log "Stopping ovpnmon"
systemctl stop ovpnmon 2>/dev/null || true

log "Restarting OpenVPN (frees the management slot)"
systemctl restart openvpn-server@server
sleep 3

log "Starting ovpnmon"
systemctl start ovpnmon
sleep 3

i=0
for c in $CLIENTS; do
	# Each client needs its own veth subnet.
	base=$((222 + i))
	log "Recreating test client $c (192.168.$base.0/30)"
	SUBNET_BASE="192.168.$base" "$HERE/test-client.sh" down "$c" >/dev/null 2>&1 || true
	SUBNET_BASE="192.168.$base" "$HERE/test-client.sh" up "$c" >/dev/null
	i=$((i + 1))
done

sleep 3
log "State"
curl -sS http://127.0.0.1:9090/api/snapshot 2>/dev/null | python3 -c "
import json,sys
s=json.load(sys.stdin)
print(f\"    management: {s['mgmt_healthy']}\")
print(f\"    sessions:   {[x['common_name'] for x in s['sessions']]}\")
" || echo "    (ovpnmon API not reachable)"
