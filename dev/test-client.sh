#!/usr/bin/env bash
# Run a real OpenVPN client against the local server, isolated in a network
# namespace.
#
# The server pushes "redirect-gateway", so a client started in the host's
# namespace would move the host's default route into the tunnel and cut the
# operator's own SSH session. A namespace keeps that blast radius at zero: only
# the namespace's routing table is redirected.
#
# Usage:
#   test-client.sh up   [name]   # bring up the namespace and connect
#   test-client.sh exec [name] -- cmd args...
#   test-client.sh down [name]
set -euo pipefail

CMD="${1:-up}"
CLIENT="${2:-alice}"
NS="vpn-$CLIENT"
HOST_IF="vh-$CLIENT"
NS_IF="vp-$CLIENT"
SUBNET_BASE="${SUBNET_BASE:-192.168.222}"
PROFILE="/etc/openvpn/client-profiles/$CLIENT.ovpn"
RUN_DIR="/run/ovpnmon-test/$CLIENT"
WAN_IF="${WAN_IF:-$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

up() {
  [ -f "$PROFILE" ] || { echo "no profile at $PROFILE" >&2; exit 1; }
  mkdir -p "$RUN_DIR"

  if ip netns list | grep -qw "$NS"; then
    log "namespace $NS already exists; tearing it down first"
    down
  fi

  log "Creating namespace $NS"
  ip netns add "$NS"
  ip link add "$HOST_IF" type veth peer name "$NS_IF"
  ip link set "$NS_IF" netns "$NS"

  ip addr add "$SUBNET_BASE.1/30" dev "$HOST_IF"
  ip link set "$HOST_IF" up

  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip addr add "$SUBNET_BASE.2/30" dev "$NS_IF"
  ip netns exec "$NS" ip link set "$NS_IF" up
  ip netns exec "$NS" ip route add default via "$SUBNET_BASE.1"

  # DNS for the namespace, until OpenVPN pushes its own.
  mkdir -p "/etc/netns/$NS"
  echo "nameserver 1.1.1.1" > "/etc/netns/$NS/resolv.conf"

  # Let the namespace reach the outside world through the host.
  iptables -t nat -C POSTROUTING -s "$SUBNET_BASE.0/30" -o "$WAN_IF" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$SUBNET_BASE.0/30" -o "$WAN_IF" -j MASQUERADE
  iptables -C FORWARD -i "$HOST_IF" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$HOST_IF" -j ACCEPT
  iptables -C FORWARD -o "$HOST_IF" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "$HOST_IF" -j ACCEPT

  # The server also answers on the veth address, and replies to the namespace
  # are sourced from it rather than from the WAN address in the profile. Point
  # the client at the address it will actually hear back from, otherwise
  # OpenVPN rejects the handshake as coming from an unexpected peer.
  sed "s|^remote .*|remote $SUBNET_BASE.1 ${VPN_PORT:-1194}|" \
      "$PROFILE" > "$RUN_DIR/client.ovpn"
  chmod 600 "$RUN_DIR/client.ovpn"

  log "Starting OpenVPN client '$CLIENT' inside $NS"
  ip netns exec "$NS" openvpn \
      --config "$RUN_DIR/client.ovpn" \
      --daemon "ovpn-test-$CLIENT" \
      --writepid "$RUN_DIR/openvpn.pid" \
      --log "$RUN_DIR/client.log" \
      --verb 3

  log "Waiting for the tunnel"
  for _ in $(seq 1 30); do
    if ip netns exec "$NS" ip -br addr show type tun 2>/dev/null | grep -q UNKNOWN; then
      ip netns exec "$NS" ip -br addr show type tun
      log "Tunnel up. Try: $0 exec $CLIENT -- curl -s https://example.com -o /dev/null"
      return 0
    fi
    sleep 1
  done

  echo "tunnel did not come up; last log lines:" >&2
  tail -20 "$RUN_DIR/client.log" >&2
  exit 1
}

down() {
  if [ -f "$RUN_DIR/openvpn.pid" ]; then
    kill "$(cat "$RUN_DIR/openvpn.pid")" 2>/dev/null || true
    rm -f "$RUN_DIR/openvpn.pid"
  fi
  ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$HOST_IF" 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s "$SUBNET_BASE.0/30" -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i "$HOST_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -o "$HOST_IF" -j ACCEPT 2>/dev/null || true
  rm -rf "/etc/netns/$NS"
  log "namespace $NS removed"
}

case "$CMD" in
  up)   up ;;
  down) down ;;
  exec)
    shift 2 2>/dev/null || shift $#
    [ "${1:-}" = "--" ] && shift
    exec ip netns exec "$NS" "$@"
    ;;
  *) echo "usage: $0 {up|down|exec} [client] [-- cmd...]" >&2; exit 1 ;;
esac
