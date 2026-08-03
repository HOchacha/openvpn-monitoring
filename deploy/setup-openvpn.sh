#!/usr/bin/env bash
# Build an OpenVPN server with a fresh easy-rsa PKI and a management interface
# that ovpnmon can attach to.
#
# Idempotent: re-running skips work that is already done.
set -euo pipefail

VPN_NET="${VPN_NET:-10.8.0.0}"
VPN_MASK="${VPN_MASK:-255.255.255.0}"
VPN_PORT="${VPN_PORT:-1194}"
VPN_PROTO="${VPN_PROTO:-udp}"
MGMT_ADDR="${MGMT_ADDR:-127.0.0.1}"
MGMT_PORT="${MGMT_PORT:-7505}"
WAN_IF="${WAN_IF:-$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')}"
SERVER_ADDR="${SERVER_ADDR:-$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')}"
CLIENTS="${CLIENTS:-alice bob}"

# Resolved before anything cd's away, so later steps can still find the files
# shipped alongside this script.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EASYRSA_SRC=/usr/share/easy-rsa
PKI_DIR=/etc/openvpn/easy-rsa
SRV_DIR=/etc/openvpn/server
CLIENT_OUT=/etc/openvpn/client-profiles

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

# ---------------------------------------------------------------- PKI --------
if [ ! -d "$PKI_DIR/pki" ]; then
  log "Initialising easy-rsa PKI in $PKI_DIR"
  mkdir -p "$PKI_DIR"
  cp -r "$EASYRSA_SRC"/* "$PKI_DIR/"
  cd "$PKI_DIR"
  EASYRSA_BATCH=1 ./easyrsa init-pki
fi

cd "$PKI_DIR"
export EASYRSA_BATCH=1 EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1
export EASYRSA_CERT_EXPIRE=3650 EASYRSA_CA_EXPIRE=3650

if [ ! -f "$PKI_DIR/pki/ca.crt" ]; then
  log "Building CA"
  # EASYRSA_REQ_CN only applies to the CA; build-*-full rejects it outright.
  EASYRSA_REQ_CN="ovpn-monitoring-ca" ./easyrsa build-ca nopass
fi

if [ ! -f "$PKI_DIR/pki/issued/server.crt" ]; then
  log "Building server certificate"
  ./easyrsa build-server-full server nopass
fi

[ -f "$PKI_DIR/pki/crl.pem" ] || ./easyrsa gen-crl

for c in $CLIENTS; do
  if [ ! -f "$PKI_DIR/pki/issued/$c.crt" ]; then
    log "Issuing client certificate: $c"
    ./easyrsa build-client-full "$c" nopass
  fi
done

# ------------------------------------------------------------ server cfg -----
mkdir -p "$SRV_DIR" /var/log/openvpn
if [ ! -f "$SRV_DIR/tls-crypt.key" ]; then
  log "Generating tls-crypt key"
  openvpn --genkey secret "$SRV_DIR/tls-crypt.key"
fi

install -m 644 "$PKI_DIR/pki/ca.crt"                 "$SRV_DIR/ca.crt"
install -m 644 "$PKI_DIR/pki/issued/server.crt"      "$SRV_DIR/server.crt"
install -m 600 "$PKI_DIR/pki/private/server.key"     "$SRV_DIR/server.key"

log "Writing $SRV_DIR/server.conf"
cat > "$SRV_DIR/server.conf" <<EOF
# OpenVPN server for ovpnmon. Managed by deploy/setup-openvpn.sh.
port $VPN_PORT
proto $VPN_PROTO
dev tun0
dev-type tun

# ovpnmon's eBPF dataplane attaches to the tun interface, so keep the data
# channel in userspace rather than offloading it to the ovpn-dco kernel module.
disable-dco

ca   $SRV_DIR/ca.crt
cert $SRV_DIR/server.crt
key  $SRV_DIR/server.key
dh   none
tls-crypt $SRV_DIR/tls-crypt.key

topology subnet
server $VPN_NET $VPN_MASK
ifconfig-pool-persist /var/log/openvpn/ipp.txt

# Route all client traffic through the VPN so egress is actually observable.
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

keepalive 10 60
persist-key
persist-tun
user nobody
group nogroup

# ovpnmon connects here to learn who is online (CN <-> virtual IP <-> real IP).
management $MGMT_ADDR $MGMT_PORT

status /var/log/openvpn/status.log 5
status-version 3
log-append /var/log/openvpn/server.log
verb 3
explicit-exit-notify 1
EOF

# ------------------------------------------------------------ forwarding -----
log "Enabling IPv4 forwarding"
cat > /etc/sysctl.d/99-openvpn-forward.conf <<'EOF'
net.ipv4.ip_forward = 1
EOF
sysctl -q -p /etc/sysctl.d/99-openvpn-forward.conf

# Forwarding rules go through a unit rather than being applied inline, so they
# come back after a reboot. Applying them here only would leave clients able to
# connect but unable to reach anything once the machine restarts.
log "Installing firewall rules for $VPN_NET/24 out of $WAN_IF"
install -d -m 755 /opt/ovpnmon/bin /opt/ovpnmon/etc
install -m 755 "$HERE/ovpn-firewall.sh" /opt/ovpnmon/bin/ovpn-firewall
install -m 644 "$HERE/ovpn-firewall.service" /etc/systemd/system/ovpn-firewall.service

# Netmask in CIDR form, derived from the dotted mask in $VPN_MASK.
CIDR_BITS=$(python3 -c "import ipaddress,sys; print(ipaddress.IPv4Network('0.0.0.0/'+sys.argv[1]).prefixlen)" "$VPN_MASK")
cat > /opt/ovpnmon/etc/firewall.conf <<EOF
# Written by setup-openvpn.sh. Consumed by ovpn-firewall.service.
VPN_NET=$VPN_NET/$CIDR_BITS
TUN_IF=tun0
WAN_IF=$WAN_IF
EOF

systemctl daemon-reload
systemctl enable ovpn-firewall >/dev/null 2>&1 || true
systemctl restart ovpn-firewall

log "Installing log rotation for /var/log/openvpn"
install -m 644 "$HERE/openvpn.logrotate" /etc/logrotate.d/openvpn

# --------------------------------------------------------- client profiles ---
mkdir -p "$CLIENT_OUT"
for c in $CLIENTS; do
  log "Writing client profile $CLIENT_OUT/$c.ovpn"
  cat > "$CLIENT_OUT/$c.ovpn" <<EOF
client
dev tun
proto $VPN_PROTO
remote $SERVER_ADDR $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3
<ca>
$(cat "$PKI_DIR/pki/ca.crt")
</ca>
<cert>
$(openssl x509 -in "$PKI_DIR/pki/issued/$c.crt")
</cert>
<key>
$(cat "$PKI_DIR/pki/private/$c.key")
</key>
<tls-crypt>
$(cat "$SRV_DIR/tls-crypt.key")
</tls-crypt>
EOF
  chmod 600 "$CLIENT_OUT/$c.ovpn"
done

# ------------------------------------------------------------- service -------
log "Starting openvpn-server@server"
systemctl enable --now openvpn-server@server >/dev/null 2>&1 || systemctl restart openvpn-server@server
sleep 2
systemctl is-active --quiet openvpn-server@server \
  && log "OpenVPN is running on $VPN_PROTO/$VPN_PORT, management on $MGMT_ADDR:$MGMT_PORT" \
  || { echo "OpenVPN failed to start; see: journalctl -u openvpn-server@server" >&2; exit 1; }

ip -br addr show tun0 || true
