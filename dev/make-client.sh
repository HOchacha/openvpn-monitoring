#!/usr/bin/env bash
# Issue a client certificate and write an .ovpn profile, for development.
#
#   ./make-client.sh alice bob carol ...
#
# This exists only to populate a test lab. Issuing certificates for real users
# is the VPN installer's job, not ovpnmon's.
set -euo pipefail

PKI_DIR="${PKI_DIR:-/etc/openvpn/easy-rsa}"
SRV_DIR="${SRV_DIR:-/etc/openvpn/server}"
OUT_DIR="${OUT_DIR:-/etc/openvpn/client-profiles}"
VPN_PORT="${VPN_PORT:-1194}"
VPN_PROTO="${VPN_PROTO:-udp}"
SERVER_ADDR="${SERVER_ADDR:-$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')}"

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
[ -d "$PKI_DIR/pki" ] || { echo "no PKI at $PKI_DIR" >&2; exit 1; }
[ $# -gt 0 ] || { echo "usage: $0 <name> [name...]" >&2; exit 1; }

mkdir -p "$OUT_DIR"
cd "$PKI_DIR"
export EASYRSA_BATCH=1 EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1 EASYRSA_CERT_EXPIRE=3650

for name in "$@"; do
	if [ ! -f "pki/issued/$name.crt" ]; then
		echo "==> issuing $name"
		./easyrsa build-client-full "$name" nopass >/dev/null 2>&1
	fi

	cat > "$OUT_DIR/$name.ovpn" <<EOF
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
$(cat pki/ca.crt)
</ca>
<cert>
$(openssl x509 -in "pki/issued/$name.crt")
</cert>
<key>
$(cat "pki/private/$name.key")
</key>
<tls-crypt>
$(cat "$SRV_DIR/tls-crypt.key")
</tls-crypt>
EOF
	chmod 600 "$OUT_DIR/$name.ovpn"
	echo "    $OUT_DIR/$name.ovpn"
done
