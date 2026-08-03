#!/usr/bin/env bash
# Install ovpnmon from a release tarball.
#
# This is what runs on the VPN server. It needs nothing but the files beside
# it - no Go, no clang, no kernel headers - because the eBPF object is
# embedded in the binary.
#
# Installing does not disturb OpenVPN: attaching the eBPF probe leaves
# existing connections alone. Only changing OpenVPN's own config (management,
# disable-dco) requires a restart, and preflight.sh tells you whether that is
# needed before you start.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/opt/ovpnmon}"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

# Refuse early rather than half-installing onto a kernel that cannot load it.
KVER=$(uname -r | cut -d- -f1)
if [ "$(printf '6.6\n%s\n' "$KVER" | sort -V | head -1)" != "6.6" ]; then
	echo "kernel $KVER is too old; TCX attachment needs 6.6 or newer" >&2
	exit 1
fi
[ -r /sys/kernel/btf/vmlinux ] || {
	echo "no /sys/kernel/btf/vmlinux; this kernel was built without BTF" >&2
	exit 1
}

log "Installing into $PREFIX"
install -d -m 755 "$PREFIX/bin" "$PREFIX/etc"
install -d -m 700 "$PREFIX/data"
install -m 755 "$HERE/bin/ovpnmon"       "$PREFIX/bin/ovpnmon"
install -m 755 "$HERE/bin/ovpn-firewall" "$PREFIX/bin/ovpn-firewall"
install -m 644 "$HERE/README.md"         "$PREFIX/README.md" 2>/dev/null || true

# Never overwrite a config the operator has edited.
if [ -f "$PREFIX/etc/ovpnmon.conf" ]; then
	log "Keeping existing $PREFIX/etc/ovpnmon.conf"
	install -m 640 "$HERE/etc/ovpnmon.conf" "$PREFIX/etc/ovpnmon.conf.default"
	warn "compare against $PREFIX/etc/ovpnmon.conf.default for new settings"
else
	install -m 640 "$HERE/etc/ovpnmon.conf" "$PREFIX/etc/ovpnmon.conf"
fi

log "Installing systemd unit"
install -m 644 "$HERE/systemd/ovpnmon.service" /etc/systemd/system/ovpnmon.service
systemctl daemon-reload

# Suggest settings that match this host instead of leaving the defaults to
# be discovered the hard way.
IFACE=$(ip -br link show type tun 2>/dev/null | awk 'NR==1{print $1}' | cut -d@ -f1)
CIDR=$(ip -br addr show "${IFACE:-none}" 2>/dev/null | awk '{print $3}')
SUBNET=$(python3 -c "import ipaddress,sys;print(ipaddress.ip_network(sys.argv[1],strict=False))" "$CIDR" 2>/dev/null || true)

echo
log "Next steps"
echo "    1. Review $PREFIX/etc/ovpnmon.conf"
if [ -n "${IFACE:-}" ] && [ -n "${SUBNET:-}" ]; then
	echo "       This host looks like:  iface = $IFACE    subnet = $SUBNET"
fi
echo "       Also set 'mgmt' to OpenVPN's management address."
echo "    2. sudo systemctl enable --now ovpnmon"
echo "    3. curl -s localhost:\$(awk -F: '/^listen/{print \$NF}' $PREFIX/etc/ovpnmon.conf)/healthz"
echo
echo "    Uninstall: systemctl disable --now ovpnmon && rm -rf $PREFIX /etc/systemd/system/ovpnmon.service"
