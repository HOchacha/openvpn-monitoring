#!/usr/bin/env bash
# Check whether a running OpenVPN server can host ovpnmon, and report exactly
# what has to change.
#
# Self-contained on purpose: copy this one file to the VPN server and run it.
# It reads state and changes nothing.
#
#   ./preflight.sh
#
# The important thing it tells you is whether OpenVPN needs a restart, because
# a restart disconnects every client. Attaching the eBPF probe does not.
set -uo pipefail

OVPNMON_PORT="${OVPNMON_PORT:-9095}"

if [ -t 1 ]; then
	B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
else
	B=''; G=''; Y=''; R=''; D=''; N=''
fi

section()  { printf '\n%s%s%s\n' "$B" "$*" "$N"; }
ok()    { printf '  %sok%s       %-24s %s\n' "$G" "$N" "$1" "${2-}"; }
warn()  { printf '  %saction%s   %-24s %s\n' "$Y" "$N" "$1" "${2-}"; }
bad()   { printf '  %sblocked%s  %-24s %s\n' "$R" "$N" "$1" "${2-}"; }
note()  { printf '           %s%s%s\n' "$D" "$*" "$N"; }

BLOCKERS=0
RESTART_NEEDED=0
CHANGES=()

# OpenVPN normally drops privileges to nobody, so reading its config path out
# of /proc needs root. Without it the DCO and management checks cannot run.
if [ "$(id -u)" -ne 0 ]; then
	printf '%sRun with sudo for a complete report.%s\n' "$Y" "$N"
	printf '  Without root the OpenVPN config cannot be located, so the\n'
	printf '  management and DCO checks are skipped.\n'
fi

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# ------------------------------------------------------------------ kernel --

section "Kernel"

KVER=$(uname -r | cut -d- -f1)
if ver_ge "$KVER" 6.6; then
	ok "kernel $KVER" "TCX attachment requires >= 6.6"
else
	bad "kernel $KVER" "ovpnmon needs 6.6+ for TCX; upgrade or run it elsewhere"
	BLOCKERS=$((BLOCKERS + 1))
fi

if [ -r /sys/kernel/btf/vmlinux ]; then
	ok "BTF" "present"
else
	bad "BTF" "kernel lacks CONFIG_DEBUG_INFO_BTF; the loader cannot run"
	BLOCKERS=$((BLOCKERS + 1))
fi

# ----------------------------------------------------------------- openvpn --

section "OpenVPN"

OVPN_PID=$(pgrep -x openvpn | head -1)
if [ -z "$OVPN_PID" ]; then
	bad "openvpn" "no running process found"
	BLOCKERS=$((BLOCKERS + 1))
else
	OVPN_VER=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')
	ok "openvpn ${OVPN_VER:-?}" "pid $OVPN_PID"
fi

# Find the config the running server uses, so advice points at the right file.
OVPN_CONF=""
if [ -n "$OVPN_PID" ]; then
	CMDLINE=$(tr '\0' ' ' < "/proc/$OVPN_PID/cmdline" 2>/dev/null)
	CONF_ARG=$(echo "$CMDLINE" | grep -oP '(?<=--config )\S+' | head -1)
	CWD=$(readlink -f "/proc/$OVPN_PID/cwd" 2>/dev/null)
	for candidate in "$CONF_ARG" "$CWD/$CONF_ARG"; do
		[ -n "$candidate" ] && [ -f "$candidate" ] && { OVPN_CONF=$candidate; break; }
	done
fi
if [ -n "$OVPN_CONF" ]; then
	ok "config" "$OVPN_CONF"
elif [ "$(id -u)" -ne 0 ]; then
	warn "config" "needs root to read; re-run with sudo"
else
	warn "config" "could not determine it from the running process"
	note "find it yourself and apply the changes below by hand"
fi

# --- management interface ---
MGMT_ADDR=""
if [ -n "$OVPN_CONF" ]; then
	MGMT_LINE=$(grep -E '^\s*management\s' "$OVPN_CONF" 2>/dev/null | head -1)
	if [ -n "$MGMT_LINE" ]; then
		MGMT_HOST=$(echo "$MGMT_LINE" | awk '{print $2}')
		MGMT_PORT=$(echo "$MGMT_LINE" | awk '{print $3}')
		MGMT_PWFILE=$(echo "$MGMT_LINE" | awk '{print $4}')
		MGMT_ADDR="$MGMT_HOST:$MGMT_PORT"
		ok "management" "$MGMT_ADDR"
		if [ "$MGMT_HOST" != "127.0.0.1" ] && [ "$MGMT_HOST" != "localhost" ]; then
			note "reachable beyond loopback - it can kill sessions, so restrict it"
		fi
		if [ -n "$MGMT_PWFILE" ]; then
			note "password protected ($MGMT_PWFILE)"
			note "set in ovpnmon.conf:  mgmt-password-file = $MGMT_PWFILE"
		fi
	else
		warn "management" "not enabled; ovpnmon has no source of client identities"
		note "add to $OVPN_CONF:  management 127.0.0.1 7505"
		CHANGES+=("management 127.0.0.1 7505")
		RESTART_NEEDED=1
	fi
fi

# Something else may already hold the single management slot.
if [ -n "$MGMT_ADDR" ]; then
	if command -v ss >/dev/null && ss -tn 2>/dev/null | grep -q "${MGMT_ADDR}.*ESTAB"; then
		warn "management in use" "another client is connected"
		note "OpenVPN serves one management client at a time; ovpnmon cannot share it"
	fi
fi

# --- data channel offload ---
# DCO moves the datapath into a kernel module, bypassing the tun device the
# probe attaches to. Nothing would be counted.
DCO_ACTIVE=0
if lsmod 2>/dev/null | grep -qE '^ovpn(_dco)?\b'; then DCO_ACTIVE=1; fi
if ip -br link show type ovpn-dco 2>/dev/null | grep -q .; then DCO_ACTIVE=1; fi

if [ -n "$OVPN_CONF" ] && grep -qE '^\s*disable-dco' "$OVPN_CONF" 2>/dev/null; then
	ok "DCO" "already disabled in config"
elif [ "$DCO_ACTIVE" -eq 1 ]; then
	warn "DCO" "active; the datapath bypasses tun and nothing would be seen"
	note "add to $OVPN_CONF:  disable-dco"
	CHANGES+=("disable-dco")
	RESTART_NEEDED=1
elif [ -n "${OVPN_VER:-}" ] && ver_ge "${OVPN_VER:-0}" 2.6; then
	warn "DCO" "OpenVPN $OVPN_VER can enable it; pin it off to be safe"
	note "add to $OVPN_CONF:  disable-dco"
	CHANGES+=("disable-dco")
	RESTART_NEEDED=1
else
	ok "DCO" "not applicable on OpenVPN ${OVPN_VER:-<2.6}"
fi

# ---------------------------------------------------------------- interface --

section "Tunnel"

TUN_IFACES=$(ip -br link show type tun 2>/dev/null | awk '{print $1}' | cut -d@ -f1)
if [ -z "$TUN_IFACES" ]; then
	bad "tun interface" "none found; is the server up, or is DCO in use?"
	BLOCKERS=$((BLOCKERS + 1))
else
	for i in $TUN_IFACES; do
		addr=$(ip -br addr show "$i" 2>/dev/null | awk '{print $3}')
		ok "$i" "${addr:-no address}"
	done
	FIRST_TUN=$(echo "$TUN_IFACES" | head -1)
	SUBNET=$(ip -br addr show "$FIRST_TUN" 2>/dev/null | awk '{print $3}')
	if [ -n "$SUBNET" ]; then
		NET=$(python3 -c "import ipaddress,sys;print(ipaddress.ip_network(sys.argv[1],strict=False))" "$SUBNET" 2>/dev/null)
		[ -n "$NET" ] && note "suggested ovpnmon settings:  iface = $FIRST_TUN   subnet = $NET"
	fi
fi

# --------------------------------------------------------------------- ports --

section "Ports"

port_owner() {
	command -v ss >/dev/null || return 1
	ss -tlnp 2>/dev/null | grep -E "[:.]$1\s" |
		grep -oP '(?<=users:\(\(")[^"]+' | head -1
}
for p in "$OVPNMON_PORT"; do
	owner=$(port_owner "$p")
	case "$owner" in
		"")        ok   "port $p" "free (ovpnmon dashboard, API, metrics)" ;;
		ovpnmon)   ok   "port $p" "already held by ovpnmon; this looks like an upgrade" ;;
		*)         warn "port $p" "in use by ${owner}; pick another with 'listen' in ovpnmon.conf" ;;
	esac
done

# -------------------------------------------------------------------- verdict --

section "Verdict"

if [ "$BLOCKERS" -gt 0 ]; then
	printf '  %sCannot install here.%s %d blocking issue(s) above.\n' "$R" "$N" "$BLOCKERS"
	exit 1
fi

if [ "${#CHANGES[@]}" -eq 0 ]; then
	printf '  %sReady.%s OpenVPN needs no changes, so nothing disconnects.\n' "$G" "$N"
	echo
	echo "    1. copy the release tarball to this host"
	echo "    2. tar xzf ovpnmon-*.tar.gz && sudo ./install.sh"
	echo "    3. edit /opt/ovpnmon/etc/ovpnmon.conf (iface, subnet, mgmt)"
	echo "    4. sudo systemctl enable --now ovpnmon"
	exit 0
fi

printf '  %sOpenVPN config changes required:%s\n' "$Y" "$N"
for c in "${CHANGES[@]}"; do echo "      $c"; done
echo
if [ "$RESTART_NEEDED" -eq 1 ]; then
	printf '  %sThese need an OpenVPN restart, which disconnects every client.%s\n' "$R" "$N"
	echo "    Plan a maintenance window. Clients with a keepalive will reconnect on"
	echo "    their own, but expect a visible interruption."
	echo
	echo "    Installing ovpnmon itself is non-disruptive: attaching the eBPF probe"
	echo "    does not touch existing connections. Do the OpenVPN change first, then"
	echo "    install ovpnmon at any time afterwards."
fi
exit 0
