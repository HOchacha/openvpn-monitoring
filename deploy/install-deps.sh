#!/usr/bin/env bash
# Install (or just report on) what ovpnmon needs.
#
#   check     report every requirement without changing anything (no root)
#   build     toolchain needed to build ovpnmon
#   dev       extra tooling for testing and benchmarking
#   all       both of the above
#
# Installing OpenVPN itself is out of scope. Use whatever the server already
# uses - https://github.com/Nyr/openvpn-install is a good default - and run
# preflight.sh to see what ovpnmon needs added to it.
#
# The required Go version is read from go.mod rather than hardcoded, so this
# stays correct when the module is bumped.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"

# Overridable so the install path can be exercised without touching a working
# toolchain.
GO_INSTALL_DIR="${GO_INSTALL_DIR:-/usr/local/go}"
MIN_KERNEL="${MIN_KERNEL:-6.6}"   # TCX attachment landed here

# ------------------------------------------------------------------ output --

if [ -t 1 ]; then
	B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
else
	B=''; G=''; Y=''; R=''; D=''; N=''
fi

log()  { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '  %sok%s      %-22s %s\n' "$G" "$N" "$1" "${2-}"; }
warn() { printf '  %swarn%s    %-22s %s\n' "$Y" "$N" "$1" "${2-}"; }
bad()  { printf '  %smissing%s %-22s %s\n' "$R" "$N" "$1" "${2-}"; }

need_root() {
	[ "$(id -u)" -eq 0 ] || {
		echo "this needs root; re-run with sudo" >&2
		exit 1
	}
}

# --------------------------------------------------------------- detection --

# ver_ge A B -> true when A >= B, comparing dotted versions.
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# go_required reads the minimum Go version from go.mod.
go_required() {
	awk '/^go [0-9]/ {print $2; exit}' "$REPO/go.mod"
}

go_installed() {
	local go
	go=$(command -v go || echo "$GO_INSTALL_DIR/bin/go")
	[ -x "$go" ] || return 1
	"$go" version 2>/dev/null | awk '{print $3}' | sed 's/^go//'
}

pkg_manager() {
	if command -v apt-get >/dev/null; then echo apt
	elif command -v dnf >/dev/null; then echo dnf
	elif command -v yum >/dev/null; then echo yum
	elif command -v pacman >/dev/null; then echo pacman
	else echo unknown
	fi
}

# Package names differ per distribution.
packages_for() {
	local group=$1 pm=$2
	case "$pm:$group" in
		apt:build)      echo "clang llvm libbpf-dev libelf-dev zlib1g-dev make" ;;
		apt:dev)        echo "linux-tools-common bpftrace iperf3 sqlite3 jq" ;;
		dnf:build|yum:build)     echo "clang llvm libbpf-devel elfutils-libelf-devel zlib-devel make" ;;
		dnf:dev|yum:dev)         echo "bpftool bpftrace iperf3 sqlite jq" ;;
		pacman:build)   echo "clang llvm libbpf libelf zlib make" ;;
		pacman:dev)     echo "bpf bpftrace iperf3 sqlite jq" ;;
		*) echo "" ;;
	esac
}

install_packages() {
	local group=$1 pm pkgs
	pm=$(pkg_manager)
	pkgs=$(packages_for "$group" "$pm")

	if [ -z "$pkgs" ]; then
		warn "$pm" "no package list for this distribution; install manually: $group"
		return 0
	fi

	log "Installing $group packages via $pm: $pkgs"
	case "$pm" in
		apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq
		        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs ;;
		dnf)    dnf install -y -q $pkgs ;;
		yum)    yum install -y -q $pkgs ;;
		pacman) pacman -Sy --noconfirm --needed $pkgs ;;
	esac
}

# install_go fetches the official tarball when the distribution's Go is older
# than go.mod requires, which is the common case on stable distributions.
install_go() {
	local want have arch os url tmp sha
	want=$(go_required)
	have=$(go_installed || echo "none")

	if [ "$have" != "none" ] && ver_ge "$have" "$want"; then
		ok "go $have" "already satisfies go.mod (needs $want)"
		return 0
	fi

	case "$(uname -m)" in
		x86_64)  arch=amd64 ;;
		aarch64) arch=arm64 ;;
		armv6l|armv7l) arch=armv6l ;;
		*) warn "go" "unsupported architecture $(uname -m); install Go $want manually"; return 0 ;;
	esac
	os=$(uname -s | tr '[:upper:]' '[:lower:]')

	log "Installing Go $want (found: $have)"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' RETURN

	url="https://go.dev/dl/go${want}.${os}-${arch}.tar.gz"
	if ! curl -fsSL -o "$tmp/go.tar.gz" "$url"; then
		echo "could not download $url" >&2
		return 1
	fi

	# Verify against the checksum the download page publishes.
	sha=$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" |
		python3 -c "
import json,sys
want='go${want}.${os}-${arch}.tar.gz'
for rel in json.load(sys.stdin):
    for f in rel.get('files',[]):
        if f['filename']==want:
            print(f['sha256']); raise SystemExit
" 2>/dev/null || true)

	if [ -n "$sha" ]; then
		echo "$sha  $tmp/go.tar.gz" | sha256sum -c - >/dev/null
		ok "go tarball" "sha256 verified"
	else
		warn "go tarball" "checksum not published for this version; skipping verification"
	fi

	# The tarball unpacks as go/, so extract into the parent of the target.
	mkdir -p "$(dirname "$GO_INSTALL_DIR")"
	rm -rf "$GO_INSTALL_DIR"
	tar -C "$(dirname "$GO_INSTALL_DIR")" -xzf "$tmp/go.tar.gz"
	[ "$(basename "$GO_INSTALL_DIR")" = go ] || \
		mv "$(dirname "$GO_INSTALL_DIR")/go" "$GO_INSTALL_DIR"

	if [ "$GO_INSTALL_DIR" = /usr/local/go ]; then
		# Make it available to future login shells.
		printf 'export PATH=$PATH:%s/bin:$HOME/go/bin\n' "$GO_INSTALL_DIR" \
			> /etc/profile.d/go.sh
		chmod 644 /etc/profile.d/go.sh
		ok "go $want" "installed to $GO_INSTALL_DIR (PATH set via /etc/profile.d/go.sh)"
		echo "  ${D}open a new shell, or: export PATH=\$PATH:$GO_INSTALL_DIR/bin${N}"
	else
		ok "go $want" "installed to $GO_INSTALL_DIR"
	fi
}

# -------------------------------------------------------------------- check --

check() {
	local fail=0

	log "Kernel"
	local kver; kver=$(uname -r | cut -d- -f1)
	if ver_ge "$kver" "$MIN_KERNEL"; then
		ok "kernel $kver" "TCX attachment needs >= $MIN_KERNEL"
	else
		bad "kernel $kver" "TCX needs >= $MIN_KERNEL; ovpnmon will fail to attach"
		fail=1
	fi

	if [ -r /sys/kernel/btf/vmlinux ]; then
		ok "BTF" "/sys/kernel/btf/vmlinux present"
	else
		bad "BTF" "kernel built without CONFIG_DEBUG_INFO_BTF"
		fail=1
	fi

	if [ -c /dev/net/tun ]; then
		ok "tun device" "/dev/net/tun"
	else
		warn "tun device" "missing; needed to run OpenVPN on this host"
	fi

	log "Build toolchain"
	local want have
	want=$(go_required)
	have=$(go_installed || echo "")
	if [ -z "$have" ]; then
		bad "go" "not found; go.mod needs $want"
		fail=1
	elif ver_ge "$have" "$want"; then
		ok "go $have" "go.mod needs $want"
	else
		bad "go $have" "too old; go.mod needs $want"
		fail=1
	fi

	# clang and libbpf headers are only needed to regenerate the eBPF object.
	# The committed artefacts mean a plain build does not touch them.
	if command -v clang >/dev/null; then
		ok "clang" "$(clang --version | head -1)"
	else
		warn "clang" "only needed for 'make generate'"
	fi
	if [ -f /usr/include/bpf/bpf_helpers.h ]; then
		ok "libbpf headers" "/usr/include/bpf"
	else
		warn "libbpf headers" "only needed for 'make generate'"
	fi

	log "Runtime"
	for tool in ip iptables; do
		if command -v "$tool" >/dev/null; then ok "$tool" "$(command -v "$tool")"
		else bad "$tool" "required"; fail=1; fi
	done
	if command -v openvpn >/dev/null; then
		ok "openvpn" "$(openvpn --version 2>/dev/null | head -1 | cut -d' ' -f1-2)"
	else
		warn "openvpn" "only needed if this host also runs the VPN server"
	fi
	if command -v bpftool >/dev/null; then
		ok "bpftool" "optional, for inspecting the probe"
	else
		warn "bpftool" "optional"
	fi

	echo
	if [ "$fail" -eq 0 ]; then
		log "${G}Ready to build.${N}  make build && sudo make install"
	else
		log "${R}Missing requirements above.${N}  sudo $0 build"
	fi
	return $fail
}

# --------------------------------------------------------------------- main --

case "${1:-check}" in
	check)
		check
		;;
	build)
		need_root
		install_packages build
		install_go
		echo; check || true
		;;
	dev)
		need_root
		install_packages dev
		;;
	all)
		need_root
		install_packages build
		install_packages dev
		install_go
		echo; check || true
		;;
	*)
		echo "usage: $0 {check|build|dev|all}" >&2
		exit 1
		;;
esac
