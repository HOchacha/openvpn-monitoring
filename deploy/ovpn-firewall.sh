#!/usr/bin/env bash
# Apply (or remove) the packet-forwarding rules the VPN needs.
#
# iptables rules live in kernel memory only. Without something to reinstate
# them at boot, clients still connect after a reboot but reach nothing - a
# failure that looks like a VPN problem and is actually a missing NAT rule.
#
# This deliberately manages only its own rules rather than saving and restoring
# the whole table, so it cannot clobber firewall rules owned by anything else.
#
# Usage: ovpn-firewall.sh {up|down|status}
set -euo pipefail

VPN_NET="${VPN_NET:-10.8.0.0/24}"
TUN_IF="${TUN_IF:-tun0}"
WAN_IF="${WAN_IF:-$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')}"

[ -n "$WAN_IF" ] || { echo "could not determine the WAN interface; set WAN_IF" >&2; exit 1; }

# Each entry is a table and the rule body, so up/down/status stay in step.
rules() {
	printf '%s\n' \
		"nat|POSTROUTING|-s $VPN_NET -o $WAN_IF -j MASQUERADE" \
		"filter|FORWARD|-i $TUN_IF -j ACCEPT" \
		"filter|FORWARD|-o $TUN_IF -j ACCEPT"
}

up() {
	while IFS='|' read -r table chain rule; do
		if ! iptables -t "$table" -C "$chain" $rule 2>/dev/null; then
			iptables -t "$table" -A "$chain" $rule
			echo "added: -t $table -A $chain $rule"
		fi
	done < <(rules)
}

down() {
	while IFS='|' read -r table chain rule; do
		while iptables -t "$table" -C "$chain" $rule 2>/dev/null; do
			iptables -t "$table" -D "$chain" $rule
			echo "removed: -t $table -D $chain $rule"
		done
	done < <(rules)
}

status() {
	local missing=0
	while IFS='|' read -r table chain rule; do
		if iptables -t "$table" -C "$chain" $rule 2>/dev/null; then
			echo "present: -t $table $chain $rule"
		else
			echo "MISSING: -t $table $chain $rule"
			missing=1
		fi
	done < <(rules)
	return $missing
}

case "${1:-up}" in
	up)     up ;;
	down)   down ;;
	status) status ;;
	*) echo "usage: $0 {up|down|status}" >&2; exit 1 ;;
esac
