#!/usr/bin/env bash
# Measure what ovpnmon's probe costs when traffic converges on it.
#
#   ./incast-bench.sh fanin  [max_clients]   N clients -> one destination
#   ./incast-bench.sh fanout [connections]   one client -> many destinations
#
# What this can and cannot show:
#
#   It CAN show what the eBPF probe does under convergent load - per-packet
#   cost, flow map pressure, ring buffer loss, and whether attribution stays
#   correct when many clients are active at once.
#
#   It CANNOT reproduce real TCP incast collapse. That comes from a switch's
#   shallow buffer overflowing and senders backing off on RTO; a veth and
#   loopback path has no such bottleneck. Treat the throughput numbers as
#   "how much work reached the probe", not as a congestion study.
#
# Note that OpenVPN's userspace datapath is single-threaded, so tun traffic
# serialises through one thread no matter how many clients send at once. That
# bounds the concurrency the probe ever sees, and is itself a result.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-fanin}"
ARG="${2:-}"

TARGET="${TARGET:-$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')}"
OVPNMON="${OVPNMON:-127.0.0.1:9095}"
IFACE="${IFACE:-tun0}"
DURATION="${DURATION:-10}"

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# ------------------------------------------------------------- measurement --

# Keys are passed as arguments rather than spliced into the program text;
# quoting a Python subscript through the shell is how this silently returned
# zero for every field the first time.
snapshot_field() {
	curl -sS "http://$OVPNMON/api/snapshot" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
for k in sys.argv[1:]:
    d = d[k]
print(d)' "$@" 2>/dev/null || echo 0
}

# Look the program up by what is attached to the interface, not by name.
# Restarting ovpnmon can leave earlier programs loaded but detached, and those
# carry zero counters - matching on name alone picks one of those and reports
# nothing happening.
prog_stats() {  # $1 = ovpnmon_ingress|ovpnmon_egress -> "total_ns run_count"
	local id
	id=$(bpftool net show dev "$IFACE" 2>/dev/null |
		awk -v n="$1" '$0 ~ n { for (i = 1; i <= NF; i++) if ($i == "prog_id") print $(i+1) }' |
		head -1)
	[ -n "$id" ] || { echo "0 0"; return; }

	bpftool prog show id "$id" -j 2>/dev/null | python3 -c '
import json, sys
p = json.load(sys.stdin)
print(p.get("run_time_ns", 0), p.get("run_cnt", 0))' 2>/dev/null || echo "0 0"
}

# ------------------------------------------------------------------ fan-in --

fanin() {
	local max=${ARG:-4}
	local names=() i

	for i in $(seq 1 "$max"); do names+=("inc$i"); done

	log "Issuing $max client certificates"
	"$HERE/make-client.sh" "${names[@]}" >/dev/null

	log "Starting iperf3 server on $TARGET"
	pkill -x iperf3 2>/dev/null || true
	sleep 1
	iperf3 -s -B "$TARGET" -D --logfile /tmp/incast-iperf.log

	printf '\n  %-8s %-12s %-12s %-10s %-9s %-8s %s\n' \
		clients aggregate per-client ns/pkt flows lost retrans

	for n in $(seq 1 "$max"); do
		# Bring up n clients, each in its own namespace and veth subnet.
		for i in $(seq 1 "$n"); do
			SUBNET_BASE="192.168.$((230 + i))" \
				"$HERE/test-client.sh" up "inc$i" >/dev/null 2>&1 || true
		done
		sleep 3

		local b_ns b_cnt
		read -r b_ns b_cnt <<<"$(prog_stats ovpnmon_ingress)"

		# All clients transmit at once; that convergence is the point.
		local results=() pids=()
		for i in $(seq 1 "$n"); do
			( ip netns exec "vpn-inc$i" iperf3 -c "$TARGET" -t "$DURATION" -f m \
				--json > "/tmp/incast-$i.json" 2>/dev/null ) &
			pids+=($!)
		done
		wait "${pids[@]}" 2>/dev/null || true

		local a_ns a_cnt
		read -r a_ns a_cnt <<<"$(prog_stats ovpnmon_ingress)"

		local agg retrans
		agg=$(python3 - "$n" <<'PY'
import json,sys
total=0.0; rx=0
for i in range(1, int(sys.argv[1])+1):
    try:
        d=json.load(open(f"/tmp/incast-{i}.json"))
        total += d["end"]["sum_received"]["bits_per_second"]/1e6
        rx   += d["end"]["sum_sent"].get("retransmits",0)
    except Exception:
        pass
print(f"{total:.0f} {rx}")
PY
)
		retrans=${agg#* }; agg=${agg%% *}

		local nspkt="-"
		if [ "$((a_cnt - b_cnt))" -gt 0 ]; then
			nspkt=$(python3 -c "print(f'{($a_ns-$b_ns)/($a_cnt-$b_cnt):.0f}')")
		fi

		printf '  %-8s %-12s %-12s %-10s %-9s %-8s %s\n' \
			"$n" "${agg} Mb/s" \
			"$(python3 -c "print(f'{$agg/$n:.0f} Mb/s')")" \
			"$nspkt" \
			"$(snapshot_field flow_count)" \
			"$(snapshot_field probe events_lost)" \
			"$retrans"
	done

	log "Tearing down"
	for i in $(seq 1 "$max"); do
		SUBNET_BASE="192.168.$((230 + i))" \
			"$HERE/test-client.sh" down "inc$i" >/dev/null 2>&1 || true
	done
	pkill -x iperf3 2>/dev/null || true
}

# ----------------------------------------------------------------- fan-out --

# One client opening many short connections to distinct destinations is the
# harder case for ovpnmon: every destination is a new flow map entry, and every
# SYN and TLS handshake is a ring buffer event.
fanout() {
	local conns=${ARG:-500}

	log "Ensuring a client is up"
	SUBNET_BASE=192.168.231 "$HERE/test-client.sh" up inc1 >/dev/null 2>&1 || true
	sleep 3

	local b_lost b_flows
	b_lost=$(snapshot_field probe events_lost)
	b_flows=$(snapshot_field flow_count)

	log "Opening $conns connections to distinct destinations"
	# Distinct ports on one host still produce distinct flow-map keys, which is
	# what the map and ring buffer actually see.
	ip netns exec vpn-inc1 bash -c "
		for p in \$(seq 1 $conns); do
			(exec 3<>/dev/tcp/$TARGET/\$((20000 + p % 1000)) ) 2>/dev/null &
		done
		wait" 2>/dev/null || true
	sleep 4

	printf '\n  flows: %s -> %s\n' "$b_flows" "$(snapshot_field flow_count)"
	printf '  events lost: %s -> %s\n' "$b_lost" "$(snapshot_field probe events_lost)"
	printf '  probe packets: %s\n' "$(snapshot_field probe packets)"

	log "Tearing down"
	SUBNET_BASE=192.168.231 "$HERE/test-client.sh" down inc1 >/dev/null 2>&1 || true
}

# --------------------------------------------------------------------- main --

command -v iperf3 >/dev/null || { echo "iperf3 missing: make deps-dev" >&2; exit 1; }

log "Enabling BPF run statistics (adds ~50ns per invocation; disabled after)"
sysctl -qw kernel.bpf_stats_enabled=1
trap 'sysctl -qw kernel.bpf_stats_enabled=0' EXIT

case "$MODE" in
	fanin)  fanin ;;
	fanout) fanout ;;
	*) echo "usage: $0 {fanin|fanout} [n]" >&2; exit 1 ;;
esac
