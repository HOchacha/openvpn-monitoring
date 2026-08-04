#!/usr/bin/env bash
# Install and configure Prometheus and Grafana for ovpnmon.
#
# Everything this writes comes from files in the repository, so the setup is
# reproducible: rebuild the host, run this again, get the same dashboards and
# alerts. Nothing is configured by clicking.
#
#   install.sh all         install both and wire them up
#   install.sh prometheus  Prometheus only
#   install.sh grafana     Grafana only
#   install.sh config      re-apply configuration without installing packages
#
# Prometheus wants port 9090, which is ovpnmon's default, so ovpnmon is moved
# to 9095 in its config file.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OVPNMON_CONF=/opt/ovpnmon/etc/ovpnmon.conf
OVPNMON_PORT_DEFAULT=9095
PROM_CONF=/etc/prometheus/prometheus.yml
PROM_DROPIN=/etc/prometheus/ovpnmon
GRAFANA_DASHBOARDS=/var/lib/grafana/dashboards/ovpnmon

# Settings come from observability.conf beside this script, so the deployment
# is described by a file in the repository rather than by whatever environment
# a command happened to run with. Environment variables still win, which keeps
# one-off overrides possible without editing the file.
CONF="${OBSERVABILITY_CONF:-$HERE/observability.conf}"
if [ -f "$CONF" ]; then
	while IFS='=' read -r key value; do
		key=$(echo "$key" | tr -d '[:space:]')
		value=$(echo "$value" | sed 's/[[:space:]]//g')
		case "$key" in
			''|'#'*) continue ;;
			bind_addr)       : "${BIND_ADDR:=$value}" ;;
			ovpnmon_port)    : "${OVPNMON_PORT:=$value}" ;;
			prometheus_port) : "${PROM_PORT:=$value}" ;;
			grafana_port)    : "${GRAFANA_PORT:=$value}" ;;
			*) echo "warning: unknown setting '$key' in $CONF" >&2 ;;
		esac
	done < "$CONF"
fi

BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
OVPNMON_PORT="${OVPNMON_PORT:-$OVPNMON_PORT_DEFAULT}"
PROM_PORT="${PROM_PORT:-9090}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

# ----------------------------------------------------------------- ovpnmon --

move_ovpnmon_port() {
	[ -f "$OVPNMON_CONF" ] || { warn "no $OVPNMON_CONF; is ovpnmon installed?"; return 0; }

	if grep -qE "^listen\s*=\s*$BIND_ADDR:$OVPNMON_PORT\s*$" "$OVPNMON_CONF"; then
		log "ovpnmon already listening on $BIND_ADDR:$OVPNMON_PORT"
		return 0
	fi

	log "Setting ovpnmon to listen on $BIND_ADDR:$OVPNMON_PORT"
	sed -i -E "s|^listen\s*=.*|listen = $BIND_ADDR:$OVPNMON_PORT|" "$OVPNMON_CONF"
	systemctl restart ovpnmon 2>/dev/null || true
}

# -------------------------------------------------------------- prometheus --

install_prometheus() {
	if command -v prometheus >/dev/null; then
		log "Prometheus already installed"
	else
		log "Installing Prometheus"
		DEBIAN_FRONTEND=noninteractive apt-get update -qq
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq prometheus
	fi
}

configure_prometheus() {
	log "Installing scrape config and rules into $PROM_DROPIN"
	install -d -m 755 "$PROM_DROPIN"
	install -m 644 "$HERE/prometheus/ovpnmon-scrape.yml" "$PROM_DROPIN/scrape.yml"
	install -m 644 "$HERE/prometheus/ovpnmon.rules.yml"  "$PROM_DROPIN/rules.yml"

	# Point the main config at the drop-in directory rather than pasting our
	# jobs into it, so upgrades and other jobs are unaffected.
	if ! grep -q "$PROM_DROPIN/scrape.yml" "$PROM_CONF"; then
		log "Referencing the drop-in from $PROM_CONF"
		cp "$PROM_CONF" "$PROM_CONF.ovpnmon-backup.$(date +%s)" 2>/dev/null || true
		python3 - "$PROM_CONF" "$PROM_DROPIN" <<'PY'
import sys, re
conf, dropin = sys.argv[1], sys.argv[2]
text = open(conf).read()

def ensure(text, key, entry):
    """Append entry to a top-level list key, adding the key if absent."""
    m = re.search(rf'^{key}:\s*$', text, re.M)
    if not m:
        return text.rstrip() + f"\n\n{key}:\n  - {entry}\n"
    # Insert as the first item of the existing block.
    end = m.end()
    return text[:end] + f"\n  - {entry}" + text[end:]

if f"{dropin}/scrape.yml" not in text:
    text = ensure(text, "scrape_config_files", f"{dropin}/scrape.yml")
if f"{dropin}/rules.yml" not in text:
    text = ensure(text, "rule_files", f"{dropin}/rules.yml")

open(conf, "w").write(text)
print(f"  updated {conf}")
PY
	fi

	# Bind to loopback. The default is every interface, which both collides
	# with anything else already on 9090 and publishes the VPN's traffic
	# history to the network.
	if [ -f /etc/default/prometheus ]; then
		want="--web.listen-address=$BIND_ADDR:$PROM_PORT"
		# -- so grep does not read the flag as one of its own options.
		if ! grep -qF -- "$want" /etc/default/prometheus; then
			log "Setting Prometheus to listen on $BIND_ADDR:$PROM_PORT"
			sed -i -E "s|^ARGS=.*|ARGS=\"$want\"|" /etc/default/prometheus
			grep -q '^ARGS=' /etc/default/prometheus || \
				echo "ARGS=\"$want\"" >> /etc/default/prometheus
		fi
	fi

	if command -v promtool >/dev/null; then
		log "Validating configuration"
		promtool check config "$PROM_CONF" | sed 's/^/    /'
		promtool check rules "$PROM_DROPIN/rules.yml" | sed 's/^/    /'
	fi

	systemctl enable --now prometheus >/dev/null 2>&1 || true
	systemctl restart prometheus
}

# ------------------------------------------------------------------ grafana --

install_grafana() {
	if command -v grafana-server >/dev/null || [ -d /usr/share/grafana ]; then
		log "Grafana already installed"
		return 0
	fi

	log "Adding Grafana's apt repository"
	install -d -m 755 /etc/apt/keyrings
	curl -fsSL https://apt.grafana.com/gpg.key |
		gpg --dearmor --yes -o /etc/apt/keyrings/grafana.gpg
	chmod 644 /etc/apt/keyrings/grafana.gpg
	echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
		> /etc/apt/sources.list.d/grafana.list

	log "Installing Grafana"
	DEBIAN_FRONTEND=noninteractive apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq grafana
}

configure_grafana() {
	log "Provisioning datasource and dashboard"
	install -d -m 755 /etc/grafana/provisioning/datasources
	install -d -m 755 /etc/grafana/provisioning/dashboards
	install -d -m 755 "$GRAFANA_DASHBOARDS"

	sed -E "s|url: http://127\\.0\\.0\\.1:[0-9]+|url: http://127.0.0.1:$PROM_PORT|" \
		"$HERE/grafana/datasource.yml" > /etc/grafana/provisioning/datasources/ovpnmon.yml
	chmod 644 /etc/grafana/provisioning/datasources/ovpnmon.yml
	install -m 644 "$HERE/grafana/dashboard-provider.yml" \
		/etc/grafana/provisioning/dashboards/ovpnmon.yml
	install -m 644 "$HERE/grafana/dashboards/ovpnmon.json" \
		"$GRAFANA_DASHBOARDS/ovpnmon.json"

	chown -R grafana:grafana /var/lib/grafana/dashboards 2>/dev/null || true

	# Loopback only: the dashboard shows every user's browsing destinations,
	# so exposing it needs a deliberate decision and authentication in front.
	if ! grep -qE "^\s*http_addr\s*=\s*${BIND_ADDR//./\\.}\s*$" /etc/grafana/grafana.ini; then
		log "Setting Grafana to listen on $BIND_ADDR"
		sed -i -E "s|^;?\s*http_addr\s*=.*|http_addr = $BIND_ADDR|" /etc/grafana/grafana.ini
	fi
	if ! grep -qE "^\s*http_port\s*=\s*$GRAFANA_PORT\s*$" /etc/grafana/grafana.ini; then
		sed -i -E "s|^;?\s*http_port\s*=.*|http_port = $GRAFANA_PORT|" /etc/grafana/grafana.ini
	fi
	if [ "$BIND_ADDR" != "127.0.0.1" ]; then
		warn "Grafana is now reachable off-host; change the admin password:"
		warn "  sudo grafana-cli admin reset-admin-password <new>"
	fi

	systemctl enable --now grafana-server >/dev/null 2>&1 || true
	systemctl restart grafana-server
}

# --------------------------------------------------------------------- main --

summary() {
	echo
	log "Endpoints"
	host="$BIND_ADDR"
	[ "$host" = "0.0.0.0" ] && host=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
	printf '    %-12s %s\n' "ovpnmon"    "http://$host:$OVPNMON_PORT/   (dashboard, /metrics)"
	printf '    %-12s %s\n' "Prometheus" "http://$host:$PROM_PORT/"
	printf '    %-12s %s\n' "Grafana"    "http://$host:$GRAFANA_PORT/"
	echo
	if [ "$BIND_ADDR" = "127.0.0.1" ]; then
		echo "    All three bind to loopback. Reach them with an SSH tunnel:"
		echo "      ssh -N -L $GRAFANA_PORT:127.0.0.1:$GRAFANA_PORT -L $PROM_PORT:127.0.0.1:$PROM_PORT <user>@<host>"
	else
		echo "    These are reachable off-host and expose every VPN user's"
		echo "    browsing destinations. Restrict them at the firewall and put"
		echo "    authentication in front of ovpnmon and Prometheus, which have none."
	fi
}

case "${1:-all}" in
	all)
		move_ovpnmon_port
		install_prometheus
		configure_prometheus
		install_grafana
		configure_grafana
		summary
		;;
	prometheus) install_prometheus; configure_prometheus ;;
	grafana)    install_grafana; configure_grafana ;;
	config)
		move_ovpnmon_port
		configure_prometheus
		configure_grafana
		summary
		;;
	*) echo "usage: $0 {all|prometheus|grafana|config}" >&2; exit 1 ;;
esac
