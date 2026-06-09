#!/bin/bash
# =============================================================
# install.sh — Automated Suricata IDS Installation
# Supports: Ubuntu 20.04, 22.04, Debian 11/12
# =============================================================

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash install.sh"

log "Detecting OS..."
. /etc/os-release
log "OS: $NAME $VERSION_ID"

log "Adding Suricata stable PPA..."
apt-get install -y software-properties-common curl gnupg2 > /dev/null 2>&1
add-apt-repository -y ppa:oisf/suricata-stable > /dev/null 2>&1
apt-get update -q

log "Installing Suricata..."
apt-get install -y suricata suricata-update jq python3-pip > /dev/null 2>&1

log "Installing Python dependencies for response engine..."
pip3 install scapy requests watchdog python-telegram-bot --quiet 2>/dev/null || true

log "Enabling Suricata service..."
systemctl enable suricata

log "Updating Suricata rules (Emerging Threats)..."
suricata-update update-sources --quiet
suricata-update enable-source et/open
suricata-update

log "Copying project config..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/../config/suricata.yaml" /etc/suricata/suricata.yaml
cp "$SCRIPT_DIR/../rules/local.rules" /etc/suricata/rules/local.rules
cp "$SCRIPT_DIR/../rules/drop.rules"  /etc/suricata/rules/drop.rules || true

log "Creating log directory..."
mkdir -p /var/log/suricata
chown -R suricata:suricata /var/log/suricata 2>/dev/null || true

log "Testing config..."
suricata -T -c /etc/suricata/suricata.yaml -v 2>&1 | tail -5

log "✅ Suricata installed successfully!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Start:   sudo bash scripts/start-ids.sh eth0"
echo "  Logs:    tail -f /var/log/suricata/fast.log"
echo "  Alerts:  tail -f /var/log/suricata/eve.json | jq ."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
