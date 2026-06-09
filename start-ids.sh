#!/bin/bash
# start-ids.sh — Start Suricata IDS on specified interface

IFACE=${1:-eth0}
CONFIG=/etc/suricata/suricata.yaml
LOG_DIR=/var/log/suricata

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${GREEN}[+]${NC} Starting Suricata IDS on interface: ${YELLOW}$IFACE${NC}"

# Check interface exists
ip link show "$IFACE" > /dev/null 2>&1 || { echo -e "${RED}[ERROR]${NC} Interface $IFACE not found."; ip link show | grep '^[0-9]'; exit 1; }

# Enable promiscuous mode
ip link set "$IFACE" promisc on
echo -e "${GREEN}[+]${NC} Promiscuous mode enabled on $IFACE"

# Kill existing instance
pkill -f suricata 2>/dev/null && echo -e "${YELLOW}[!]${NC} Stopped existing Suricata process"
sleep 1

mkdir -p "$LOG_DIR"

# Start Suricata
suricata -c "$CONFIG" -i "$IFACE" --pidfile /var/run/suricata.pid -D

sleep 2
if pgrep -f suricata > /dev/null; then
    echo -e "${GREEN}[✓]${NC} Suricata is running (PID: $(cat /var/run/suricata.pid 2>/dev/null))"
    echo ""
    echo "  Live alerts:  tail -f $LOG_DIR/fast.log"
    echo "  JSON events:  tail -f $LOG_DIR/eve.json | jq ."
    echo "  Stop:         sudo pkill suricata"
else
    echo -e "${RED}[ERROR]${NC} Suricata failed to start. Check: $LOG_DIR/suricata.log"
    tail -20 "$LOG_DIR/suricata.log"
fi
