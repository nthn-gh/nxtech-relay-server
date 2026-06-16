#!/bin/bash

# Load ADMIN_TOKEN from systemd service environment
ADMIN_TOKEN=$(grep 'ADMIN_TOKEN' /etc/systemd/system/nxtech-relay.service | cut -d'=' -f3)
BASE_URL="http://localhost:3001"

show_help() {
  echo ""
  echo "NXTech Relay — Subscriber Manager"
  echo "----------------------------------"
  echo "  nxtech list              List all subscribers"
  echo "  nxtech add               Add a new client (interactive)"
  echo "  nxtech off <machineId>   Deactivate a client (kill switch)"
  echo "  nxtech on  <machineId>   Reactivate a client"
  echo "  nxtech remove <machineId> Remove a client permanently"
  echo "  nxtech status            Show relay server status"
  echo ""
}

case "$1" in

  list)
    echo ""
    echo "=== Active Subscribers ==="
    curl -s "$BASE_URL/subscribers" \
      -H "Authorization: Bearer $ADMIN_TOKEN" | \
      node -e "
        const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
        if (!d.subscribers.length) { console.log('  (none)'); process.exit(); }
        d.subscribers.forEach(s => {
          const status = s.active ? '✓ ACTIVE  ' : '✗ INACTIVE';
          console.log(status + ' | ' + s.machineId + ' | ' + s.label + ' | ' + (s.notes||''));
        });
      "
    echo ""
    ;;

  add)
    echo ""
    read -p "Host Machine ID:  " MACHINE_ID
    read -p "Shop Name:        " LABEL
    read -p "Notes (optional): " NOTES
    if [ -z "$MACHINE_ID" ] || [ -z "$LABEL" ]; then
      echo "✗ Machine ID and Shop Name are required."
      exit 1
    fi
    RESULT=$(curl -s -X POST "$BASE_URL/subscribers" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"machineId\":\"$MACHINE_ID\",\"label\":\"$LABEL\",\"active\":true,\"notes\":\"$NOTES\"}")
    echo "$RESULT" | grep -q '"ok":true' && \
      echo "✓ Added: $LABEL ($MACHINE_ID) — ACTIVE" || \
      echo "✗ Failed: $RESULT"
    echo ""
    ;;

  off)
    if [ -z "$2" ]; then echo "Usage: nxtech off <machineId>"; exit 1; fi
    RESULT=$(curl -s -X PATCH "$BASE_URL/subscribers/$2" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"active":false}')
    echo "$RESULT" | grep -q '"ok":true' && \
      echo "✓ Deactivated: $2 — relay access BLOCKED" || \
      echo "✗ Failed: $RESULT"
    ;;

  on)
    if [ -z "$2" ]; then echo "Usage: nxtech on <machineId>"; exit 1; fi
    RESULT=$(curl -s -X PATCH "$BASE_URL/subscribers/$2" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"active":true}')
    echo "$RESULT" | grep -q '"ok":true' && \
      echo "✓ Reactivated: $2 — relay access RESTORED" || \
      echo "✗ Failed: $RESULT"
    ;;

  remove)
    if [ -z "$2" ]; then echo "Usage: nxtech remove <machineId>"; exit 1; fi
    read -p "Are you sure you want to REMOVE $2? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then echo "Cancelled."; exit 0; fi
    RESULT=$(curl -s -X DELETE "$BASE_URL/subscribers/$2" \
      -H "Authorization: Bearer $ADMIN_TOKEN")
    echo "$RESULT" | grep -q '"ok":true' && \
      echo "✓ Removed: $2" || \
      echo "✗ Failed: $RESULT"
    ;;

  status)
    echo ""
    echo "=== Relay Server Status ==="
    systemctl status nxtech-relay.service --no-pager | head -20
    echo ""
    echo "=== Health Check ==="
    curl -s "$BASE_URL/../health" 2>/dev/null || \
    curl -s "http://localhost:8787/health"
    echo ""
    ;;

  *)
    show_help
    ;;
esac
