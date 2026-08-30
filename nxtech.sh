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
  echo "  nxtech off <machineId> <feature|all>   Deactivate a client's feature(s)"
  echo "  nxtech on  <machineId> <feature|all>   Reactivate a client's feature(s)"
  echo "  (feature = remote_access | mobile_data | all)"
  echo ""
}

case "$1" in

  list)
    echo ""
    echo "=== Subscribers ==="
    curl -s "$BASE_URL/subscribers" \
      -H "Authorization: Bearer $ADMIN_TOKEN" | \
      node -e "
        const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
        if (!d.subscribers.length) { console.log('  (none)'); process.exit(); }
        d.subscribers.forEach(s => {
          const ra = s.features && s.features.remote_access;
          const md = s.features && s.features.mobile_data;
          const anyOn = ra || md;
          const status = anyOn ? '✓ ACTIVE  ' : '✗ INACTIVE';
          const detail = 'remote:' + (ra ? 'on ' : 'off') + ' mobile:' + (md ? 'on ' : 'off');
          console.log(status + ' | ' + s.machineId + ' | ' + s.label + ' | ' + detail + ' | ' + (s.notes||''));
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
    if [ -z "$2" ] || [ -z "$3" ]; then
      echo "Usage: nxtech off <machineId> <remote_access|mobile_data|all>"
      exit 1
    fi
    FEATURES=("$3")
    if [ "$3" == "all" ]; then FEATURES=("remote_access" "mobile_data"); fi
    for F in "${FEATURES[@]}"; do
      RESULT=$(curl -s -X PATCH "$BASE_URL/subscribers/$2" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"feature\":\"$F\",\"active\":false}")
      echo "$RESULT" | grep -q '"ok":true' && \
        echo "✓ Deactivated $F for: $2" || \
        echo "✗ Failed ($F): $RESULT"
    done
    ;;

  on)
    if [ -z "$2" ] || [ -z "$3" ]; then
      echo "Usage: nxtech on <machineId> <remote_access|mobile_data|all>"
      exit 1
    fi
    FEATURES=("$3")
    if [ "$3" == "all" ]; then FEATURES=("remote_access" "mobile_data"); fi
    for F in "${FEATURES[@]}"; do
      RESULT=$(curl -s -X PATCH "$BASE_URL/subscribers/$2" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"feature\":\"$F\",\"active\":true}")
      echo "$RESULT" | grep -q '"ok":true' && \
        echo "✓ Reactivated $F for: $2" || \
        echo "✗ Failed ($F): $RESULT"
    done
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
