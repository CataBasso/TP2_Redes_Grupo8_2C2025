#!/usr/bin/env bash
# cleanup_env.sh
# Script to clean Mininet/POX test artifacts safely.
# Usage:
#   chmod +x scripts/cleanup_env.sh
#   ./scripts/cleanup_env.sh [--delete-ovs-bridges]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DELETE_OVS_BRIDGES=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --delete-ovs-bridges)
      DELETE_OVS_BRIDGES=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--delete-ovs-bridges]"
      echo "  --delete-ovs-bridges  : delete OVS bridges found (destructive)"
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

echo "[cleanup] Starting environment cleanup"

echo "[cleanup] Killing test servers (http.server, nc listeners)"
pkill -f 'http.server' || true
pkill -f "nc -u -l" || true
pkill -f "nc -u -6 -l" || true

echo "[cleanup] Removing temporary test logs in /tmp"
rm -f /tmp/http80.log /tmp/udp80.log /tmp/http80v6.log /tmp/udp80v6.log || true
rm -f /tmp/http8080.log /tmp/udp8080.log /tmp/http8080_v6.log /tmp/udp8080_v6.log || true

echo "[cleanup] Flushing ARP / neighbour caches (requires sudo)"
if command -v sudo >/dev/null 2>&1; then
  sudo ip -s -s neigh flush all || true
  sudo ip -6 neigh flush all || true
else
  ip -s -s neigh flush all || true
  ip -6 neigh flush all || true
fi

echo "[cleanup] POX: attempt to send SIGHUP to reset in-memory state (if running)"
if pgrep -f pox.py >/dev/null 2>&1; then
  pkill -HUP -f pox.py || true
  echo "[cleanup] SIGHUP sent to pox.py (if supported). If you prefer a full restart, run: pkill -f pox.py && start it again."
else
  echo "[cleanup] No running pox.py process found."
fi

echo "[cleanup] Killing any remaining POX processes"
pkill -f pox.py || true

echo "[cleanup] Removing pox.log in repo"
rm -f "${REPO_ROOT}/pox.log" || true

# Mininet cleanup
if command -v mn >/dev/null 2>&1; then
  echo "[cleanup] Running 'sudo mn -c' to clean Mininet/OVS artifacts (requires sudo)"
  sudo mn -c || true
else
  echo "[cleanup] 'mn' command not found. Skipping 'mn -c'."
fi

# OVS: list bridges and clear flows
if command -v ovs-vsctl >/dev/null 2>&1 && command -v ovs-ofctl >/dev/null 2>&1; then
  echo "[cleanup] Listing OVS bridges"
  BRIDGES=$(sudo ovs-vsctl list-br 2>/dev/null || true)
  if [[ -z "$BRIDGES" ]]; then
    echo "[cleanup] No OVS bridges found"
  else
    echo "[cleanup] Found OVS bridges:"
    echo "$BRIDGES"
    for br in $BRIDGES; do
      echo "[cleanup] Dumping flows on $br"
      sudo ovs-ofctl dump-flows $br || true
      echo "[cleanup] Deleting flows on $br"
      sudo ovs-ofctl del-flows $br || true
      if $DELETE_OVS_BRIDGES; then
        echo "[cleanup] Deleting OVS bridge $br (destructive)"
        sudo ovs-vsctl --if-exists del-br $br || true
      fi
    done
  fi
else
  echo "[cleanup] OVS tools not found (ovs-vsctl/ovs-ofctl). Skipping OVS cleanup."
fi

# Linux bridges (usually Docker). Don't delete by default.
echo "[cleanup] Linux bridges (br-*) present:"
ls /sys/class/net | grep '^br-' || true

# Network namespaces
echo "[cleanup] Network namespaces (ip netns list):"
ip netns list || true

# Listener on OpenFlow port
echo "[cleanup] Checking if any process listens on 6633 (OpenFlow)"
ss -nlp | grep 6633 || true

# Show pox processes if any
echo "[cleanup] POX processes:"
pgrep -a -f pox.py || true

# Final message
echo "[cleanup] Cleanup completed. If you still see test failures, consider restarting POX manually and/or rebooting networking services."

exit 0
