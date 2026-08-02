#!/usr/bin/env bash
# Safe local demo: opens a real TCP listener on a port historically
# associated with malware/backdoors (31337 — "eleet"), using the
# harmless `nc` (netcat) that ships with macOS. Nothing leaves this
# machine, no data is sent anywhere. Sentinel's network monitor should
# pick this up within one poll interval (~5s) and score it high enough
# to cross the block threshold on the suspicious-port + new-listening-
# port rules alone, offering "Terminate process" in the dashboard.
#
# Usage: ./demo/trigger-suspicious-connection.sh
# Stop it with Ctrl+C (or it self-terminates after 30s).
set -euo pipefail

PORT=31337
echo "Opening a local TCP listener on port $PORT (harmless nc, no data sent anywhere)..."
echo "Watch the dashboard (http://localhost:4100) — this should appear within ~5-10s"
echo "as a 'blocked' incident with both suspicious-port and new-listening-port findings."
echo "Press Ctrl+C to stop early."

nc -l "$PORT" &
NC_PID=$!
trap 'kill $NC_PID 2>/dev/null || true' EXIT

sleep 30
