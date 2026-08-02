#!/usr/bin/env bash
# Stops and removes the Sentinel Agent LaunchAgent. Does not touch
# ~/.sentinel/ (incident history/settings) — remove that manually if
# you want a full clean slate.
set -euo pipefail

PLIST_LABEL="com.sentinel.agent"
PLIST_DEST="$HOME/Library/LaunchAgents/${PLIST_LABEL}.plist"

launchctl bootout "gui/$(id -u)" "$PLIST_DEST" 2>/dev/null || true
rm -f "$PLIST_DEST"

echo "Sentinel Agent LaunchAgent removed. Incident history in ~/.sentinel/ was left untouched."
