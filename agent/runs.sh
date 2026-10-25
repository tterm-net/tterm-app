#!/bin/sh
# The agent as built, run for a moment the way a computer runs it: with a
# hub that is not there it keeps trying and says so, and SIGTERM, as from
# launchd or systemd, stops it with success. Usage: agent/runs.sh FILE
set -u
AGENT=$1
LOG=$(mktemp)
env -i PATH=/usr/bin:/bin HOME="$HOME" "$AGENT" --token check --hub ws://127.0.0.1:9/agent >"$LOG" 2>&1 &
PID=$!
sleep 3
kill -TERM "$PID"
wait "$PID"
CODE=$?
cat "$LOG"
grep -q '^\[tterm-agent\] no link (' "$LOG" || { echo "it did not try the hub"; exit 1; }
grep -q '^\[tterm-agent\] stopped$' "$LOG" || { echo "it did not say it stopped"; exit 1; }
[ "$CODE" -eq 0 ] || { echo "it stopped with $CODE"; exit 1; }
echo "runs, and stops when told"
