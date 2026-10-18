#!/usr/bin/env bash
# Sets up scheduled daily host hygiene execution for laptop/workstation on macOS and Linux.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOUR="${1:-9}"
MINUTE="${2:-0}"

# Find Python 3 binary
if command -v python3 >/dev/null 2>&1; then
    PY_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PY_BIN="$(command -v python)"
else
    echo "[!] Error: Python 3 not found on PATH." >&2
    exit 1
fi

TARGET_SCRIPT="$SCRIPT_DIR/run_daily.py"

echo "=========================================================="
echo " Setting Up Daily Host Hygiene Scheduled Task"
echo "=========================================================="
echo " Platform:      $(uname -s)"
echo " Scheduled Time: $(printf "%02d:%02d" "$HOUR" "$MINUTE") Daily"
echo " Python Binary:  $PY_BIN"
echo " Target Script:  $TARGET_SCRIPT"
echo ""

if [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS: LaunchAgent via launchd
    LABEL="com.hosthygiene.daily"
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_PATH="$PLIST_DIR/$LABEL.plist"

    mkdir -p "$PLIST_DIR"

    # Unload existing if loaded
    launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true

    cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PY_BIN</string>
        <string>$TARGET_SCRIPT</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$SCRIPT_DIR</string>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>$HOUR</integer>
        <key>Minute</key>
        <integer>$MINUTE</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>$SCRIPT_DIR/daily_reports/launchd_stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$SCRIPT_DIR/daily_reports/launchd_stderr.log</string>
</dict>
</plist>
EOF

    mkdir -p "$SCRIPT_DIR/daily_reports"
    launchctl load "$PLIST_PATH"

    echo "[SUCCESS] macOS LaunchAgent registered: $PLIST_PATH"
    echo " -> Scheduled to run every day at $(printf "%02d:%02d" "$HOUR" "$MINUTE")."
    echo " -> Daily reports and history will be saved to: $SCRIPT_DIR/daily_reports/"

else
    # Linux: user crontab
    CRON_CMD="$PY_BIN $TARGET_SCRIPT >> $SCRIPT_DIR/daily_reports/cron.log 2>&1"
    CRON_SCHEDULE="$MINUTE $HOUR * * * $CRON_CMD"

    mkdir -p "$SCRIPT_DIR/daily_reports"

    # Get current crontab excluding existing host hygiene task
    EXISTING_CRON="$(crontab -l 2>/dev/null | grep -v "run_daily.py" || true)"

    # Write updated crontab
    if [ -n "$EXISTING_CRON" ]; then
        printf "%s\n%s\n" "$EXISTING_CRON" "$CRON_SCHEDULE" | crontab -
    else
        printf "%s\n" "$CRON_SCHEDULE" | crontab -
    fi

    echo "[SUCCESS] Linux crontab schedule registered."
    echo " -> Scheduled: $CRON_SCHEDULE"
    echo " -> Daily reports and history will be saved to: $SCRIPT_DIR/daily_reports/"
fi
