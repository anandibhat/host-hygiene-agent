#!/usr/bin/env bash
# Uninstalls the scheduled daily host hygiene task on macOS and Linux.
set -e

if [[ "$(uname -s)" == "Darwin" ]]; then
    LABEL="com.hosthygiene.daily"
    PLIST_PATH="$HOME/Library/LaunchAgents/$LABEL.plist"

    if [ -f "$PLIST_PATH" ]; then
        launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
        rm -f "$PLIST_PATH"
        echo "[SUCCESS] Removed macOS LaunchAgent: $PLIST_PATH"
    else
        echo "[*] No active LaunchAgent found at: $PLIST_PATH"
    fi
else
    # Linux crontab cleanup
    EXISTING_CRON="$(crontab -l 2>/dev/null | grep -v "run_daily.py" || true)"
    if [ -n "$EXISTING_CRON" ]; then
        printf "%s\n" "$EXISTING_CRON" | crontab -
    else
        crontab -r 2>/dev/null || true
    fi
    echo "[SUCCESS] Removed Linux daily host hygiene crontab entry."
fi
