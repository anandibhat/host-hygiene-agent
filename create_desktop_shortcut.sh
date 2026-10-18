#!/usr/bin/env bash
# Creates a Desktop launcher shortcut for Host Hygiene on macOS or Linux.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="$HOME/Desktop"

if [ ! -d "$DESKTOP_DIR" ]; then
    echo "[!] Desktop directory not found at $DESKTOP_DIR" >&2
    exit 1
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS: Create a double-clickable .command file
    SHORTCUT="$DESKTOP_DIR/Run Host Hygiene.command"
    cat <<EOF > "$SHORTCUT"
#!/bin/bash
cd "$SCRIPT_DIR"
./run.sh "\$@"
echo ""
read -n 1 -s -r -p "Press any key to close this terminal..."
echo ""
EOF
    chmod +x "$SHORTCUT"
    echo "[SUCCESS] Created macOS desktop shortcut at: $SHORTCUT"
    echo " -> You can now double-click 'Run Host Hygiene.command' on your Desktop to audit."
else
    # Linux: Create an XDG .desktop file
    SHORTCUT="$DESKTOP_DIR/host-hygiene.desktop"
    cat <<EOF > "$SHORTCUT"
[Desktop Entry]
Version=1.0
Type=Application
Name=Host Hygiene Agent
Comment=Run Host Hygiene & Process Triage Audit
Exec=bash -c 'cd "$SCRIPT_DIR" && ./run.sh; read -p "Press Enter to exit..."'
Icon=security-high
Terminal=true
Categories=System;Security;
EOF
    chmod +x "$SHORTCUT"
    echo "[SUCCESS] Created Linux desktop launcher at: $SHORTCUT"
fi
