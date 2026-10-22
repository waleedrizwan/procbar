#!/bin/zsh
# Builds ProcBar.app into ~/Applications, starts it, and makes it launch at login.
# Uninstall: ./install.sh --uninstall
set -euo pipefail
cd "$(dirname "$0")"

APP="$HOME/Applications/ProcBar.app"
AGENT="$HOME/Library/LaunchAgents/com.waleedrizwan.procbar.plist"

pkill -x ProcBar 2>/dev/null || true
launchctl bootout "gui/$(id -u)/com.waleedrizwan.procbar" 2>/dev/null || true

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -rf "$APP" "$AGENT"
  echo "ProcBar removed."
  exit 0
fi

mkdir -p "$APP/Contents/MacOS" build
xcrun swiftc -O -swift-version 5 -o "$APP/Contents/MacOS/ProcBar" Sources/main.swift
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.waleedrizwan.procbar</string>
  <key>CFBundleName</key><string>ProcBar</string>
  <key>CFBundleExecutable</key><string>ProcBar</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$APP" >/dev/null

mkdir -p "$(dirname "$AGENT")"
cat > "$AGENT" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.waleedrizwan.procbar</string>
  <key>ProgramArguments</key><array><string>$APP/Contents/MacOS/ProcBar</string></array>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict></plist>
PLIST
launchctl bootstrap "gui/$(id -u)" "$AGENT"
echo "ProcBar installed at $APP and running (starts at login)."
