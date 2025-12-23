#!/bin/sh
set -eu

APP_PATH="${1:?usage: $0 /path/to/App.app}"

echo "== entitlements =="
codesign -d --entitlements :- "$APP_PATH" | plutil -p -

echo "== code signing flags =="
codesign -dvv "$APP_PATH" 2>&1 | sed -n '1,120p'
