#!/bin/sh

# xproxy uninstaller for OPNsense
# Usage: fetch -o - https://raw.githubusercontent.com/dasunNimantha/xproxy/main/uninstall.sh | sh

set -e

PREFIX="/usr/local"

echo "==> Stopping xproxy service..."
configctl xproxy stop 2>/dev/null || true

echo "==> Removing plugin files..."

cd /tmp
fetch -o xproxy.tar.gz "https://github.com/dasunNimantha/xproxy/archive/refs/heads/main.tar.gz"
tar xzf xproxy.tar.gz
cd xproxy-main/src

find . -type f | while read FILE; do
    rm -f "${PREFIX}/${FILE}"
done

cd /tmp
rm -rf xproxy-main xproxy.tar.gz

echo "==> Restarting configd..."
service configd restart

echo "==> Reloading firewall rules..."
configctl filter reload

echo "==> Done. xproxy has been removed."
