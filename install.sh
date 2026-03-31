#!/bin/sh

# xproxy installer for OPNsense
# Usage: fetch -o - https://raw.githubusercontent.com/dasunNimantha/xproxy/main/install.sh | sh

set -e

REPO="dasunNimantha/xproxy"
BRANCH="main"
PREFIX="/usr/local"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run this installer as root."
    exit 1
fi

echo "==> Installing xproxy..."

MISSING_PKGS=""
for PKG in xray-core unzip; do
    if ! pkg info -e "${PKG}" >/dev/null 2>&1; then
        MISSING_PKGS="${MISSING_PKGS} ${PKG}"
    fi
done

if [ -n "${MISSING_PKGS}" ]; then
    echo "==> Installing required packages:${MISSING_PKGS}"
    pkg install -y ${MISSING_PKGS}
else
    echo "==> Required packages already installed."
fi

cd /tmp
fetch -o xproxy.tar.gz "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
tar xzf xproxy.tar.gz
cd xproxy-${BRANCH}/src

find . -type f | while read FILE; do
    DIR=$(dirname "${PREFIX}/${FILE}")
    mkdir -p "${DIR}"
    cp "${FILE}" "${PREFIX}/${FILE}"
done

chmod +x "${PREFIX}/opnsense/scripts/xproxy/"*.py "${PREFIX}/opnsense/scripts/xproxy/"*.sh "${PREFIX}/opnsense/scripts/xproxy/"*.php 2>/dev/null || true

echo "==> Installing tun2socks..."
"${PREFIX}/opnsense/scripts/xproxy/setup.sh"

cd /tmp
rm -rf xproxy-${BRANCH} xproxy.tar.gz

echo "==> Restarting configd..."
service configd restart

echo "==> Done. Navigate to VPN > Xproxy in the OPNsense web UI."
