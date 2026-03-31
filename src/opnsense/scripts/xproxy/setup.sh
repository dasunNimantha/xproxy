#!/bin/sh

# Download tun2socks binary for FreeBSD if not already present.

TUN2SOCKS_BIN="/usr/local/bin/tun2socks"
TUN2SOCKS_VERSION="2.6.0"
ARCH=$(uname -m)

if [ -x "$TUN2SOCKS_BIN" ]; then
    echo "tun2socks already installed at $TUN2SOCKS_BIN"
    exit 0
fi

case "$ARCH" in
    amd64|x86_64)
        ASSET="tun2socks-freebsd-amd64"
        ;;
    aarch64|arm64)
        ASSET="tun2socks-freebsd-arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

URL="https://github.com/xjasonlyu/tun2socks/releases/download/v${TUN2SOCKS_VERSION}/${ASSET}.zip"
TMPDIR=$(mktemp -d)

echo "Downloading tun2socks v${TUN2SOCKS_VERSION} for ${ARCH}..."
fetch -o "${TMPDIR}/${ASSET}.zip" "$URL" || exit 1

cd "$TMPDIR" || exit 1
if command -v unzip >/dev/null 2>&1; then
    unzip -o "${ASSET}.zip" || exit 1
else
    bsdtar -xf "${ASSET}.zip" || exit 1
fi

if [ -f "${ASSET}" ]; then
    install -m 0755 "${ASSET}" "$TUN2SOCKS_BIN"
elif [ -f "tun2socks" ]; then
    install -m 0755 "tun2socks" "$TUN2SOCKS_BIN"
else
    echo "Error: tun2socks binary not found in archive"
    rm -rf "$TMPDIR"
    exit 1
fi

rm -rf "$TMPDIR"
echo "tun2socks installed to $TUN2SOCKS_BIN"
