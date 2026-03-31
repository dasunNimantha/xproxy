# xproxy

Category: `security/xproxy`

OPNsense plugin for Xray-core with transparent LAN routing.

When enabled, all LAN traffic is routed through a VLESS, VMess, Shadowsocks, or Trojan tunnel — no configuration needed on individual devices.

## Features

- Transparent proxying via TUN interface (tun2socks) — phones, IoT, smart TVs, and guest devices are covered automatically
- VLESS (with XTLS-Vision / Reality), VMess, Shadowsocks, and Trojan protocols
- Import server profiles from standard proxy URIs (`vless://`, `vmess://`, `ss://`, `trojan://`)
- Policy-based routing with dynamic firewall rules — rules are only active while the service is running
- Multiple server profiles with quick switching
- Service log viewer with rotation

## How it works

1. **Xray-core** connects to the remote proxy server and exposes a local SOCKS5 endpoint
2. **tun2socks** creates a TUN interface (`tun9`) that routes traffic through the SOCKS5 endpoint
3. The plugin registers a virtual interface (`xproxytun`) and gateway (`XPROXY_TUN`) in OPNsense
4. Firewall rules route LAN traffic through the TUN gateway using OPNsense's `_firewall()` plugin hook

## Dependencies

| Package | Source | Status |
|---|---|---|
| xray-core | [security/xray-core](https://www.freshports.org/security/xray-core/) | Installed by `install.sh` or manual setup |
| tun2socks | [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks) | Downloaded by `install.sh` / `xproxy setup` |

## Installation

SSH into your OPNsense firewall and run:

```bash
fetch -o - https://raw.githubusercontent.com/dasunNimantha/xproxy/main/install.sh | sh
```

The installer copies the plugin files, installs `xray-core` and `unzip`, downloads the `tun2socks` binary, and restarts `configd`.

Then navigate to **VPN > Xproxy** in the web UI to configure.

### Manual installation

```bash
# Install runtime dependencies
pkg install -y xray-core unzip

# Clone and copy plugin files
cd /tmp
fetch -o xproxy.tar.gz https://github.com/dasunNimantha/xproxy/archive/refs/heads/main.tar.gz
tar xzf xproxy.tar.gz
cd xproxy-main/src
find . -type f | while read FILE; do
  mkdir -p "$(dirname /usr/local/$FILE)"
  cp "$FILE" "/usr/local/$FILE"
done
chmod +x /usr/local/opnsense/scripts/xproxy/*.py /usr/local/opnsense/scripts/xproxy/*.sh /usr/local/opnsense/scripts/xproxy/*.php 2>/dev/null || true
/usr/local/opnsense/scripts/xproxy/setup.sh
service configd restart
```

### Uninstall

```bash
fetch -o - https://raw.githubusercontent.com/dasunNimantha/xproxy/main/uninstall.sh | sh
```

## UI

The plugin adds **VPN > Xproxy** to the OPNsense sidebar with four tabs:

- **General** — Enable/disable the service, select active server, toggle transparent routing
- **Servers** — View and manage imported server profiles
- **Import** — Paste proxy URIs to import server configurations
- **Log** — Live service log viewer

## License

BSD 2-Clause. See [LICENSE](https://github.com/opnsense/plugins/blob/master/LICENSE).
