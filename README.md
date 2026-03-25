# os-xproxy

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
| xray-core | [security/xray-core](https://www.freshports.org/security/xray-core/) | In FreeBSD ports |
| tun2socks | [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks) | Downloaded by setup script |

## Installation

Copy the plugin files to your OPNsense firewall:

```bash
# From the plugin directory
(cd src && find * -type f) | while read FILE; do
  cp --parents "src/$FILE" /usr/local/
done

# Restart configd
service configd restart
```

Or build and install as a package:

```bash
make package
pkg add work/pkg/*.pkg
```

## UI

The plugin adds **VPN > Xproxy** to the OPNsense sidebar with four tabs:

- **General** — Enable/disable the service, select active server, toggle transparent routing
- **Servers** — View and manage imported server profiles
- **Import** — Paste proxy URIs to import server configurations
- **Log** — Live service log viewer

## License

BSD 2-Clause. See [LICENSE](https://github.com/opnsense/plugins/blob/master/LICENSE).
