# xproxy

OPNsense plugin for Xray-core with transparent LAN routing.

When enabled, LAN traffic is routed through a VLESS, VMess, Shadowsocks, or Trojan tunnel — no configuration needed on individual devices.

## Features

- Transparent proxying via TUN interface (hev-socks5-tunnel) — phones, IoT, smart TVs, and guest devices are covered automatically
- VLESS (with XTLS-Vision / Reality), VMess, Shadowsocks, and Trojan protocols
- Import server profiles from standard proxy URIs (`vless://`, `vmess://`, `ss://`, `trojan://`)
- Per-interface routing — choose which LANs (e.g. Guest, IoT) route through the tunnel, or route all
- Policy-based routing with dynamic firewall rules — rules are only active while the service is running
- Context-aware server dialog — fields shown/hidden based on selected protocol, security, and transport
- Multiple server profiles with quick switching and auto-select on add/import/delete
- Hardened process lifecycle — file locking, PID verification, orphan cleanup, crash recovery
- Optimized xray config — sniffing with routeOnly, connection policy tuning, TCP Fast Open, DNS caching
- TCP buffer and congestion control tuning via `sysctl.d` for high-throughput proxy workloads
- Service log viewer with smart auto-scroll

## How it works

1. **Xray-core** connects to the remote proxy server and exposes a local SOCKS5 endpoint
2. **hev-socks5-tunnel** creates a TUN interface (`tun9`) that routes traffic through the SOCKS5 endpoint
3. The plugin registers a virtual interface (`xproxytun`) and gateway (`XPROXY_TUN`) in OPNsense
4. Firewall rules route selected LAN interface traffic through the TUN gateway using OPNsense's `_firewall()` plugin hook
5. When "Route LAN through tunnel" is disabled, only local SOCKS5/HTTP proxy is available — TUN and firewall rules are skipped

## Dependencies

| Package | Source | Status |
|---|---|---|
| xray-core | [security/xray-core](https://www.freshports.org/security/xray-core/) | Installed by `install.sh` or manual setup |
| hev-socks5-tunnel | [heiher/hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) | Downloaded by `install.sh` / `xproxy setup` |

## Installation

SSH into your OPNsense firewall and run:

```bash
fetch -o - https://raw.githubusercontent.com/dasunNimantha/xproxy/main/install.sh | sh
```

The installer copies the plugin files, installs `xray-core`, downloads the `hev-socks5-tunnel` binary, and restarts `configd`.

Then navigate to **VPN > Xproxy** in the web UI to configure.

### Manual installation

```bash
pkg install -y xray-core

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

- **General** — Enable/disable the service, select active server, toggle transparent routing, choose which interfaces to tunnel
- **Servers** — View and manage server profiles (shows protocol, address, port, security at a glance)
- **Import** — Paste proxy URIs to batch-import server configurations (with parse error reporting)
- **Log** — Live service log viewer with smart auto-scroll (won't jump to bottom while you're reading)

The Active Server dropdown refreshes automatically when servers are added, deleted, edited, or imported. When no active server is set, the plugin auto-selects the first available server.

TUN-related fields (Tunnel Interfaces, TUN Device, TUN Address, TUN Gateway, Bypass IPs) are hidden when "Route LAN through tunnel" is unchecked, keeping the UI clean for SOCKS-only setups.

## Performance tuning

The plugin ships TCP tuning via `/usr/local/etc/sysctl.d/xproxy.conf`:

- Large socket buffers (`maxsockbuf=16M`, send/recv max `8M`) sized for ~500 Mbps at 50ms RTT
- Initial congestion window of 44 segments for faster ramp-up on new connections
- CDG (CAIA Delay Gradient) congestion control — performs better than CUBIC on paths with bufferbloat or variable latency

On the VPS/server side, enable **BBR** congestion control for matched performance:

```bash
# Enable BBR (Linux)
modprobe tcp_bbr
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.default_qdisc=fq

# Persist
echo tcp_bbr >> /etc/modules-load.d/bbr.conf
echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.d/99-xray-tuning.conf
echo 'net.core.default_qdisc=fq' >> /etc/sysctl.d/99-xray-tuning.conf
```

## License

BSD 2-Clause. See [LICENSE](https://github.com/opnsense/plugins/blob/master/LICENSE).
