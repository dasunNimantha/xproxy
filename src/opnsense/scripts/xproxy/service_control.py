#!/usr/local/bin/python3

"""
Xproxy service lifecycle manager.
Reads OPNsense config.xml, generates xray-core config, manages
xray-core and tun2socks processes, and configures the TUN interface.

Usage: service_control.py <start|stop|restart|reconfigure|status>
"""

import sys
import os
import re
import json
import signal
import time
import subprocess
import ipaddress
import xml.etree.ElementTree as ET

CONFIG_XML = '/conf/config.xml'
XRAY_BIN = '/usr/local/bin/xray'
TUN2SOCKS_BIN = '/usr/local/bin/tun2socks'
CONFIG_DIR = '/usr/local/etc/xproxy'
XRAY_CONFIG = os.path.join(CONFIG_DIR, 'config.json')
XRAY_PID = '/var/run/xproxy_xray.pid'
TUN2SOCKS_PID = '/var/run/xproxy_tun2socks.pid'
LOG_FILE = '/var/log/xproxy.log'

TUN_DEVICE_RE = re.compile(r'^tun[0-9]{1,3}$')
SUPPORTED_PROTOCOLS = ('vless', 'vmess', 'shadowsocks', 'trojan')


def _safe_int(value, default, minimum=None, maximum=None):
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if minimum is not None and n < minimum:
        return default
    if maximum is not None and n > maximum:
        return default
    return n


def read_config():
    """Read xproxy settings from OPNsense config.xml."""
    try:
        tree = ET.parse(CONFIG_XML)
    except (ET.ParseError, OSError):
        return None
    root = tree.getroot()
    xp = root.find('.//OPNsense/xproxy')
    if xp is None:
        return None

    def txt(parent, tag, default=''):
        el = parent.find(tag)
        return el.text if el is not None and el.text else default

    general = xp.find('general')
    if general is None:
        return None

    cfg = {
        'enabled': txt(general, 'enabled', '0'),
        'active_server': txt(general, 'active_server'),
        'socks_port': _safe_int(txt(general, 'socks_port', '10808'), 10808, 1, 65535),
        'http_port': _safe_int(txt(general, 'http_port', '10809'), 10809, 1, 65535),
        'socks_listen': txt(general, 'socks_listen', '127.0.0.1'),
        'http_listen': txt(general, 'http_listen', '127.0.0.1'),
        'tun_device': txt(general, 'tun_device', 'tun9'),
        'tun_address': txt(general, 'tun_address', '10.255.0.1'),
        'tun_gateway': txt(general, 'tun_gateway', '10.255.0.2'),
        'tun_mtu': _safe_int(txt(general, 'tun_mtu', '1500'), 1500, 576, 9000),
        'log_level': txt(general, 'log_level', 'warning'),
        'bypass_ips': txt(general, 'bypass_ips', '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8'),
        'servers': [],
    }

    servers_node = xp.find('servers')
    if servers_node is not None:
        for srv in servers_node:
            if srv.tag != 'server':
                continue
            server = {
                'uuid': srv.attrib.get('uuid', ''),
                'enabled': txt(srv, 'enabled', '0'),
                'description': txt(srv, 'description'),
                'protocol': txt(srv, 'protocol', 'vless'),
                'address': txt(srv, 'address'),
                'port': _safe_int(txt(srv, 'port', '443'), 443, 1, 65535),
                'user_id': txt(srv, 'user_id'),
                'password': txt(srv, 'password'),
                'encryption': txt(srv, 'encryption', 'none'),
                'flow': txt(srv, 'flow', '').replace('_', '-'),
                'transport': txt(srv, 'transport', 'tcp'),
                'transport_host': txt(srv, 'transport_host'),
                'transport_path': txt(srv, 'transport_path'),
                'security': txt(srv, 'security', 'none'),
                'sni': txt(srv, 'sni'),
                'fingerprint': txt(srv, 'fingerprint', 'chrome'),
                'alpn': txt(srv, 'alpn'),
                'reality_pubkey': txt(srv, 'reality_pubkey'),
                'reality_short_id': txt(srv, 'reality_short_id'),
            }
            cfg['servers'].append(server)

    return cfg


def find_active_server(cfg):
    active_uuid = cfg.get('active_server', '')
    if not active_uuid:
        return None
    for srv in cfg['servers']:
        if srv['uuid'] == active_uuid:
            return srv
    return None


def build_xray_config(cfg, server):
    """Generate xray-core JSON config for the active server."""
    socks_port = cfg['socks_port']
    http_port = cfg['http_port']
    socks_listen = (cfg.get('socks_listen') or '127.0.0.1').strip() or '127.0.0.1'
    http_listen = (cfg.get('http_listen') or '127.0.0.1').strip() or '127.0.0.1'
    log_level = cfg['log_level']
    bypass_list = [s.strip() for s in cfg['bypass_ips'].split(',') if s.strip()]

    inbounds = [
        {
            "tag": "socks-in",
            "protocol": "socks",
            "listen": socks_listen,
            "port": socks_port,
            "settings": {"udp": True}
        },
        {
            "tag": "http-in",
            "protocol": "http",
            "listen": http_listen,
            "port": http_port
        }
    ]

    outbound = build_outbound(server)
    outbounds = [
        outbound,
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"}
    ]

    routing_rules = []
    if bypass_list:
        routing_rules.append({
            "type": "field",
            "ip": bypass_list,
            "outboundTag": "direct"
        })
    addr = (server.get('address') or '').strip()
    if addr:
        try:
            ipaddress.ip_address(addr)
            routing_rules.append({
                "type": "field",
                "ip": [addr],
                "outboundTag": "direct"
            })
        except ValueError:
            routing_rules.append({
                "type": "field",
                "domain": ["full:" + addr],
                "outboundTag": "direct"
            })

    config = {
        "log": {"loglevel": log_level, "access": LOG_FILE},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": routing_rules
        }
    }
    return config


def build_outbound(srv):
    """Build protocol-specific outbound config."""
    proto = srv['protocol']
    outbound = {"tag": "proxy", "protocol": proto}

    if proto == 'vless':
        user = {"id": srv['user_id'], "encryption": srv['encryption'] or 'none'}
        if srv['flow']:
            user["flow"] = srv['flow']
        outbound["settings"] = {
            "vnext": [{"address": srv['address'], "port": srv['port'], "users": [user]}]
        }
    elif proto == 'vmess':
        outbound["settings"] = {
            "vnext": [{
                "address": srv['address'],
                "port": srv['port'],
                "users": [{"id": srv['user_id'], "alterId": 0, "security": srv['encryption'] or 'auto'}]
            }]
        }
    elif proto == 'shadowsocks':
        outbound["settings"] = {
            "servers": [{
                "address": srv['address'],
                "port": srv['port'],
                "method": srv['encryption'] or 'aes-256-gcm',
                "password": srv['password']
            }]
        }
    elif proto == 'trojan':
        outbound["settings"] = {
            "servers": [{
                "address": srv['address'],
                "port": srv['port'],
                "password": srv['password']
            }]
        }

    stream = build_stream_settings(srv)
    if stream:
        outbound["streamSettings"] = stream

    return outbound


def build_stream_settings(srv):
    """Build streamSettings for transport and security."""
    stream = {"network": srv['transport'] or 'tcp'}

    security = srv['security']
    if security == 'tls':
        tls = {}
        if srv['sni']:
            tls["serverName"] = srv['sni']
        if srv['fingerprint']:
            tls["fingerprint"] = srv['fingerprint']
        if srv['alpn']:
            tls["alpn"] = [a.strip() for a in srv['alpn'].split(',') if a.strip()]
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security == 'reality':
        reality = {
            "fingerprint": srv['fingerprint'] or 'chrome',
        }
        if srv['sni']:
            reality["serverName"] = srv['sni']
        if srv['reality_pubkey']:
            reality["publicKey"] = srv['reality_pubkey']
        if srv['reality_short_id']:
            reality["shortId"] = srv['reality_short_id']
        stream["security"] = "reality"
        stream["realitySettings"] = reality

    transport = srv['transport']
    if transport == 'ws':
        ws = {"path": srv['transport_path'] or '/'}
        if srv['transport_host']:
            ws["headers"] = {"Host": srv['transport_host']}
        stream["wsSettings"] = ws
    elif transport == 'grpc':
        stream["grpcSettings"] = {"serviceName": srv['transport_path'] or ''}
    elif transport == 'h2':
        h2 = {"path": srv['transport_path'] or '/'}
        if srv['transport_host']:
            h2["host"] = [srv['transport_host']]
        stream["httpSettings"] = h2
    elif transport == 'httpupgrade':
        hu = {"path": srv['transport_path'] or '/'}
        if srv['transport_host']:
            hu["host"] = srv['transport_host']
        stream["httpupgradeSettings"] = hu

    return stream


def write_xray_config(config):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(XRAY_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)


def read_pid(pidfile):
    try:
        with open(pidfile, 'r') as f:
            return int(f.read().strip())
    except (IOError, ValueError):
        return None


def is_running(pidfile):
    pid = read_pid(pidfile)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def kill_pid(pidfile):
    pid = read_pid(pidfile)
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(50):
            try:
                os.kill(pid, 0)
                time.sleep(0.1)
            except OSError:
                break
    except OSError:
        pass
    try:
        os.unlink(pidfile)
    except OSError:
        pass


def _go_env():
    """Environment variables to limit Go runtime memory usage."""
    env = os.environ.copy()
    env['GOGC'] = '50'
    env['GOMEMLIMIT'] = '128MiB'
    return env


def start_xray():
    if is_running(XRAY_PID):
        return
    cmd = [
        '/usr/sbin/daemon', '-c', '-f', '-p', XRAY_PID,
        XRAY_BIN, 'run', '-c', XRAY_CONFIG
    ]
    subprocess.run(cmd, env=_go_env(), check=False)
    for _ in range(10):
        time.sleep(0.5)
        if is_running(XRAY_PID):
            return
    log_error('xproxy: xray failed to start')


def start_tun2socks(cfg):
    if is_running(TUN2SOCKS_PID):
        return
    device = cfg.get('tun_device') or 'tun9'
    if not TUN_DEVICE_RE.match(device):
        return

    subprocess.run(
        ['ifconfig', device, 'destroy'],
        capture_output=True, check=False
    )

    socks_addr = '127.0.0.1:%d' % cfg['socks_port']
    cmd = [
        '/usr/sbin/daemon', '-c', '-f', '-p', TUN2SOCKS_PID,
        TUN2SOCKS_BIN,
        '-device', 'tun://' + device,
        '-proxy', 'socks5://' + socks_addr,
    ]

    for attempt in range(3):
        subprocess.run(cmd, env=_go_env(), check=False)
        for _ in range(20):
            time.sleep(0.5)
            if is_running(TUN2SOCKS_PID):
                return
        kill_pid(TUN2SOCKS_PID)
        subprocess.run(
            ['ifconfig', device, 'destroy'],
            capture_output=True, check=False
        )
        if attempt < 2:
            time.sleep(2)
    log_error('xproxy: tun2socks failed to start after retries')


def configure_tun(cfg):
    device = cfg.get('tun_device') or 'tun9'
    if not TUN_DEVICE_RE.match(device):
        return
    address = (cfg.get('tun_address') or '').strip()
    gateway = (cfg.get('tun_gateway') or '').strip()
    try:
        a = ipaddress.ip_address(address)
        g = ipaddress.ip_address(gateway)
        if a.version != 4 or g.version != 4:
            return
    except ValueError:
        return
    mtu = str(cfg['tun_mtu'])
    subprocess.run(
        ['ifconfig', device, address, gateway, 'mtu', mtu, 'up'],
        check=False
    )


def stop_services(cfg):
    kill_pid(TUN2SOCKS_PID)
    device = (cfg.get('tun_device', 'tun9') if cfg else 'tun9') or 'tun9'
    if TUN_DEVICE_RE.match(device):
        subprocess.run(['ifconfig', device, 'destroy'], capture_output=True, check=False)
    kill_pid(XRAY_PID)


def log_error(msg):
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(time.strftime('%Y/%m/%d %H:%M:%S') + ' ' + msg + '\n')
    except OSError:
        pass
    print(msg, file=sys.stderr)


def schedule_filter_reload():
    """Spawn a detached filter reload that runs after this configd action exits.

    Calling ``configctl filter reload`` directly inside a configd action
    creates a nested configd call that deadlocks during boot (configd
    waits for the action to finish while the action waits for configd to
    process the filter reload).  By spawning the process detached, it
    executes after the current action returns and configd is free.
    """
    subprocess.Popen(
        ['/usr/local/sbin/configctl', 'filter', 'reload'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )


def do_start():
    cfg = read_config()
    if cfg is None or cfg['enabled'] != '1':
        return
    server = find_active_server(cfg)
    if server is None:
        log_error('xproxy: no server matches the active selection — go to General tab and select a server')
        return
    if not (server.get('address') or '').strip():
        log_error('xproxy: active server has no address')
        return
    if server.get('protocol') not in SUPPORTED_PROTOCOLS:
        log_error('xproxy: unsupported protocol %r' % (server.get('protocol'),))
        return
    xray_config = build_xray_config(cfg, server)
    write_xray_config(xray_config)
    start_xray()
    if os.path.exists(TUN2SOCKS_BIN):
        start_tun2socks(cfg)
        configure_tun(cfg)
    schedule_filter_reload()


def do_stop():
    cfg = read_config()
    stop_services(cfg)
    schedule_filter_reload()


def truncate_log():
    try:
        open(LOG_FILE, 'w').close()
    except OSError:
        pass


def do_reconfigure():
    cfg = read_config()
    stop_services(cfg)
    truncate_log()
    if cfg and cfg['enabled'] == '1':
        do_start()
    else:
        schedule_filter_reload()


def do_status():
    xray_up = is_running(XRAY_PID)
    tun_up = is_running(TUN2SOCKS_PID)
    if xray_up and tun_up:
        print("xproxy is running")
    elif xray_up:
        print("xproxy is running (xray-core only, tun2socks not active)")
    else:
        print("xproxy is not running")


def do_healthcheck():
    """Watchdog: detect crashed xray/tun2socks and recover.

    If the service is enabled but xray is not running, it was likely
    killed externally (OOM, signal).  Restart the full stack and reload
    firewall rules so LAN traffic isn't black-holed by stale route-to
    rules pointing at a dead tunnel.
    """
    cfg = read_config()
    if cfg is None or cfg['enabled'] != '1':
        return
    if not cfg.get('active_server'):
        return

    xray_up = is_running(XRAY_PID)
    tun_up = is_running(TUN2SOCKS_PID)

    if xray_up and tun_up:
        return

    log_error('xproxy healthcheck: xray=%s tun2socks=%s — restarting'
              % ('up' if xray_up else 'DOWN', 'up' if tun_up else 'DOWN'))
    stop_services(cfg)
    do_start()


def main():
    if len(sys.argv) < 2:
        print("Usage: service_control.py <start|stop|restart|reconfigure|status|healthcheck>")
        sys.exit(1)

    action = sys.argv[1]
    if action == 'start':
        do_start()
    elif action == 'stop':
        do_stop()
    elif action == 'restart':
        do_stop()
        do_start()
    elif action == 'reconfigure':
        do_reconfigure()
    elif action == 'status':
        do_status()
    elif action == 'healthcheck':
        do_healthcheck()
    else:
        print("Unknown action: " + action)
        sys.exit(1)


if __name__ == '__main__':
    main()
