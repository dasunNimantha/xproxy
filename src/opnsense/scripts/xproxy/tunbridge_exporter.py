#!/usr/local/bin/python3

"""
Prometheus exporter for xproxy process and system metrics.
Exposes xray-core and hev-socks5-tunnel health, RSS, CPU, uptime,
system memory, and tunnel interface traffic on port 9101.

Reads PIDs from pidfiles to track the correct child processes
rather than daemon wrappers.
"""

import http.server
import os
import re
import subprocess
import time

LISTEN_PORT = 9101
SCRAPE_INTERVAL = 0  # computed on each /metrics request

XRAY_PID_FILE = '/var/run/xproxy_xray.pid'
HEV_PID_FILE = '/var/run/xproxy_hev.pid'
TUN_DEVICE = 'tun9'

_proc_start_times = {}


def _read_pid(pidfile):
    try:
        with open(pidfile) as f:
            pid = int(f.read().strip())
            return pid if pid > 0 else None
    except (IOError, ValueError):
        return None


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _get_child_pid(parent_pid):
    """If the PID is a daemon wrapper, return the actual child PID."""
    try:
        r = subprocess.run(
            ['ps', '-p', str(parent_pid), '-o', 'comm'],
            capture_output=True, timeout=5, check=False,
        )
        lines = r.stdout.decode('utf-8', errors='replace').strip().splitlines()
        comm = lines[-1].strip() if lines else ''
        if 'daemon' in comm.lower():
            r2 = subprocess.run(
                ['pgrep', '-P', str(parent_pid)],
                capture_output=True, timeout=5, check=False,
            )
            child = r2.stdout.decode('utf-8', errors='replace').strip().splitlines()
            if child and child[0].strip().isdigit():
                return int(child[0].strip())
    except (subprocess.TimeoutExpired, OSError):
        pass
    return parent_pid


def _parse_etime(raw):
    """Parse FreeBSD etime format (DD-HH:MM:SS, HH:MM:SS, or MM:SS) to seconds."""
    raw = raw.strip()
    days = 0
    if '-' in raw:
        d, raw = raw.split('-', 1)
        days = int(d)
    parts = raw.split(':')
    if len(parts) == 3:
        return days * 86400 + int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
    elif len(parts) == 2:
        return days * 86400 + int(parts[0]) * 60 + int(parts[1])
    return 0


def _ps_stats(pid):
    """Get RSS (bytes), VSZ (bytes), %CPU, and elapsed seconds for a PID."""
    if pid is None:
        return None
    try:
        r = subprocess.run(
            ['ps', '-p', str(pid), '-o', 'rss,vsz,pcpu,etime'],
            capture_output=True, timeout=5, check=False,
        )
        if r.returncode != 0:
            return None
        lines = r.stdout.decode('utf-8', errors='replace').strip().splitlines()
        if len(lines) < 2:
            return None
        parts = lines[1].split()
        if len(parts) < 4:
            return None
        return {
            'rss': int(parts[0]) * 1024,
            'vsz': int(parts[1]) * 1024,
            'cpu_pct': float(parts[2]),
            'uptime': _parse_etime(parts[3]),
        }
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None


def _cpu_seconds(pid):
    """Read cumulative CPU time in seconds from ps."""
    if pid is None:
        return 0.0
    try:
        r = subprocess.run(
            ['ps', '-p', str(pid), '-o', 'time'],
            capture_output=True, timeout=5, check=False,
        )
        if r.returncode != 0:
            return 0.0
        lines = r.stdout.decode('utf-8', errors='replace').strip().splitlines()
        if len(lines) < 2:
            return 0.0
        raw = lines[-1].strip()
        parts = raw.split(':')
        if len(parts) == 3:
            h, m, s = parts
            return int(h) * 3600 + int(m) * 60 + float(s)
        elif len(parts) == 2:
            m, s = parts
            return int(m) * 60 + float(s)
        return float(raw)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return 0.0


def _sysctl_val(name):
    try:
        r = subprocess.run(
            ['sysctl', '-n', name],
            capture_output=True, timeout=5, check=False,
        )
        return int(r.stdout.decode().strip())
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return 0


def _system_memory():
    page_size = _sysctl_val('hw.pagesize') or 4096
    total = _sysctl_val('hw.physmem')
    free_pages = _sysctl_val('vm.stats.vm.v_free_count')
    inactive_pages = _sysctl_val('vm.stats.vm.v_inactive_count')
    wired_pages = _sysctl_val('vm.stats.vm.v_wire_count')
    active_pages = _sysctl_val('vm.stats.vm.v_active_count')
    free_bytes = free_pages * page_size
    inactive_bytes = inactive_pages * page_size
    available_bytes = free_bytes + inactive_bytes
    return {
        'total': total,
        'free': free_bytes,
        'available': available_bytes,
        'inactive': inactive_bytes,
        'wired': wired_pages * page_size,
        'active': active_pages * page_size,
    }


def _tunnel_traffic(device):
    """Read bytes/packets from netstat for the TUN device."""
    result = {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0}
    try:
        r = subprocess.run(
            ['netstat', '-I', device, '-b', '-n'],
            capture_output=True, timeout=5, check=False,
        )
        if r.returncode != 0:
            return result
        for line in r.stdout.decode('utf-8', errors='replace').splitlines()[1:]:
            parts = line.split()
            if len(parts) < 12 or not parts[2].startswith('<Link'):
                continue
            result['rx_packets'] = int(parts[4])
            result['rx_bytes'] = int(parts[7])
            result['tx_packets'] = int(parts[8])
            result['tx_bytes'] = int(parts[10])
            break
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    return result


def _process_metrics(name, pidfile):
    pid = _read_pid(pidfile)
    if pid and _pid_alive(pid):
        real_pid = _get_child_pid(pid)
        stats = _ps_stats(real_pid)
        if stats:
            cpu_s = _cpu_seconds(real_pid)
            return {
                'up': 1,
                'rss': stats['rss'],
                'vsz': stats['vsz'],
                'cpu_pct': stats['cpu_pct'],
                'cpu_s': cpu_s,
                'uptime': stats['uptime'],
            }
    return {'up': 0, 'rss': 0, 'vsz': 0, 'cpu_pct': 0, 'cpu_s': 0, 'uptime': 0}


def generate_metrics():
    xray = _process_metrics('xray', XRAY_PID_FILE)
    tunnel = _process_metrics('tunnel', HEV_PID_FILE)
    mem = _system_memory()
    traffic = _tunnel_traffic(TUN_DEVICE)

    lines = [
        '# HELP tunbridge_up Whether the process is running (1=up, 0=down)',
        '# TYPE tunbridge_up gauge',
        '# HELP tunbridge_rss_bytes Resident set size in bytes',
        '# TYPE tunbridge_rss_bytes gauge',
        '# HELP tunbridge_vsz_bytes Virtual memory size in bytes',
        '# TYPE tunbridge_vsz_bytes gauge',
        '# HELP tunbridge_cpu_percent Snapshot CPU usage percent',
        '# TYPE tunbridge_cpu_percent gauge',
        '# HELP tunbridge_cpu_seconds_total Cumulative CPU time in seconds',
        '# TYPE tunbridge_cpu_seconds_total counter',
        '# HELP tunbridge_uptime_seconds Process uptime in seconds',
        '# TYPE tunbridge_uptime_seconds gauge',
    ]
    for label, m in [('xray', xray), ('tunnel', tunnel)]:
        lines.append('tunbridge_up{process="%s"} %d' % (label, m['up']))
        lines.append('tunbridge_rss_bytes{process="%s"} %d' % (label, m['rss']))
        lines.append('tunbridge_vsz_bytes{process="%s"} %d' % (label, m['vsz']))
        lines.append('tunbridge_cpu_percent{process="%s"} %.1f' % (label, m['cpu_pct']))
        lines.append('tunbridge_cpu_seconds_total{process="%s"} %.2f' % (label, m['cpu_s']))
        lines.append('tunbridge_uptime_seconds{process="%s"} %d' % (label, m['uptime']))

    lines += [
        '# HELP tunbridge_system_memory_total_bytes Total system memory',
        '# TYPE tunbridge_system_memory_total_bytes gauge',
        '# HELP tunbridge_system_memory_free_bytes Free memory',
        '# TYPE tunbridge_system_memory_free_bytes gauge',
        '# HELP tunbridge_system_memory_available_bytes Free + inactive memory',
        '# TYPE tunbridge_system_memory_available_bytes gauge',
        '# HELP tunbridge_system_memory_inactive_bytes Inactive/cached pages',
        '# TYPE tunbridge_system_memory_inactive_bytes gauge',
        '# HELP tunbridge_system_memory_wired_bytes Wired (non-pageable) memory',
        '# TYPE tunbridge_system_memory_wired_bytes gauge',
        '# HELP tunbridge_system_memory_active_bytes Active memory',
        '# TYPE tunbridge_system_memory_active_bytes gauge',
        'tunbridge_system_memory_total_bytes %d' % mem['total'],
        'tunbridge_system_memory_free_bytes %d' % mem['free'],
        'tunbridge_system_memory_available_bytes %d' % mem['available'],
        'tunbridge_system_memory_inactive_bytes %d' % mem['inactive'],
        'tunbridge_system_memory_wired_bytes %d' % mem['wired'],
        'tunbridge_system_memory_active_bytes %d' % mem['active'],
        '# HELP tunbridge_tunnel_bytes_total Bytes through tunnel interface',
        '# TYPE tunbridge_tunnel_bytes_total counter',
        '# HELP tunbridge_tunnel_packets_total Packets through tunnel interface',
        '# TYPE tunbridge_tunnel_packets_total counter',
        'tunbridge_tunnel_bytes_total{direction="rx"} %d' % traffic['rx_bytes'],
        'tunbridge_tunnel_bytes_total{direction="tx"} %d' % traffic['tx_bytes'],
        'tunbridge_tunnel_packets_total{direction="rx"} %d' % traffic['rx_packets'],
        'tunbridge_tunnel_packets_total{direction="tx"} %d' % traffic['tx_packets'],
    ]
    return '\n'.join(lines) + '\n'


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            body = generate_metrics().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', LISTEN_PORT), MetricsHandler)
    server.serve_forever()
