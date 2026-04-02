"""Tests for hardening features in service_control.py.

Covers process management, PID handling, locking, TUN configuration,
hev-socks5-tunnel config generation, log rotation, sysctl tuning,
Go runtime environment, and config write atomicity.
"""

import sys
import os
import json
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                '..', 'src', 'opnsense', 'scripts', 'xproxy'))

import service_control
from service_control import (
    _safe_int, read_pid, _xray_env, _write_hev_config,
    write_xray_config, build_xray_config, _rotate_log,
    find_active_server, read_config, _SYSCTL_TUNABLES,
)


def _base_cfg(**overrides):
    cfg = {
        'enabled': '1',
        'active_server': 'uuid-1',
        'socks_port': 10808,
        'http_port': 10809,
        'socks_listen': '127.0.0.1',
        'http_listen': '127.0.0.1',
        'tun_device': 'tun9',
        'tun_address': '10.255.0.1',
        'tun_gateway': '10.255.0.2',
        'log_level': 'warning',
        'bypass_ips': '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8',
        'servers': [],
    }
    cfg.update(overrides)
    return cfg


def _vless_server(**overrides):
    srv = {
        'protocol': 'vless',
        'address': 'proxy.example.com',
        'port': 443,
        'user_id': 'test-uuid',
        'encryption': 'none',
        'flow': 'xtls-rprx-vision',
        'transport': 'tcp',
        'transport_host': '',
        'transport_path': '',
        'security': 'reality',
        'sni': 'www.spotify.com',
        'fingerprint': 'chrome',
        'alpn': '',
        'reality_pubkey': 'pubkey123',
        'reality_short_id': 'shortid456',
        'password': '',
    }
    srv.update(overrides)
    return srv


# ---------------------------------------------------------------------------
# PID file handling
# ---------------------------------------------------------------------------

class TestReadPid(unittest.TestCase):

    def test_valid_pid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False) as f:
            f.write('12345\n')
            f.flush()
            pid = read_pid(f.name)
        os.unlink(f.name)
        self.assertEqual(pid, 12345)

    def test_empty_pid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False) as f:
            f.write('')
            f.flush()
            pid = read_pid(f.name)
        os.unlink(f.name)
        self.assertIsNone(pid)

    def test_invalid_pid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False) as f:
            f.write('not-a-number\n')
            f.flush()
            pid = read_pid(f.name)
        os.unlink(f.name)
        self.assertIsNone(pid)

    def test_nonexistent_pid_file(self):
        pid = read_pid('/nonexistent/path/pid')
        self.assertIsNone(pid)

    def test_zero_pid_returns_none(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False) as f:
            f.write('0\n')
            f.flush()
            pid = read_pid(f.name)
        os.unlink(f.name)
        self.assertIsNone(pid)

    def test_negative_pid_returns_none(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False) as f:
            f.write('-1\n')
            f.flush()
            pid = read_pid(f.name)
        os.unlink(f.name)
        self.assertIsNone(pid)

    def test_pid_with_whitespace(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False) as f:
            f.write('  99999  \n')
            f.flush()
            pid = read_pid(f.name)
        os.unlink(f.name)
        self.assertEqual(pid, 99999)


# ---------------------------------------------------------------------------
# Go runtime environment
# ---------------------------------------------------------------------------

class TestXrayEnv(unittest.TestCase):

    def test_gogc_set(self):
        env = _xray_env()
        self.assertEqual(env['GOGC'], '100')

    def test_gomemlimit_set(self):
        env = _xray_env()
        self.assertEqual(env['GOMEMLIMIT'], '512MiB')

    def test_inherits_existing_env(self):
        env = _xray_env()
        self.assertIn('PATH', env)

    def test_does_not_modify_os_environ(self):
        original_gogc = os.environ.get('GOGC')
        _xray_env()
        self.assertEqual(os.environ.get('GOGC'), original_gogc)


# ---------------------------------------------------------------------------
# hev-socks5-tunnel config generation
# ---------------------------------------------------------------------------

class TestWriteHevConfig(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_config_dir = service_control.CONFIG_DIR
        self._orig_hev_config = service_control.HEV_CONFIG
        self._orig_hev_pid = service_control.HEV_PID
        service_control.CONFIG_DIR = self.tmpdir
        service_control.HEV_CONFIG = os.path.join(self.tmpdir, 'hev.yml')
        service_control.HEV_PID = '/var/run/xproxy_hev.pid'

    def tearDown(self):
        service_control.CONFIG_DIR = self._orig_config_dir
        service_control.HEV_CONFIG = self._orig_hev_config
        service_control.HEV_PID = self._orig_hev_pid
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_generates_valid_yaml(self):
        cfg = _base_cfg()
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('tunnel:', content)
        self.assertIn('socks5:', content)
        self.assertIn('misc:', content)

    def test_tun_device_name(self):
        cfg = _base_cfg(tun_device='tun7')
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('name: tun7', content)

    def test_socks_port(self):
        cfg = _base_cfg(socks_port=1080)
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('port: 1080', content)

    def test_mtu_8500(self):
        cfg = _base_cfg()
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('mtu: 8500', content)

    def test_tcp_buffer_size_262144(self):
        cfg = _base_cfg()
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('tcp-buffer-size: 262144', content)

    def test_connect_timeout_5000(self):
        cfg = _base_cfg()
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('connect-timeout: 5000', content)

    def test_pid_file_path(self):
        cfg = _base_cfg()
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('pid-file: /var/run/xproxy_hev.pid', content)

    def test_ipv4_address(self):
        cfg = _base_cfg(tun_address='10.200.0.1')
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('ipv4: 10.200.0.1', content)

    def test_default_tun_device(self):
        cfg = _base_cfg(tun_device='')
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('name: tun9', content)

    def test_default_tun_address(self):
        cfg = _base_cfg(tun_address='')
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('ipv4: 10.255.0.1', content)

    def test_socks_address_is_localhost(self):
        cfg = _base_cfg()
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn('address: 127.0.0.1', content)

    def test_udp_enabled(self):
        cfg = _base_cfg()
        _write_hev_config(cfg)
        with open(service_control.HEV_CONFIG) as f:
            content = f.read()
        self.assertIn("udp: 'udp'", content)


# ---------------------------------------------------------------------------
# Atomic config writes
# ---------------------------------------------------------------------------

class TestWriteXrayConfig(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_config_dir = service_control.CONFIG_DIR
        self._orig_xray_config = service_control.XRAY_CONFIG
        service_control.CONFIG_DIR = self.tmpdir
        service_control.XRAY_CONFIG = os.path.join(self.tmpdir, 'config.json')

    def tearDown(self):
        service_control.CONFIG_DIR = self._orig_config_dir
        service_control.XRAY_CONFIG = self._orig_xray_config
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_writes_valid_json(self):
        config = {'log': {'loglevel': 'debug'}}
        write_xray_config(config)
        with open(service_control.XRAY_CONFIG) as f:
            loaded = json.load(f)
        self.assertEqual(loaded, config)

    def test_no_tmp_file_remains_on_success(self):
        config = {'test': True}
        write_xray_config(config)
        tmp_path = service_control.XRAY_CONFIG + '.tmp'
        self.assertFalse(os.path.exists(tmp_path))

    def test_overwrites_existing_config(self):
        config1 = {'version': 1}
        config2 = {'version': 2}
        write_xray_config(config1)
        write_xray_config(config2)
        with open(service_control.XRAY_CONFIG) as f:
            loaded = json.load(f)
        self.assertEqual(loaded['version'], 2)


# ---------------------------------------------------------------------------
# Log rotation
# ---------------------------------------------------------------------------

class TestLogRotation(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_log_file = service_control.LOG_FILE
        self._orig_max_bytes = service_control.LOG_MAX_BYTES
        service_control.LOG_FILE = os.path.join(self.tmpdir, 'xproxy.log')

    def tearDown(self):
        service_control.LOG_FILE = self._orig_log_file
        service_control.LOG_MAX_BYTES = self._orig_max_bytes
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_no_rotation_when_small(self):
        service_control.LOG_MAX_BYTES = 1000
        with open(service_control.LOG_FILE, 'w') as f:
            f.write('small log\n')
        _rotate_log()
        self.assertTrue(os.path.exists(service_control.LOG_FILE))
        self.assertFalse(os.path.exists(service_control.LOG_FILE + '.1'))

    def test_rotates_when_exceeds_max(self):
        service_control.LOG_MAX_BYTES = 100
        with open(service_control.LOG_FILE, 'w') as f:
            f.write('x' * 200)
        _rotate_log()
        self.assertFalse(os.path.exists(service_control.LOG_FILE))
        self.assertTrue(os.path.exists(service_control.LOG_FILE + '.1'))

    def test_rotation_overwrites_old_rotated(self):
        service_control.LOG_MAX_BYTES = 100
        rotated = service_control.LOG_FILE + '.1'
        with open(rotated, 'w') as f:
            f.write('old rotated content')
        with open(service_control.LOG_FILE, 'w') as f:
            f.write('x' * 200)
        _rotate_log()
        with open(rotated) as f:
            content = f.read()
        self.assertEqual(content, 'x' * 200)

    def test_no_error_when_log_missing(self):
        service_control.LOG_MAX_BYTES = 100
        _rotate_log()  # should not raise


# ---------------------------------------------------------------------------
# Config reading edge cases
# ---------------------------------------------------------------------------

class TestReadConfigEdgeCases(unittest.TestCase):

    def _write_config(self, content):
        fd, path = tempfile.mkstemp(suffix='.xml')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(content)
        return path

    def test_missing_general_returns_none(self):
        xml = """<?xml version="1.0"?>
        <opnsense><OPNsense><xproxy>
            <servers></servers>
        </xproxy></OPNsense></opnsense>"""
        original = service_control.CONFIG_XML
        path = self._write_config(xml)
        try:
            service_control.CONFIG_XML = path
            self.assertIsNone(read_config())
        finally:
            service_control.CONFIG_XML = original
            os.unlink(path)

    def test_empty_server_fields_use_defaults(self):
        xml = """<?xml version="1.0"?>
        <opnsense><OPNsense><xproxy>
            <general>
                <enabled>1</enabled>
                <active_server>u1</active_server>
                <socks_port></socks_port>
                <http_port></http_port>
                <socks_listen></socks_listen>
                <http_listen></http_listen>
                <tun_device></tun_device>
                <tun_address></tun_address>
                <tun_gateway></tun_gateway>
                <log_level></log_level>
                <bypass_ips></bypass_ips>
            </general>
            <servers>
                <server uuid="u1">
                    <enabled>1</enabled>
                    <protocol></protocol>
                    <address></address>
                    <port></port>
                    <user_id></user_id>
                    <password></password>
                    <encryption></encryption>
                    <flow></flow>
                    <transport></transport>
                    <transport_host></transport_host>
                    <transport_path></transport_path>
                    <security></security>
                    <sni></sni>
                    <fingerprint></fingerprint>
                    <alpn></alpn>
                    <reality_pubkey></reality_pubkey>
                    <reality_short_id></reality_short_id>
                </server>
            </servers>
        </xproxy></OPNsense></opnsense>"""
        original = service_control.CONFIG_XML
        path = self._write_config(xml)
        try:
            service_control.CONFIG_XML = path
            cfg = read_config()
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg['socks_port'], 10808)
            self.assertEqual(cfg['http_port'], 10809)
            self.assertEqual(cfg['tun_device'], 'tun9')
            srv = cfg['servers'][0]
            self.assertEqual(srv['protocol'], 'vless')
            self.assertEqual(srv['port'], 443)
            self.assertEqual(srv['fingerprint'], 'chrome')
        finally:
            service_control.CONFIG_XML = original
            os.unlink(path)

    def test_invalid_port_uses_default(self):
        xml = """<?xml version="1.0"?>
        <opnsense><OPNsense><xproxy>
            <general>
                <enabled>1</enabled>
                <active_server>u1</active_server>
                <socks_port>99999</socks_port>
                <http_port>-5</http_port>
            </general>
        </xproxy></OPNsense></opnsense>"""
        original = service_control.CONFIG_XML
        path = self._write_config(xml)
        try:
            service_control.CONFIG_XML = path
            cfg = read_config()
            self.assertEqual(cfg['socks_port'], 10808)
            self.assertEqual(cfg['http_port'], 10809)
        finally:
            service_control.CONFIG_XML = original
            os.unlink(path)

    def test_non_server_children_ignored(self):
        xml = """<?xml version="1.0"?>
        <opnsense><OPNsense><xproxy>
            <general><enabled>0</enabled></general>
            <servers>
                <notaserver><protocol>vless</protocol></notaserver>
                <server uuid="u1">
                    <enabled>1</enabled>
                    <protocol>vless</protocol>
                    <address>host</address>
                </server>
            </servers>
        </xproxy></OPNsense></opnsense>"""
        original = service_control.CONFIG_XML
        path = self._write_config(xml)
        try:
            service_control.CONFIG_XML = path
            cfg = read_config()
            self.assertEqual(len(cfg['servers']), 1)
        finally:
            service_control.CONFIG_XML = original
            os.unlink(path)


# ---------------------------------------------------------------------------
# find_active_server edge cases
# ---------------------------------------------------------------------------

class TestFindActiveServerEdgeCases(unittest.TestCase):

    def test_no_servers_list(self):
        cfg = {'active_server': 'uuid-1', 'servers': []}
        self.assertIsNone(find_active_server(cfg))

    def test_none_active_server(self):
        cfg = {'active_server': None, 'servers': [{'uuid': 'a'}]}
        self.assertIsNone(find_active_server(cfg))

    def test_multiple_servers_returns_correct(self):
        cfg = {
            'active_server': 'uuid-3',
            'servers': [
                {'uuid': 'uuid-1', 'name': 'first'},
                {'uuid': 'uuid-2', 'name': 'second'},
                {'uuid': 'uuid-3', 'name': 'third'},
            ],
        }
        srv = find_active_server(cfg)
        self.assertEqual(srv['name'], 'third')


# ---------------------------------------------------------------------------
# TUN device name validation
# ---------------------------------------------------------------------------

class TestTunDeviceValidation(unittest.TestCase):

    def test_valid_tun_devices(self):
        for name in ('tun0', 'tun9', 'tun99', 'tun123'):
            with self.subTest(name=name):
                self.assertTrue(service_control.TUN_DEVICE_RE.match(name))

    def test_invalid_tun_devices(self):
        for name in ('', 'eth0', 'tun', 'tun1234', 'TUN0', 'tun-1', '../tun0', 'tun0; rm -rf /'):
            with self.subTest(name=name):
                self.assertIsNone(service_control.TUN_DEVICE_RE.match(name))


# ---------------------------------------------------------------------------
# sysctl tunable constants
# ---------------------------------------------------------------------------

class TestSysctlTunables(unittest.TestCase):

    def test_all_tunables_defined(self):
        required = [
            'kern.ipc.maxsockbuf',
            'net.inet.tcp.recvbuf_max',
            'net.inet.tcp.sendbuf_max',
            'net.inet.tcp.recvspace',
            'net.inet.tcp.sendspace',
            'net.inet.tcp.fast_finwait2_recycle',
            'net.inet.tcp.finwait2_timeout',
        ]
        for key in required:
            with self.subTest(tunable=key):
                self.assertIn(key, _SYSCTL_TUNABLES)

    def test_tunables_are_numeric_strings(self):
        for key, val in _SYSCTL_TUNABLES.items():
            with self.subTest(tunable=key):
                int(val)  # should not raise

    def test_buffer_sizes_reasonable(self):
        maxsock = int(_SYSCTL_TUNABLES['kern.ipc.maxsockbuf'])
        recvmax = int(_SYSCTL_TUNABLES['net.inet.tcp.recvbuf_max'])
        sendmax = int(_SYSCTL_TUNABLES['net.inet.tcp.sendbuf_max'])
        self.assertGreaterEqual(maxsock, recvmax)
        self.assertGreaterEqual(maxsock, sendmax)
        self.assertGreater(recvmax, 1024 * 1024)  # > 1 MB
        self.assertGreater(sendmax, 1024 * 1024)


# ---------------------------------------------------------------------------
# Constants and paths
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):

    def test_hev_pid_uses_new_name(self):
        self.assertEqual(service_control.HEV_PID, '/var/run/xproxy_hev.pid')

    def test_lock_file_exists(self):
        self.assertEqual(service_control.LOCK_FILE, '/var/run/xproxy.lock')

    def test_log_max_bytes(self):
        self.assertEqual(service_control.LOG_MAX_BYTES, 2 * 1024 * 1024)

    def test_supported_protocols(self):
        expected = ('vless', 'vmess', 'shadowsocks', 'trojan')
        self.assertEqual(service_control.SUPPORTED_PROTOCOLS, expected)


# ---------------------------------------------------------------------------
# Process management (mocked)
# ---------------------------------------------------------------------------

class TestPidRunning(unittest.TestCase):

    def test_pid_running_with_current_pid(self):
        self.assertTrue(service_control._pid_running(os.getpid()))

    def test_pid_running_with_nonexistent_pid(self):
        self.assertFalse(service_control._pid_running(999999999))


class TestKillPid(unittest.TestCase):

    def test_nonexistent_pid_file(self):
        service_control.kill_pid('/nonexistent/pid/file')

    def test_empty_pid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False) as f:
            f.write('')
        try:
            service_control.kill_pid(f.name)
        finally:
            try:
                os.unlink(f.name)
            except OSError:
                pass

    def test_stale_pid_cleans_up(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False) as f:
            f.write('999999999\n')
        try:
            service_control.kill_pid(f.name)
            self.assertFalse(os.path.exists(f.name))
        finally:
            try:
                os.unlink(f.name)
            except OSError:
                pass


class TestIsRunning(unittest.TestCase):

    def test_missing_pid_file(self):
        self.assertFalse(service_control.is_running('/nonexistent/pid/file'))

    def test_stale_pid_returns_false_and_cleans(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pid', delete=False) as f:
            f.write('999999999\n')
        try:
            result = service_control.is_running(f.name)
            self.assertFalse(result)
            self.assertFalse(os.path.exists(f.name))
        finally:
            try:
                os.unlink(f.name)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Config generation with all hardening features
# ---------------------------------------------------------------------------

class TestHardenedConfigGeneration(unittest.TestCase):

    def _full_config(self, **srv_overrides):
        cfg = _base_cfg()
        srv = _vless_server(**srv_overrides)
        return build_xray_config(cfg, srv)

    def test_config_has_all_required_sections(self):
        config = self._full_config()
        for section in ('log', 'dns', 'policy', 'inbounds', 'outbounds', 'routing'):
            with self.subTest(section=section):
                self.assertIn(section, config)

    def test_config_is_json_serializable(self):
        config = self._full_config()
        serialized = json.dumps(config)
        reparsed = json.loads(serialized)
        self.assertEqual(reparsed, config)

    def test_all_protocols_produce_valid_config(self):
        protocols = [
            {'protocol': 'vless'},
            {'protocol': 'vmess', 'flow': '', 'encryption': 'auto'},
            {'protocol': 'shadowsocks', 'encryption': 'aes-256-gcm', 'password': 'p'},
            {'protocol': 'trojan', 'password': 'p'},
        ]
        for kw in protocols:
            with self.subTest(protocol=kw['protocol']):
                config = self._full_config(**kw)
                serialized = json.dumps(config)
                self.assertGreater(len(serialized), 100)

    def test_no_duplicate_routing_rules_for_server(self):
        config = self._full_config(address='proxy.example.com')
        domain_rules = [
            r for r in config['routing']['rules']
            if 'domain' in r and 'full:proxy.example.com' in r['domain']
        ]
        self.assertEqual(len(domain_rules), 1)

    def test_no_duplicate_dns_pins_for_server(self):
        config = self._full_config(address='proxy.example.com')
        pinned_domains = []
        for entry in config['dns']['servers']:
            if isinstance(entry, dict):
                pinned_domains.extend(entry.get('domains', []))
        count = pinned_domains.count('full:proxy.example.com')
        self.assertEqual(count, 1)


# ---------------------------------------------------------------------------
# Locking (unit-level — just tests the API without contention)
# ---------------------------------------------------------------------------

class TestLocking(unittest.TestCase):

    def setUp(self):
        fd, self.lock_path = tempfile.mkstemp(suffix='.lock')
        os.close(fd)
        self._orig_lock = service_control.LOCK_FILE
        service_control.LOCK_FILE = self.lock_path

    def tearDown(self):
        service_control.LOCK_FILE = self._orig_lock
        service_control._release_lock()
        try:
            os.unlink(self.lock_path)
        except OSError:
            pass

    def test_acquire_and_release(self):
        service_control._acquire_lock()
        self.assertIsNotNone(service_control._lock_fd)
        service_control._release_lock()
        self.assertIsNone(service_control._lock_fd)

    def test_double_release_safe(self):
        service_control._acquire_lock()
        service_control._release_lock()
        service_control._release_lock()  # should not raise


if __name__ == '__main__':
    unittest.main()
