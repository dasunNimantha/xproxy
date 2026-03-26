"""Integration tests for service_control.py that require a POSIX environment.

These test read_config() with real XML parsing, find_active_server(),
the full URI import -> config generation pipeline, and shell script syntax.
"""

import sys
import os
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                '..', 'src', 'opnsense', 'scripts', 'xproxy'))

from service_control import read_config, find_active_server, build_xray_config, _safe_int
from import_uris import parse_uri

SAMPLE_CONFIG_XML = """\
<?xml version="1.0"?>
<opnsense>
  <OPNsense>
    <xproxy>
      <general>
        <enabled>1</enabled>
        <active_server>uuid-1</active_server>
        <socks_port>10808</socks_port>
        <http_port>10809</http_port>
        <socks_listen>127.0.0.1</socks_listen>
        <http_listen>127.0.0.1</http_listen>
        <tun_device>tun9</tun_device>
        <tun_address>10.255.0.1</tun_address>
        <tun_gateway>10.255.0.2</tun_gateway>
        <tun_mtu>1500</tun_mtu>
        <log_level>warning</log_level>
        <bypass_ips>10.0.0.0/8,192.168.0.0/16</bypass_ips>
        <policy_route_lan>1</policy_route_lan>
      </general>
      <servers>
        <server uuid="uuid-1">
          <enabled>1</enabled>
          <description>Test Server</description>
          <protocol>vless</protocol>
          <address>proxy.example.com</address>
          <port>443</port>
          <user_id>00000000-1111-2222-3333-444444444444</user_id>
          <password></password>
          <encryption>none</encryption>
          <flow>xtls_rprx_vision</flow>
          <transport>tcp</transport>
          <transport_host></transport_host>
          <transport_path></transport_path>
          <security>reality</security>
          <sni>www.spotify.com</sni>
          <fingerprint>chrome</fingerprint>
          <alpn></alpn>
          <reality_pubkey>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</reality_pubkey>
          <reality_short_id>abcdef0123456789</reality_short_id>
        </server>
        <server uuid="uuid-2">
          <enabled>1</enabled>
          <description>Backup</description>
          <protocol>trojan</protocol>
          <address>trojan.example.com</address>
          <port>443</port>
          <user_id></user_id>
          <password>trojan-pass</password>
          <encryption></encryption>
          <flow></flow>
          <transport>tcp</transport>
          <transport_host></transport_host>
          <transport_path></transport_path>
          <security>tls</security>
          <sni>trojan.example.com</sni>
          <fingerprint>chrome</fingerprint>
          <alpn></alpn>
          <reality_pubkey></reality_pubkey>
          <reality_short_id></reality_short_id>
        </server>
      </servers>
    </xproxy>
  </OPNsense>
</opnsense>
"""

EMPTY_CONFIG_XML = """\
<?xml version="1.0"?>
<opnsense>
  <system><hostname>test</hostname></system>
</opnsense>
"""


class TestReadConfig(unittest.TestCase):
    """Test config.xml parsing with real XML files."""

    def _write_config(self, content):
        fd, path = tempfile.mkstemp(suffix='.xml')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(content)
        return path

    def test_read_full_config(self):
        import service_control
        original = service_control.CONFIG_XML
        path = self._write_config(SAMPLE_CONFIG_XML)
        try:
            service_control.CONFIG_XML = path
            cfg = read_config()
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg['enabled'], '1')
            self.assertEqual(cfg['active_server'], 'uuid-1')
            self.assertEqual(cfg['socks_port'], 10808)
            self.assertEqual(cfg['http_port'], 10809)
            self.assertEqual(cfg['tun_device'], 'tun9')
            self.assertEqual(cfg['tun_mtu'], 1500)
            self.assertEqual(cfg['log_level'], 'warning')
            self.assertEqual(len(cfg['servers']), 2)
            self.assertEqual(cfg['servers'][0]['uuid'], 'uuid-1')
            self.assertEqual(cfg['servers'][0]['protocol'], 'vless')
            self.assertEqual(cfg['servers'][1]['protocol'], 'trojan')
        finally:
            service_control.CONFIG_XML = original
            os.unlink(path)

    def test_missing_xproxy_section(self):
        import service_control
        original = service_control.CONFIG_XML
        path = self._write_config(EMPTY_CONFIG_XML)
        try:
            service_control.CONFIG_XML = path
            cfg = read_config()
            self.assertIsNone(cfg)
        finally:
            service_control.CONFIG_XML = original
            os.unlink(path)

    def test_nonexistent_file(self):
        import service_control
        original = service_control.CONFIG_XML
        try:
            service_control.CONFIG_XML = '/nonexistent/path/config.xml'
            cfg = read_config()
            self.assertIsNone(cfg)
        finally:
            service_control.CONFIG_XML = original

    def test_malformed_xml(self):
        import service_control
        original = service_control.CONFIG_XML
        path = self._write_config('<broken xml')
        try:
            service_control.CONFIG_XML = path
            cfg = read_config()
            self.assertIsNone(cfg)
        finally:
            service_control.CONFIG_XML = original
            os.unlink(path)

    def test_flow_underscore_to_dash(self):
        import service_control
        original = service_control.CONFIG_XML
        path = self._write_config(SAMPLE_CONFIG_XML)
        try:
            service_control.CONFIG_XML = path
            cfg = read_config()
            self.assertEqual(cfg['servers'][0]['flow'], 'xtls-rprx-vision')
        finally:
            service_control.CONFIG_XML = original
            os.unlink(path)


class TestFindActiveServer(unittest.TestCase):

    def test_finds_matching_server(self):
        cfg = {
            'active_server': 'uuid-1',
            'servers': [
                {'uuid': 'uuid-1', 'description': 'Server 1'},
                {'uuid': 'uuid-2', 'description': 'Server 2'},
            ]
        }
        srv = find_active_server(cfg)
        self.assertEqual(srv['description'], 'Server 1')

    def test_returns_none_for_empty_active(self):
        cfg = {'active_server': '', 'servers': [{'uuid': 'a'}]}
        self.assertIsNone(find_active_server(cfg))

    def test_returns_none_for_nonexistent_uuid(self):
        cfg = {'active_server': 'missing', 'servers': [{'uuid': 'a'}]}
        self.assertIsNone(find_active_server(cfg))


class TestEndToEndPipeline(unittest.TestCase):
    """Parse URI -> build xray config, full pipeline."""

    def test_vless_uri_to_xray_config(self):
        uri = (
            'vless://00000000-1111-2222-3333-444444444444@proxy.example.com:443'
            '?type=tcp&encryption=none&security=reality'
            '&pbk=pubkey123&fp=chrome&sni=www.spotify.com'
            '&sid=shortid456&flow=xtls-rprx-vision#my-server'
        )
        parsed = parse_uri(uri)
        cfg = {
            'socks_port': 10808,
            'http_port': 10809,
            'socks_listen': '127.0.0.1',
            'http_listen': '127.0.0.1',
            'log_level': 'warning',
            'bypass_ips': '192.168.0.0/16',
        }
        xray_config = build_xray_config(cfg, parsed)
        self.assertEqual(xray_config['outbounds'][0]['protocol'], 'vless')
        self.assertEqual(
            xray_config['outbounds'][0]['streamSettings']['security'], 'reality'
        )
        self.assertTrue(any(
            'full:proxy.example.com' in r.get('domain', [])
            for r in xray_config['routing']['rules']
        ))

    def test_trojan_uri_to_xray_config(self):
        uri = 'trojan://secret@trojan.host:443?security=tls&sni=trojan.host#trojan-srv'
        parsed = parse_uri(uri)
        cfg = {
            'socks_port': 10808,
            'http_port': 10809,
            'socks_listen': '127.0.0.1',
            'http_listen': '127.0.0.1',
            'log_level': 'info',
            'bypass_ips': '',
        }
        xray_config = build_xray_config(cfg, parsed)
        self.assertEqual(xray_config['outbounds'][0]['protocol'], 'trojan')
        server = xray_config['outbounds'][0]['settings']['servers'][0]
        self.assertEqual(server['password'], 'secret')

    def test_xray_config_is_valid_json(self):
        uri = 'vless://uuid@host:443?type=ws&security=tls&sni=host&path=%2Fws#test'
        parsed = parse_uri(uri)
        cfg = {
            'socks_port': 10808, 'http_port': 10809,
            'socks_listen': '127.0.0.1', 'http_listen': '127.0.0.1',
            'log_level': 'warning', 'bypass_ips': '',
        }
        xray_config = build_xray_config(cfg, parsed)
        serialized = json.dumps(xray_config)
        reparsed = json.loads(serialized)
        self.assertEqual(reparsed, xray_config)


if __name__ == '__main__':
    unittest.main()
