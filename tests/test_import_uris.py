"""Tests for import_uris.py — proxy URI parsing."""

import sys
import os
import json
import base64
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                '..', 'src', 'opnsense', 'scripts', 'xproxy'))

from import_uris import parse_vless, parse_vmess, parse_shadowsocks, parse_trojan, parse_uri


class TestParseVless(unittest.TestCase):

    def test_basic_reality(self):
        uri = (
            'vless://00000000-1111-2222-3333-444444444444@example.com:443'
            '?type=tcp&encryption=none&security=reality'
            '&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            '&fp=chrome&sni=www.spotify.com&sid=abcdef0123456789'
            '&flow=xtls-rprx-vision#my-server'
        )
        r = parse_vless(uri)
        self.assertEqual(r['protocol'], 'vless')
        self.assertEqual(r['address'], 'example.com')
        self.assertEqual(r['port'], '443')
        self.assertEqual(r['user_id'], '00000000-1111-2222-3333-444444444444')
        self.assertEqual(r['encryption'], 'none')
        self.assertEqual(r['security'], 'reality')
        self.assertEqual(r['transport'], 'tcp')
        self.assertEqual(r['sni'], 'www.spotify.com')
        self.assertEqual(r['fingerprint'], 'chrome')
        self.assertEqual(r['reality_pubkey'], 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        self.assertEqual(r['reality_short_id'], 'abcdef0123456789')
        self.assertEqual(r['flow'], 'xtls_rprx_vision')
        self.assertEqual(r['description'], 'my-server')

    def test_websocket_tls(self):
        uri = (
            'vless://uuid-123@ws.example.com:8443'
            '?type=ws&security=tls&sni=ws.example.com'
            '&path=%2Fws-path&host=ws.example.com#ws-server'
        )
        r = parse_vless(uri)
        self.assertEqual(r['transport'], 'ws')
        self.assertEqual(r['security'], 'tls')
        self.assertEqual(r['transport_path'], '/ws-path')
        self.assertEqual(r['transport_host'], 'ws.example.com')
        self.assertEqual(r['description'], 'ws-server')

    def test_no_fragment_uses_host(self):
        uri = 'vless://uuid@bare.host.com:443?type=tcp&security=none'
        r = parse_vless(uri)
        self.assertEqual(r['description'], 'bare.host.com')

    def test_default_port(self):
        uri = 'vless://uuid@noport.com?type=tcp&security=none'
        r = parse_vless(uri)
        self.assertEqual(r['port'], '443')

    def test_no_flow(self):
        uri = 'vless://uuid@host.com:443?type=tcp&security=none'
        r = parse_vless(uri)
        self.assertEqual(r['flow'], '')

    def test_grpc_transport(self):
        uri = 'vless://uuid@grpc.host:443?type=grpc&security=tls&serviceName=mygrpc#grpc-srv'
        r = parse_vless(uri)
        self.assertEqual(r['transport'], 'grpc')

    def test_missing_at_raises(self):
        with self.assertRaises(ValueError):
            parse_vless('vless://no-at-sign')

    def test_url_encoded_fragment(self):
        uri = 'vless://uuid@host.com:443?type=tcp&security=none#my%20server%20name'
        r = parse_vless(uri)
        self.assertEqual(r['description'], 'my server name')


class TestParseVmess(unittest.TestCase):

    def _make_uri(self, cfg_dict):
        payload = base64.b64encode(json.dumps(cfg_dict).encode()).decode()
        return 'vmess://' + payload

    def test_basic_vmess(self):
        cfg = {
            'v': '2', 'ps': 'test-vmess', 'add': 'vmess.host.com',
            'port': 443, 'id': 'test-uuid', 'aid': 0,
            'scy': 'auto', 'net': 'tcp', 'tls': 'tls',
            'sni': 'vmess.host.com',
        }
        r = parse_vmess(self._make_uri(cfg))
        self.assertEqual(r['protocol'], 'vmess')
        self.assertEqual(r['address'], 'vmess.host.com')
        self.assertEqual(r['port'], '443')
        self.assertEqual(r['user_id'], 'test-uuid')
        self.assertEqual(r['encryption'], 'auto')
        self.assertEqual(r['security'], 'tls')
        self.assertEqual(r['description'], 'test-vmess')

    def test_websocket_vmess(self):
        cfg = {
            'v': '2', 'ps': 'ws-vmess', 'add': 'ws.host.com',
            'port': 8080, 'id': 'uuid', 'net': 'ws',
            'path': '/vmess-ws', 'host': 'cdn.example.com',
            'tls': '', 'sni': '',
        }
        r = parse_vmess(self._make_uri(cfg))
        self.assertEqual(r['transport'], 'ws')
        self.assertEqual(r['transport_path'], '/vmess-ws')
        self.assertEqual(r['transport_host'], 'cdn.example.com')
        self.assertEqual(r['security'], 'none')

    def test_no_description_uses_address(self):
        cfg = {'v': '2', 'add': 'fallback.host', 'port': 443, 'id': 'u', 'net': 'tcp'}
        r = parse_vmess(self._make_uri(cfg))
        self.assertEqual(r['description'], 'fallback.host')

    def test_invalid_base64_raises(self):
        with self.assertRaises(ValueError):
            parse_vmess('vmess://not-valid-base64!!!')

    def test_flow_always_empty(self):
        cfg = {'v': '2', 'add': 'h', 'port': 1, 'id': 'u', 'net': 'tcp'}
        r = parse_vmess(self._make_uri(cfg))
        self.assertEqual(r['flow'], '')


class TestParseShadowsocks(unittest.TestCase):

    def test_userinfo_at_host(self):
        method_pass = base64.b64encode(b'aes-256-gcm:mypassword').decode()
        uri = f'ss://{method_pass}@ss.host.com:8388#my-ss'
        r = parse_shadowsocks(uri)
        self.assertEqual(r['protocol'], 'shadowsocks')
        self.assertEqual(r['address'], 'ss.host.com')
        self.assertEqual(r['port'], '8388')
        self.assertEqual(r['encryption'], 'aes-256-gcm')
        self.assertEqual(r['password'], 'mypassword')
        self.assertEqual(r['description'], 'my-ss')

    def test_all_in_base64(self):
        inner = base64.b64encode(b'chacha20-ietf-poly1305:secret@1.2.3.4:9999').decode()
        uri = f'ss://{inner}#encoded-ss'
        r = parse_shadowsocks(uri)
        self.assertEqual(r['address'], '1.2.3.4')
        self.assertEqual(r['port'], '9999')
        self.assertEqual(r['encryption'], 'chacha20-ietf-poly1305')
        self.assertEqual(r['password'], 'secret')

    def test_no_fragment_uses_host(self):
        method_pass = base64.b64encode(b'aes-256-gcm:pass').decode()
        uri = f'ss://{method_pass}@bare.host:1234'
        r = parse_shadowsocks(uri)
        self.assertEqual(r['description'], 'bare.host')

    def test_transport_always_tcp(self):
        method_pass = base64.b64encode(b'aes-256-gcm:pass').decode()
        uri = f'ss://{method_pass}@h:1234'
        r = parse_shadowsocks(uri)
        self.assertEqual(r['transport'], 'tcp')


class TestParseTrojan(unittest.TestCase):

    def test_basic_trojan(self):
        uri = 'trojan://mypassword@trojan.host.com:443?security=tls&sni=trojan.host.com#trojan-1'
        r = parse_trojan(uri)
        self.assertEqual(r['protocol'], 'trojan')
        self.assertEqual(r['address'], 'trojan.host.com')
        self.assertEqual(r['port'], '443')
        self.assertEqual(r['password'], 'mypassword')
        self.assertEqual(r['security'], 'tls')
        self.assertEqual(r['sni'], 'trojan.host.com')
        self.assertEqual(r['description'], 'trojan-1')

    def test_default_security_is_tls(self):
        uri = 'trojan://pass@host:443#t'
        r = parse_trojan(uri)
        self.assertEqual(r['security'], 'tls')

    def test_websocket_transport(self):
        uri = 'trojan://pass@host:443?type=ws&path=%2Ftrojan-ws&host=cdn.com&security=tls&sni=host#t'
        r = parse_trojan(uri)
        self.assertEqual(r['transport'], 'ws')
        self.assertEqual(r['transport_path'], '/trojan-ws')
        self.assertEqual(r['transport_host'], 'cdn.com')

    def test_missing_at_raises(self):
        with self.assertRaises(ValueError):
            parse_trojan('trojan://no-at-sign')

    def test_invalid_security_defaults_tls(self):
        uri = 'trojan://pass@host:443?security=bogus#t'
        r = parse_trojan(uri)
        self.assertEqual(r['security'], 'tls')

    def test_sni_defaults_to_host(self):
        uri = 'trojan://pass@myhost.com:443#t'
        r = parse_trojan(uri)
        self.assertEqual(r['sni'], 'myhost.com')


class TestParseUri(unittest.TestCase):

    def test_empty_returns_none(self):
        self.assertIsNone(parse_uri(''))
        self.assertIsNone(parse_uri('   '))

    def test_unknown_scheme_raises(self):
        with self.assertRaises(ValueError):
            parse_uri('http://not-a-proxy')

    def test_dispatches_vless(self):
        uri = 'vless://uuid@host:443?type=tcp&security=none'
        r = parse_uri(uri)
        self.assertEqual(r['protocol'], 'vless')

    def test_dispatches_trojan(self):
        uri = 'trojan://pass@host:443#t'
        r = parse_uri(uri)
        self.assertEqual(r['protocol'], 'trojan')


if __name__ == '__main__':
    unittest.main()
