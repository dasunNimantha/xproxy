"""Tests for service_control.py — xray config generation."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                '..', 'src', 'opnsense', 'scripts', 'xproxy'))

from service_control import (
    build_xray_config, build_outbound, build_stream_settings, _safe_int,
)


def _base_cfg(**overrides):
    cfg = {
        'socks_port': 10808,
        'http_port': 10809,
        'socks_listen': '127.0.0.1',
        'http_listen': '127.0.0.1',
        'log_level': 'warning',
        'bypass_ips': '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16',
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


class TestSafeInt(unittest.TestCase):

    def test_valid(self):
        self.assertEqual(_safe_int('443', 80), 443)

    def test_default_on_invalid(self):
        self.assertEqual(_safe_int('abc', 80), 80)
        self.assertEqual(_safe_int('', 80), 80)
        self.assertEqual(_safe_int(None, 80), 80)

    def test_min_max(self):
        self.assertEqual(_safe_int('0', 80, minimum=1), 80)
        self.assertEqual(_safe_int('99999', 80, maximum=65535), 80)
        self.assertEqual(_safe_int('443', 80, minimum=1, maximum=65535), 443)


class TestBuildStreamSettings(unittest.TestCase):

    def test_tcp_no_security(self):
        srv = _vless_server(security='none', transport='tcp')
        stream = build_stream_settings(srv)
        self.assertEqual(stream['network'], 'tcp')
        self.assertNotIn('security', stream)

    def test_tls(self):
        srv = _vless_server(security='tls', sni='example.com', fingerprint='firefox', alpn='h2,http/1.1')
        stream = build_stream_settings(srv)
        self.assertEqual(stream['security'], 'tls')
        self.assertEqual(stream['tlsSettings']['serverName'], 'example.com')
        self.assertEqual(stream['tlsSettings']['fingerprint'], 'firefox')
        self.assertEqual(stream['tlsSettings']['alpn'], ['h2', 'http/1.1'])

    def test_reality(self):
        srv = _vless_server()
        stream = build_stream_settings(srv)
        self.assertEqual(stream['security'], 'reality')
        self.assertEqual(stream['realitySettings']['publicKey'], 'pubkey123')
        self.assertEqual(stream['realitySettings']['shortId'], 'shortid456')
        self.assertEqual(stream['realitySettings']['serverName'], 'www.spotify.com')

    def test_websocket(self):
        srv = _vless_server(transport='ws', transport_path='/ws', transport_host='cdn.example.com')
        stream = build_stream_settings(srv)
        self.assertEqual(stream['wsSettings']['path'], '/ws')
        self.assertEqual(stream['wsSettings']['headers']['Host'], 'cdn.example.com')

    def test_grpc(self):
        srv = _vless_server(transport='grpc', transport_path='my-grpc-svc')
        stream = build_stream_settings(srv)
        self.assertEqual(stream['grpcSettings']['serviceName'], 'my-grpc-svc')

    def test_h2(self):
        srv = _vless_server(transport='h2', transport_path='/h2', transport_host='h2.host')
        stream = build_stream_settings(srv)
        self.assertEqual(stream['httpSettings']['path'], '/h2')
        self.assertEqual(stream['httpSettings']['host'], ['h2.host'])

    def test_httpupgrade(self):
        srv = _vless_server(transport='httpupgrade', transport_path='/upgrade', transport_host='up.host')
        stream = build_stream_settings(srv)
        self.assertEqual(stream['httpupgradeSettings']['path'], '/upgrade')
        self.assertEqual(stream['httpupgradeSettings']['host'], 'up.host')


class TestBuildOutbound(unittest.TestCase):

    def test_vless_outbound(self):
        srv = _vless_server()
        out = build_outbound(srv)
        self.assertEqual(out['tag'], 'proxy')
        self.assertEqual(out['protocol'], 'vless')
        vnext = out['settings']['vnext'][0]
        self.assertEqual(vnext['address'], 'proxy.example.com')
        self.assertEqual(vnext['port'], 443)
        self.assertEqual(vnext['users'][0]['id'], 'test-uuid')
        self.assertEqual(vnext['users'][0]['flow'], 'xtls-rprx-vision')

    def test_vmess_outbound(self):
        srv = _vless_server(protocol='vmess', encryption='auto', flow='')
        out = build_outbound(srv)
        self.assertEqual(out['protocol'], 'vmess')
        user = out['settings']['vnext'][0]['users'][0]
        self.assertEqual(user['alterId'], 0)
        self.assertEqual(user['security'], 'auto')

    def test_shadowsocks_outbound(self):
        srv = _vless_server(protocol='shadowsocks', encryption='aes-256-gcm', password='secret')
        out = build_outbound(srv)
        self.assertEqual(out['protocol'], 'shadowsocks')
        server = out['settings']['servers'][0]
        self.assertEqual(server['method'], 'aes-256-gcm')
        self.assertEqual(server['password'], 'secret')

    def test_trojan_outbound(self):
        srv = _vless_server(protocol='trojan', password='trojan-pass')
        out = build_outbound(srv)
        self.assertEqual(out['protocol'], 'trojan')
        server = out['settings']['servers'][0]
        self.assertEqual(server['password'], 'trojan-pass')

    def test_vless_no_flow(self):
        srv = _vless_server(flow='')
        out = build_outbound(srv)
        self.assertNotIn('flow', out['settings']['vnext'][0]['users'][0])


class TestBuildXrayConfig(unittest.TestCase):

    def test_full_config_structure(self):
        cfg = _base_cfg()
        srv = _vless_server()
        config = build_xray_config(cfg, srv)

        self.assertIn('log', config)
        self.assertIn('inbounds', config)
        self.assertIn('outbounds', config)
        self.assertIn('routing', config)
        self.assertEqual(config['log']['loglevel'], 'warning')

    def test_inbounds(self):
        cfg = _base_cfg()
        srv = _vless_server()
        config = build_xray_config(cfg, srv)
        inbounds = config['inbounds']

        socks = next(i for i in inbounds if i['tag'] == 'socks-in')
        self.assertEqual(socks['port'], 10808)
        self.assertEqual(socks['listen'], '127.0.0.1')
        self.assertTrue(socks['settings']['udp'])

        http = next(i for i in inbounds if i['tag'] == 'http-in')
        self.assertEqual(http['port'], 10809)

    def test_outbounds_include_direct_and_block(self):
        cfg = _base_cfg()
        srv = _vless_server()
        config = build_xray_config(cfg, srv)
        tags = [o['tag'] for o in config['outbounds']]
        self.assertEqual(tags, ['proxy', 'direct', 'block'])

    def test_bypass_ips_routing(self):
        cfg = _base_cfg(bypass_ips='10.0.0.0/8,192.168.0.0/16')
        srv = _vless_server()
        config = build_xray_config(cfg, srv)
        bypass_rule = config['routing']['rules'][0]
        self.assertEqual(bypass_rule['outboundTag'], 'direct')
        self.assertIn('10.0.0.0/8', bypass_rule['ip'])
        self.assertIn('192.168.0.0/16', bypass_rule['ip'])

    def test_domain_address_routing(self):
        cfg = _base_cfg(bypass_ips='')
        srv = _vless_server(address='proxy.example.com')
        config = build_xray_config(cfg, srv)
        domain_rule = next(
            r for r in config['routing']['rules'] if 'domain' in r
        )
        self.assertIn('full:proxy.example.com', domain_rule['domain'])
        self.assertEqual(domain_rule['outboundTag'], 'direct')

    def test_ip_address_routing(self):
        cfg = _base_cfg(bypass_ips='')
        srv = _vless_server(address='1.2.3.4')
        config = build_xray_config(cfg, srv)
        ip_rule = next(
            r for r in config['routing']['rules'] if 'ip' in r
        )
        self.assertIn('1.2.3.4', ip_rule['ip'])

    def test_custom_listen_addresses(self):
        cfg = _base_cfg(socks_listen='0.0.0.0', http_listen='0.0.0.0')
        srv = _vless_server()
        config = build_xray_config(cfg, srv)
        socks = config['inbounds'][0]
        http = config['inbounds'][1]
        self.assertEqual(socks['listen'], '0.0.0.0')
        self.assertEqual(http['listen'], '0.0.0.0')


if __name__ == '__main__':
    unittest.main()
