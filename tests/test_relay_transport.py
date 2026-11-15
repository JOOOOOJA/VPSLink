"""UDP burst handling and verified Docker destination selection, no real Docker."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('transport_relay', Path(__file__).resolve().parents[1] / 'src/NetUlta/relay.py')
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
CID = 'a' * 12
NET = 'b' * 64


class DestinationTests(unittest.TestCase):
    def setUp(self):
        self.binding = {'Host': '127.0.0.1', 'Port': 9609, 'Inside': 51820}
        self.networks = {'vpn': {'NetworkID': NET, 'IPAddress': '172.29.172.3', 'Gateway': '172.29.172.1'}}
        self.driver = 'bridge'
        self.mode = 'missing'
        self.route = [{'prefsrc': '172.29.172.1', 'dev': 'amn0'}]
        relay.INVENTORY = {'Sources': [{'Container': CID, 'Ports': [self.binding]}]}
        self.patches = [patch.object(relay, 'run', side_effect=self.run_command),
                        patch.object(relay, 'bindings', return_value=[self.binding])]
        self.mock_run, self.mock_bindings = [p.start() for p in self.patches]

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        relay.INVENTORY = None
        if relay.UDP: relay.UDP.close(); relay.UDP = None

    def run_command(self, *args):
        if args == ('docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', CID):
            return json.dumps(self.networks)
        if args == ('docker', 'network', 'inspect', '--format', '{{.Driver}}', NET): return self.driver
        if args == ('docker', 'inspect', '--format', '{{.HostConfig.NetworkMode}}', CID): return self.mode
        if args == ('ip', '-j', 'route', 'get', '172.29.172.3'): return json.dumps(self.route)
        raise AssertionError(args)

    def destination(self, host='127.0.0.1', port=9609):
        return relay.udp_destination(ipaddress.ip_address(host), port)

    def test_verified_mapping_uses_container_inside_port(self):
        self.assertEqual(self.destination(), ('172.29.172.3', 51820))

    def test_no_redirect_of_manual_external_destination(self):
        self.assertEqual(self.destination('192.0.2.1'), ('192.0.2.1', 9609))
        self.mock_run.assert_not_called()

    def test_primary_network_wins_over_extra_dns_network(self):
        self.mode = 'vpn'
        self.networks['dns'] = {'NetworkID': 'c' * 64, 'IPAddress': '172.30.1.3', 'Gateway': '172.30.1.1'}
        self.assertEqual(self.destination(), ('172.29.172.3', 51820))

    def test_unknown_or_ambiguous_binding_keeps_original(self):
        self.assertEqual(self.destination(port=443), ('127.0.0.1', 443))
        relay.INVENTORY['Sources'].append({'Container': 'c' * 12, 'Ports': [self.binding]})
        self.assertEqual(self.destination(), ('127.0.0.1', 9609))
        self.mock_run.assert_not_called()

    def test_stale_invitation_mapping_keeps_original(self):
        self.mock_bindings.return_value = []
        self.assertEqual(self.destination(), ('127.0.0.1', 9609))

    def test_nonbridge_ambiguous_and_invalid_networks_keep_original(self):
        for networks in (None, [], {}, {'a': {}, 'b': {}}, {'a': {'NetworkID': 'invalid'}},
                         {'a': {'NetworkID': NET, 'IPAddress': '127.0.0.1', 'Gateway': '172.29.172.1'}}):
            self.networks = networks
            self.assertEqual(self.destination(), ('127.0.0.1', 9609))

    def test_no_indirect_or_different_source_route(self):
        for route in ([], None, [{'prefsrc': '192.0.2.1'}],
                      [{'prefsrc': '172.29.172.1', 'gateway': '192.0.2.1'}]):
            self.route = route
            self.assertEqual(self.destination(), ('127.0.0.1', 9609))

    def test_nonbridge_driver_keeps_original(self):
        self.driver = 'macvlan'
        self.assertEqual(self.destination(), ('127.0.0.1', 9609))

    def test_loopback_echo_and_bounded_burst(self):
        relay.INVENTORY = None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender, patch.object(relay, 'reply') as reply:
            sender.bind(('127.0.0.1', 0)); sender.settimeout(1)
            relay.configure(json.dumps({'Host': '127.0.0.1', 'Port': sender.getsockname()[1]}).encode())
            self.assertTrue(reply.call_args.args[1]['Ready'])
            self.assertGreaterEqual(relay.UDP.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), 128 * 1024)
            relay.UDP.send(b'probe')
            data, target = sender.recvfrom(16)
            self.assertEqual(data, b'probe')
            for n in range(64): sender.sendto(n.to_bytes(4, 'big') + bytes(1396), target)
            received = [int.from_bytes(relay.UDP.recv(1500)[:4], 'big') for _ in range(64)]
            self.assertEqual(received, list(range(64)))


if __name__ == '__main__': unittest.main()
