"""UDP burst handling and verified Docker destination selection, no real Docker."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import queue
import socket
import threading
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


class DatagramQueueTests(unittest.TestCase):
    def test_drops_oldest_at_both_bounds(self):
        sock = object()
        datagrams = relay.DatagramQueue(clock=lambda: 0)
        with patch.object(relay, 'UDP_QUEUE_BYTES', 7), patch.object(relay, 'UDP_QUEUE_PACKETS', 2):
            for packet in (b'a', b'b', b'c', b'1234567'):
                datagrams.put(sock, packet)
                self.assertLessEqual(len(datagrams.items), 2)
                self.assertLessEqual(datagrams.size, 7)
            self.assertEqual(datagrams.get(), (0, sock, b'1234567'))
        datagrams.close()
        self.assertIsNone(datagrams.get())
        self.assertEqual(datagrams.size, 0)

    def test_stalled_stdout_allows_udp_drain_and_skips_stale_packets(self):
        incoming = queue.Queue()
        stop = threading.Event()
        entered_write = threading.Event()
        release_write = threading.Event()
        queued_old = threading.Event()
        queued_fresh = threading.Event()
        delivered_fresh = threading.Event()
        clock = [0.0]
        sent = []
        datagrams = relay.DatagramQueue(clock=lambda: clock[0])

        class Socket:
            def recv(self, _):
                try:
                    return incoming.get(timeout=0.05)
                except queue.Empty:
                    raise socket.timeout() from None

        sock = Socket()
        put = datagrams.put

        def record_packet(source, data):
            put(source, data)
            if data == b'old':
                queued_old.set()
            if data == b'fresh':
                queued_fresh.set()

        def slow_write(kind, data):
            sent.append((kind, data))
            if data == b'blocked':
                entered_write.set()
                release_write.wait(3)
            if data == b'fresh':
                delivered_fresh.set()

        with patch.object(relay, 'STOP', stop), patch.object(relay, 'UDP', sock), \
                patch.object(relay, 'write_frame', side_effect=slow_write), patch.object(datagrams, 'put', side_effect=record_packet):
            reader = threading.Thread(target=relay.udp_receive, args=(datagrams,))
            writer = threading.Thread(target=relay.udp_write, args=(datagrams,))
            reader.start()
            writer.start()
            try:
                incoming.put(b'blocked')
                self.assertTrue(entered_write.wait(2))
                incoming.put(b'old')
                self.assertTrue(queued_old.wait(2))
                clock[0] = 0.2
                incoming.put(b'fresh')
                self.assertTrue(queued_fresh.wait(2))
                release_write.set()
                self.assertTrue(delivered_fresh.wait(2))
                self.assertEqual(sent, [('D', b'blocked'), ('D', b'fresh')])
            finally:
                stop.set()
                datagrams.close()
                release_write.set()
                reader.join(2)
                writer.join(2)


if __name__ == '__main__': unittest.main()
