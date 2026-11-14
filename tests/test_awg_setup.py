"""Regression tests for adding a peer without losing existing VPS settings."""

import base64
from pathlib import Path
import unittest
from unittest.mock import patch


SRC = Path(__file__).resolve().parents[1] / "src" / "NetUlta"
RELAY = {"__name__": "relay_test"}
exec(compile(b"\n".join((SRC / name).read_bytes() for name in ("awg_setup.py", "relay.py")),
             "relay_test", "exec"), RELAY)


def key(number):
    return base64.b64encode(bytes([number]) * 32).decode()


class ProvisionTest(unittest.TestCase):
    def setUp(self):
        self.peer = key(2)
        self.source = {"Container": "fixture", "Tool": "awg", "Interface": "awg0",
                       "ListenPort": 9609, "ServerKey": key(3)}
        self.original = (
            "[Interface]\nPrivateKey = " + key(4) +
            "\nAddress = 10.20.30.1/24\nListenPort = 9609\nJc = 4\n"
            "[Peer]\nPublicKey = " + key(6) + "\nAllowedIPs = 10.20.30.2/32\n"
        ).encode()
        self.disk = self.original
        self.live = {key(7): "10.20.30.3/32"}
        self.reject_set = False
        self.changes = 0
        self.backup = None

    def command(self, container, args, data=None):
        self.assertEqual(container, "fixture")
        if args[0] == "cat":
            return self.disk
        if args == ["awg", "pubkey"]:
            self.assertEqual(data, (key(4) + "\n").encode())
            return self.source["ServerKey"].encode()
        if args[-1] == "public-key":
            return self.source["ServerKey"].encode()
        if args[-1] == "allowed-ips":
            return "\n".join(k + " " + a for k, a in self.live.items()).encode()
        if args[:4] == ["awg", "set", "awg0", "peer"]:
            if args[-1] == "remove":
                self.live.pop(args[4], None)
            elif self.reject_set:
                raise RELAY["SetupError"]("command")
            else:
                self.assertNotIn(data.strip(), (key(4).encode(),))
                self.live[args[4]] = args[-1]
            return b""
        self.fail(f"Unexpected command {args[:4]}")

    def replace(self, container, path, before, after, keep_backup=False):
        self.assertEqual(before, self.disk)
        if keep_backup:
            self.backup = before
        self.disk = after
        self.changes += 1

    def run_setup(self):
        with patch.dict(RELAY, command_bytes=self.command, replace_config=self.replace):
            return RELAY["provision_locked"](self.source, self.peer, "/fixture/awg0.conf")

    def test_reserves_next_address_and_retries_without_duplicate(self):
        answer = self.run_setup()
        self.assertEqual(answer["Address"], "10.20.30.4")
        self.assertEqual(answer["Settings"], {"Jc": "4"})
        self.assertEqual(answer["ServerKey"], key(3))
        self.assertNotIn(key(4), str(answer))
        self.assertIn(key(6).encode(), self.disk)
        self.assertEqual(self.run_setup(), answer)
        self.assertEqual(self.changes, 1)
        self.assertEqual(self.backup, self.original)
        self.assertEqual(self.disk.count(self.peer.encode()), 1)

    def test_restores_persistent_config_when_kernel_rejects_peer(self):
        self.reject_set = True
        with self.assertRaisesRegex(RELAY["SetupError"], "apply"):
            self.run_setup()
        self.assertEqual(self.disk, self.original)
        self.assertEqual(self.backup, self.original)
        self.assertNotIn(self.peer, self.live)
        self.assertEqual(self.changes, 2)

    def test_awg31_parameters_survive_provision_and_retry(self):
        fields = {'HeaderProtectionKey': key(9), 'ContentPaddingAddition': '10-100',
                  'RekeyAfterTime': '120-180', 'RekeyTimeout': '5-10', 'RejectAfterTime': '180',
                  'KeepaliveTimeout': '10', 'MaxHandshakeAttempts': '20',
                  'RandomTrailers': 'on', 'DisableCookies': 'on'}
        extra = ''.join(name + ' = ' + value + '\n' for name, value in fields.items()).encode()
        self.original = self.original.replace(b'[Peer]', extra + b'[Peer]', 1)
        self.disk = self.original
        answer = self.run_setup()
        self.assertEqual(answer['Settings'], {'Jc': '4', **fields})
        self.assertEqual(self.run_setup(), answer)
        self.assertEqual(self.backup, self.original)
        for name, value in fields.items():
            self.assertIn((name + ' = ' + value).encode(), self.disk)


if __name__ == "__main__":
    unittest.main()
