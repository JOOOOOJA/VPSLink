"""Synthetic protocol/security tests: no live VPS, host adapters or credentials."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/NetUlta"
HEADER = struct.Struct("!IB")
PEER = base64.b64encode(bytes(32)).decode()


def frame(kind, payload=b""):
    if isinstance(payload, dict):
        payload = json.dumps(payload).encode()
    return HEADER.pack(len(payload), ord(kind)) + payload


def frames(data):
    result = []
    while data:
        size, kind = HEADER.unpack(data[:5])
        result.append((chr(kind), data[5:5 + size]))
        data = data[5 + size:]
    return result


class RestrictedClient(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        for name, destination in (("shared_client.py", "client.py"), ("relay.py", "relay.py")):
            (self.folder / destination).write_bytes((SOURCE / name).read_bytes())
        self.policy = {"Host": "127.0.0.1", "Port": 12345, "Peer": PEER,
                       "Source": {"Id": "fixture:awg0", "PeerKeys": ["other-peer"], "PeerCount": 9,
                                  "CanProvision": True, "Ports": [{"Host": "127.0.0.1", "Port": 12345, "Inside": 12345}]}}
        (self.folder / "policy.json").write_text(json.dumps(self.policy))

    def tearDown(self):
        self.temp.cleanup()

    def run_client(self, data, env=None):
        return subprocess.run([sys.executable, "-I", str(self.folder / "client.py")], input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, env=env)

    def test_inventory_reveals_only_recipient(self):
        r = self.run_client(frame("I"))
        self.assertEqual(r.returncode, 0, r.stderr)
        result = json.loads(frames(r.stdout)[1][1])
        self.assertEqual(result["Sources"][0]["PeerKeys"], [PEER])
        self.assertFalse(result["Sources"][0]["CanProvision"])
        self.assertNotIn(b"other-peer", r.stdout)

    def test_disallow_management_and_arbitrary_udp(self):
        for kind, data in (("C", {}), ("G", {}), ("J", {}), ("X", {}),
                           ("S", {"Host": "192.0.2.99", "Port": 53}),
                           ("S", {"Host": "127.0.0.1", "Port": 22}),
                           ("T", {"Id": "fixture:awg0", "Peer": "other-peer"})):
            with self.subTest(kind=kind, data=data):
                r = self.run_client(frame(kind, data))
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(len(frames(r.stdout)), 1)

    def test_original_command_is_never_executed(self):
        marker = self.folder / "executed"
        env = dict(os.environ, SSH_ORIGINAL_COMMAND="touch " + str(marker))
        self.assertEqual(self.run_client(frame("P", b"12345678"), env).returncode, 0)
        self.assertFalse(marker.exists())

    def test_correct_target_and_ping(self):
        r = self.run_client(frame("S", {"Host": "127.0.0.1", "Port": 12345}) + frame("P", b"12345678"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([k for k, _ in frames(r.stdout)], ["H", "S", "P"])

    def test_revoked_open_session_is_closed(self):
        p = subprocess.Popen([sys.executable, "-I", str(self.folder / "client.py")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(p.stdout.read(10), frame("H", b"TFL/1"))
            (self.folder / "policy.json").unlink()
            p.stdin.write(frame("P", b"12345678")); p.stdin.flush()
            p.stdin.close()
            self.assertNotEqual(p.wait(timeout=5), 0)
            self.assertEqual(p.stdout.read(), b"")
        finally:
            if p.poll() is None:
                p.kill(); p.wait()
            p.stdout.close(); p.stderr.close()


class OwnerManagement(unittest.TestCase):
    def setUp(self):
        if sys.platform == "win32":
            sys.modules["fcntl"] = types.SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=2)
            os.O_NOFOLLOW = 0  # Only the Windows fixture; production management runs on Linux.
        self.scope = {"__name__": "sharing_test"}
        for name in ("awg_setup.py", "sharing_setup.py", "relay.py"):
            exec(compile((SOURCE / name).read_text(), name, "exec"), self.scope)
        self.temp = tempfile.TemporaryDirectory()
        folder = Path(self.temp.name)
        self.scope["SHARES"] = folder / "shares"; self.scope["SHARES"].mkdir()
        self.scope["AUTHORIZED"] = folder / "ssh" / "authorized_keys"

    def tearDown(self):
        self.temp.cleanup()

    def test_key_replacement_preserves_other_users(self):
        path = self.scope["AUTHORIZED"]; path.parent.mkdir()
        original = b"# owner\nssh-ed25519 OWNER owner\n"
        path.write_bytes(original)
        key = 'restrict,command="fixed-command" ssh-ed25519 TEST vpslink-share-' + "a" * 32
        self.scope["share_keys"]("a" * 32, key)
        self.assertTrue(path.read_bytes().startswith(original))
        self.scope["share_keys"]("a" * 32)
        self.assertEqual(path.read_bytes(), original)

    def test_reject_path_injection(self):
        for value in ("../owner", "a" * 31, "A" * 32, "a" * 32 + "\n"):
            self.assertEqual(self.scope["sharing_locked"]({"Action": "Revoke", "ShareId": value})["Error"], "id")

    def test_revoke_removes_only_exact_peer(self):
        before = ("[Interface]\nPrivateKey = server\n[Peer]\nPublicKey = " + PEER +
                  "\nAllowedIPs = 10.0.0.2/32\n[Peer]\nPublicKey = OTHER\nAllowedIPs = 10.0.0.3/32\n").encode()
        writes, commands = [], []
        self.scope["managed_config"] = lambda *args: "/config"
        self.scope["replace_config"] = lambda c, p, old, new, **kw: writes.append((old, new))
        def command(c, args):
            commands.append(args)
            return before if args[0] == "cat" else b""
        self.scope["command_bytes"] = command
        # Isolate the lock file path, retaining the implementation's flock semantics.
        real_open = os.open
        self.scope["os"] = types.SimpleNamespace(open=lambda path, flags, mode: real_open(Path(self.temp.name) / "lock", os.O_CREAT | os.O_RDWR, mode),
                                                O_CREAT=os.O_CREAT, O_RDWR=os.O_RDWR, O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0), fdopen=os.fdopen)
        self.scope["revoke_peer"]({"Peer": PEER, "Source": {"Id": "fixture", "Container": "", "Tool": "awg", "Interface": "awg0", "Label": ""}})
        self.assertNotIn(PEER.encode(), writes[0][1])
        self.assertIn(b"PublicKey = OTHER", writes[0][1])
        self.assertIn(["awg", "set", "awg0", "peer", PEER, "remove"], commands)


if __name__ == "__main__":
    unittest.main()
