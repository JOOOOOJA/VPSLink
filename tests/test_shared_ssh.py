"""Isolated Linux CI sshd: real forced-command authentication, no production sshd edits."""
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src/NetUlta"
HEADER = struct.Struct("!IB")


def frame(kind, data=b""):
    return HEADER.pack(len(data), ord(kind)) + data


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0 and Path("/usr/sbin/sshd").is_file(), "isolated Linux root CI with existing OpenSSH server")
class SharedSsh(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpslink-ci-", dir="/root")
        self.folder = Path(self.temp.name)
        self.process = None
        try:
            for name in ("host", "client"):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.folder / name)], check=True, timeout=10)
            self.scope = {"__name__": "fixture"}
            for name in ("awg_setup.py", "sharing_setup.py", "relay.py"):
                exec(compile((SOURCE / name).read_text(), name, "exec"), self.scope)
            self.scope["SHARES"] = self.folder / "shares"
            self.scope["AUTHORIZED"] = self.folder / "authorized_keys"
            self.scope["SHARED_CLIENT_SOURCE"] = base64.b64encode((SOURCE / "shared_client.py").read_bytes()).decode()
            self.scope["SHARED_RELAY_SOURCE"] = base64.b64encode((SOURCE / "relay.py").read_bytes()).decode()
            peer = base64.b64encode(bytes(32)).decode()
            source = {"Id": "fixture:awg0", "CanProvision": True, "Container": "", "Interface": "awg0", "Tool": "awg", "Label": "fixture",
                      "Ports": [{"Host": "127.0.0.1", "Port": 12345, "Inside": 12345}], "ServerKey": peer, "ListenPort": 12345}
            self.scope["INVENTORY"] = {"Sources": [source]}
            self.scope["managed_config"] = lambda *args: "/synthetic-awg"
            self.scope["command_bytes"] = lambda c, args: b"[Interface]\nPrivateKey = synthetic\n" if args[0] == "cat" else b""
            self.scope["provision"] = lambda req: {"Address": "10.0.0.2", "ServerKey": peer, "PresharedKey": peer, "Settings": {}}
            self.scope["revoke_peer"] = lambda policy: None
            ssh_key = " ".join((self.folder / "client.pub").read_text().split()[:2])
            self.share_id = "a" * 32
            result = self.scope["sharing"]({"Action": "Create", "ShareId": self.share_id, "Name": "CI fixture", "SshKey": ssh_key,
                                              "Id": source["Id"], "Peer": peer, "Host": "127.0.0.1", "Port": 12345})
            self.assertTrue(result.get("Ready"), result)
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]
            # A separate loopback listener; never reads/modifies /etc/ssh/sshd_config.
            config = (f"Port {self.port}\nListenAddress 127.0.0.1\nHostKey {self.folder}/host\n"
                      f"PidFile {self.folder}/pid\nAuthorizedKeysFile {self.folder}/authorized_keys\n"
                      "PermitRootLogin forced-commands-only\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                      "UsePAM no\nStrictModes yes\nAllowUsers root\nLogLevel ERROR\n")
            (self.folder / "sshd_config").write_text(config)
            Path("/run/sshd").mkdir(exist_ok=True)
            self.process = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(self.folder / "sshd_config")], stderr=subprocess.PIPE)
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", self.port), .1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError("isolated sshd failed")
            host_pub = " ".join((self.folder / "host.pub").read_text().split()[:2])
            (self.folder / "known_hosts").write_text(f"[127.0.0.1]:{self.port} {host_pub}\n")
        except BaseException:
            self.tearDown()
            raise

    def tearDown(self):
        if self.process:
            self.process.terminate()
            self.process.communicate(timeout=5)
        self.temp.cleanup()

    def ssh(self, command, data):
        return subprocess.run(["ssh", "-F", "/dev/null", "-T", "-p", str(self.port), "-i", str(self.folder / "client"),
                               "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                               "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(self.folder / "known_hosts"),
                               "root@127.0.0.1", command], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def test_real_ssh_forces_handler_and_revokes(self):
        marker = self.folder / "must-not-exist"
        result = self.ssh("touch " + str(marker), frame("P", b"12345678"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, frame("H", b"TFL/1") + frame("P", b"12345678"))
        self.assertFalse(marker.exists())
        forbidden = self.ssh("vpslink-client-v1", frame("J", b'{"Action":"Create"}'))
        self.assertNotEqual(forbidden.returncode, 0)
        revoked = self.scope["sharing"]({"Action": "Revoke", "ShareId": self.share_id})
        self.assertTrue(revoked.get("Ready"), revoked)
        result = self.ssh("vpslink-client-v1", frame("P", b"12345678"))
        self.assertEqual(result.returncode, 255)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
