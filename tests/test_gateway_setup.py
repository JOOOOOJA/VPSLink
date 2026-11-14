"""Transactional gateway installation; no real service, network or host changes."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / 'src/NetUlta/gateway_setup.py'
spec = importlib.util.spec_from_file_location('gateway', source)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.program, self.private, self.units = (root / name for name in ('program', 'private', 'units'))
        self.units.mkdir()
        self.calls = []
        self.failure = None
        self.req = dict(Owner='a' * 32, Hostname='link.example.com', TunnelToken='t' * 60,
                        RelayToken='r' * 43, SshPort=22)
        self.binary = b'fixture binary, never executed'
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name, value in {'GW_PROGRAM': self.program, 'GW_PRIVATE': self.private, 'GW_UNITS': self.units,
                            'GW_SHA': hashlib.sha256(self.binary).hexdigest(),
                            'GATEWAY_RELAY_SOURCE': base64.b64encode(b'# fixture relay').decode()}.items():
            stack.enter_context(patch.object(gateway, name, value, create=True))
        stack.enter_context(patch.object(gateway.os, 'geteuid', return_value=0, create=True))
        stack.enter_context(patch.object(gateway.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True))
        if os.name == 'nt':
            stack.enter_context(patch.object(gateway.os, 'fchmod', create=True))
        stack.enter_context(patch.dict('sys.modules', fcntl=types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *a: None)))
        stack.enter_context(patch.object(gateway.platform, 'system', return_value='Linux'))
        stack.enter_context(patch.object(gateway.platform, 'machine', return_value='x86_64'))
        self.download = stack.enter_context(patch.object(gateway.urllib.request, 'urlopen', side_effect=lambda *a, **k: io.BytesIO(self.binary)))
        stack.enter_context(patch.object(gateway, 'gateway_run', side_effect=self.command))
        stack.enter_context(patch.object(gateway.subprocess, 'run', side_effect=lambda args, **k: self.calls.append(tuple(args))))
        stack.enter_context(patch.object(gateway.socket, 'create_connection', return_value=contextlib.nullcontext()))

    def command(self, *args):
        self.calls.append(args)
        if self.failure and self.failure in args:
            raise gateway.GatewayError('service')

    def snapshot(self):
        return {str(p.relative_to(self.program.parent)): p.read_bytes()
                for p in self.program.parent.rglob('*') if p.is_file() and p.name != 'install.lock'}

    def test_install_and_repeat_without_restart_or_download(self):
        self.assertTrue(gateway.gateway_install(self.req)['Ready'])
        before = self.snapshot()
        self.assertEqual(self.download.call_count, 1)
        self.calls.clear()
        self.assertTrue(gateway.gateway_install(self.req)['Persistent'])
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.download.call_count, 1)
        self.assertFalse(any('restart' in call for call in self.calls))
        for path in self.units.iterdir():
            unit = path.read_text()
            self.assertIn('WantedBy=multi-user.target', unit)
            self.assertIn('LoadCredential=', unit)
            self.assertNotIn(self.req['TunnelToken'], unit)
            self.assertNotIn(self.req['RelayToken'], unit)

    def test_other_owner_is_not_changed(self):
        gateway.gateway_install(self.req)
        before = self.snapshot()
        self.calls.clear()
        self.assertEqual(gateway.gateway_install(dict(self.req, Owner='b' * 32)), {'Error': 'owned'})
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.calls, [])

    def test_first_failure_rolls_back_and_retry_works(self):
        self.failure = 'is-active'
        self.assertEqual(gateway.gateway_install(self.req), {'Error': 'service'})
        self.assertFalse(self.program.exists())
        self.assertFalse((self.private / 'deployment.json').exists())
        self.assertEqual(list(self.units.iterdir()), [])
        self.failure = None
        self.assertTrue(gateway.gateway_install(self.req)['Ready'])

    def test_update_failure_restores_files_and_tokens(self):
        gateway.gateway_install(self.req)
        before = self.snapshot()
        self.failure = 'is-active'
        self.assertEqual(gateway.gateway_install(dict(self.req, TunnelToken='new' * 20)), {'Error': 'service'})
        self.assertEqual(before, self.snapshot())

    def test_bad_download_does_not_claim_program_directory(self):
        with patch.object(gateway, 'GW_SHA', '0' * 64):
            self.assertEqual(gateway.gateway_install(self.req), {'Error': 'checksum'})
        self.assertFalse(self.program.exists())
        self.assertTrue(gateway.gateway_install(self.req)['Ready'])

    def test_rejects_injection_before_files_or_commands(self):
        for key, value in [('Hostname', 'x.example.com\nExecStart=bad'), ('Owner', '../other'),
                           ('SshPort', True), ('SshPort', 0), ('RelayToken', 'x\n'), ('TunnelToken', 'x\n')]:
            with self.subTest(key=key):
                self.assertIn('Error', gateway.gateway_install(dict(self.req, **{key: value})))
        self.assertFalse(self.private.exists())
        self.assertEqual(self.calls, [])
        self.assertFalse(self.download.called)


if __name__ == '__main__':
    unittest.main()
