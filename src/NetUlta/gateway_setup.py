"""Install Link's persistent, authenticated gateway without changing SSH or nginx."""
import base64
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

GW_PROGRAM = Path('/opt/thingsnotfun-link-gateway')
GW_PRIVATE = Path('/etc/thingsnotfun-link-gateway')
GW_UNITS = Path('/etc/systemd/system')
GW_RELAY = 'thingsnotfun-link-relay.service'
GW_TUNNEL = 'thingsnotfun-link-cloudflared.service'
GW_SHA = '51f7c68b57ed7269164075d7e789efce5b59355982f06392deeb037d982a51fd'
GW_URL = 'https://github.com/cloudflare/cloudflared/releases/download/2026.11.0/cloudflared-linux-amd64'


class GatewayError(Exception):
    pass


def gateway_validate(req):
    if not isinstance(req, dict):
        raise GatewayError('request')
    owner, hostname = req.get('Owner', ''), req.get('Hostname', '')
    token, relay = req.get('TunnelToken', ''), req.get('RelayToken', '')
    if not isinstance(owner, str) or not re.fullmatch(r'[a-f0-9]{32}', owner):
        raise GatewayError('owner')
    if not isinstance(hostname, str) or len(hostname) > 253 or not re.fullmatch(
            r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', hostname):
        raise GatewayError('hostname')
    if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9+/=_-]{40,4096}', token):
        raise GatewayError('token')
    if not isinstance(relay, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', relay):
        raise GatewayError('relay_token')
    port = req.get('SshPort')
    if type(port) is not int or not 1 <= port <= 65535:
        raise GatewayError('port')
    return owner, hostname, token, relay, port


def gateway_run(*args):
    result = subprocess.run(args, capture_output=True, timeout=45)
    if result.returncode:
        # Never forward command output: it could contain credentials.
        raise GatewayError('service')


def gateway_write(path, data, mode):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise GatewayError('unsafe_path')
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
            temp = Path(f.name)
            os.fchmod(f.fileno(), mode)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def gateway_units(ssh_port):
    common = ('[Unit]\nAfter=network-online.target\nWants=network-online.target\n'
              'StartLimitIntervalSec=0\n[Service]\nType=simple\nDynamicUser=yes\n'
              'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
              'UMask=0077\nRestart=always\nRestartSec=3\n')
    relay = (common + f'LoadCredential=relay:{GW_PRIVATE}/relay-token\n'
             f'ExecStart=/usr/bin/python3 -I -u {GW_PROGRAM}/relay.py '
             f'--token-file /run/credentials/{GW_RELAY}/relay --listen-port 18093 --ssh-port {ssh_port}\n'
             '[Install]\nWantedBy=multi-user.target\n')
    tunnel = (common + f'LoadCredential=tunnel:{GW_PRIVATE}/tunnel-token\n'
              f'ExecStart={GW_PROGRAM}/cloudflared --no-autoupdate tunnel --protocol http2 run '
              f'--token-file /run/credentials/{GW_TUNNEL}/tunnel\n'
              '[Install]\nWantedBy=multi-user.target\n')
    return {GW_UNITS / GW_RELAY: relay.encode(), GW_UNITS / GW_TUNNEL: tunnel.encode()}


def gateway_install(req):
    try:
        owner, hostname, token, relay, ssh_port = gateway_validate(req)
        if os.geteuid() != 0:
            raise GatewayError('root')
        if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
            raise GatewayError('platform')
        import fcntl
        for directory in (GW_PROGRAM, GW_PRIVATE):
            if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                raise GatewayError('unsafe_path')
        GW_PRIVATE.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(GW_PRIVATE / 'install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            manifest = GW_PRIVATE / 'deployment.json'
            if manifest.is_symlink():
                raise GatewayError('unsafe_path')
            if manifest.exists():
                previous = json.loads(manifest.read_text())
                if previous.get('Owner') != owner or previous.get('Hostname') != hostname:
                    raise GatewayError('owned')
            elif any(p.exists() for p in (GW_PROGRAM, GW_UNITS / GW_RELAY, GW_UNITS / GW_TUNNEL)):
                raise GatewayError('owned')
            binary = GW_PROGRAM / 'cloudflared'
            if binary.is_symlink():
                raise GatewayError('unsafe_path')
            if binary.exists():
                data = binary.read_bytes()
            else:
                # Reuse the already verified test binary when migrating this lab.
                cached = Path('/opt/tfl-ws-lab/cloudflared')
                if cached.is_file() and not cached.is_symlink() and hashlib.sha256(cached.read_bytes()).hexdigest() == GW_SHA:
                    data = cached.read_bytes()
                else:
                    with urllib.request.urlopen(GW_URL, timeout=30) as response:
                        data = response.read(50000001)
            if len(data) > 50000000 or hashlib.sha256(data).hexdigest() != GW_SHA:
                raise GatewayError('checksum')
            GW_PROGRAM.mkdir(mode=0o755, exist_ok=True)
            files = gateway_units(ssh_port)
            files.update({binary: data, GW_PROGRAM / 'relay.py': base64.b64decode(GATEWAY_RELAY_SOURCE),
                          GW_PRIVATE / 'relay-token': (relay + '\n').encode(),
                          GW_PRIVATE / 'tunnel-token': (token + '\n').encode(),
                          manifest: json.dumps({'Owner': owner, 'Hostname': hostname, 'Version': 1}).encode()})
            backup = {}
            for path in files:
                if path.is_symlink() or (path.exists() and not path.is_file()):
                    raise GatewayError('unsafe_path')
                backup[path] = (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
            existing = manifest.exists()
            changed = any(backup[path] is None or backup[path][0] != content for path, content in files.items())
            try:
                for path, content in files.items():
                    mode = 0o600 if path.parent == GW_PRIVATE else 0o755 if path == binary else 0o644
                    gateway_write(path, content, mode)
                gateway_run('systemctl', 'daemon-reload')
                gateway_run('systemctl', 'enable', GW_RELAY, GW_TUNNEL)
                gateway_run('systemctl', 'restart' if changed and existing else 'start', GW_RELAY, GW_TUNNEL)
                for attempt in range(20):
                    try:
                        with socket.create_connection(('127.0.0.1', 18093), 0.3):
                            break
                    except OSError:
                        if attempt == 19:
                            raise GatewayError('listen')
                        time.sleep(0.25)
                gateway_run('systemctl', 'is-active', GW_RELAY, GW_TUNNEL)
            except BaseException:
                # Only our own units/files are rolled back. The working test gateway is untouched.
                if not existing:
                    subprocess.run(['systemctl', 'disable', '--now', GW_TUNNEL, GW_RELAY], capture_output=True, timeout=45)
                for path, old in backup.items():
                    if old is None:
                        path.unlink(missing_ok=True)
                    else:
                        gateway_write(path, old[0], old[1])
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=45)
                if existing:
                    subprocess.run(['systemctl', 'restart', GW_RELAY, GW_TUNNEL], capture_output=True, timeout=45)
                else:
                    GW_PROGRAM.rmdir()
                raise
            return {'Ready': True, 'Hostname': hostname, 'Persistent': True}
    except GatewayError as error:
        return {'Error': str(error)}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return {'Error': 'install'}
