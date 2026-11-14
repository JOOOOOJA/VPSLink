"""Install the authenticated SSH relay on an existing nginx HTTPS virtual host."""
import argparse
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICE = "tfl-https-relay.service"
PROGRAM = Path("/opt/tfl-https-relay")
PRIVATE = Path("/etc/tfl-https-relay")
UNIT = Path("/etc/systemd/system") / SERVICE
INCLUDE = "    include /opt/tfl-https-relay/nginx-location.conf;\n"


def run(*command):
    subprocess.run(command, check=True, timeout=20)


def listen_ready():
    for _ in range(20):
        try:
            with socket.create_connection(("127.0.0.1", 18091), 0.3):
                return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError("Relay did not start")


def replace_config(path, data):
    stat = path.stat()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp:
        target = Path(temp.name)
        try:
            temp.write(data)
            temp.flush()
            os.fchmod(temp.fileno(), stat.st_mode & 0o777)
            os.fchown(temp.fileno(), stat.st_uid, stat.st_gid)
            os.replace(target, path)
        finally:
            target.unlink(missing_ok=True)


def install(vhost, domain):
    if os.geteuid() != 0:
        raise RuntimeError("Installation requires root")
    if any(item.exists() for item in (PROGRAM, PRIVATE, UNIT)):
        raise RuntimeError("Existing relay files found")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", domain):
        raise ValueError("Invalid nginx host name")
    original = vhost.read_bytes()
    config = original.decode("utf-8")
    listen = re.compile(r"(?m)^[ \t]*listen[ \t]+443[ \t]+ssl[^;\n]*;[ \t]*\n"
                        r"[ \t]*server_name[ \t]+" + re.escape(domain) + r";[ \t]*\n")
    updated, count = listen.subn(lambda match: match.group() + INCLUDE, config)
    if count != 1 or "location = /link-ssh" in config or INCLUDE in config:
        raise RuntimeError("Expected one matching HTTPS server and an unused /link-ssh route")
    run("nginx", "-t")
    reload_attempted = False
    config_written = False
    created = []
    unit_created = False
    try:
        PROGRAM.mkdir(mode=0o755)
        created.append(PROGRAM)
        PRIVATE.mkdir(mode=0o700)
        created.append(PRIVATE)
        token = PRIVATE / "token"
        with os.fdopen(os.open(token, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as f:
            f.write(secrets.token_urlsafe(32) + "\n")
        for filename in ("relay.py", "nginx-location.conf"):
            shutil.copyfile(HERE / filename, PROGRAM / filename)
        shutil.copyfile(HERE / SERVICE, UNIT)
        unit_created = True
        run("systemctl", "daemon-reload")
        run("systemctl", "start", SERVICE)
        listen_ready()
        if vhost.read_bytes() != original:
            raise RuntimeError("nginx configuration changed during installation")
        backup = PRIVATE / "nginx.original"
        backup.write_bytes(original)
        config_written = True
        replace_config(vhost, updated.encode("utf-8"))
        run("nginx", "-t")
        reload_attempted = True
        run("systemctl", "reload", "nginx")
        run("systemctl", "enable", SERVICE)
    except BaseException:
        if config_written:
            replace_config(vhost, original)
        if reload_attempted:
            subprocess.run(["systemctl", "reload", "nginx"], check=False, timeout=20)
        if unit_created:
            subprocess.run(["systemctl", "disable", "--now", SERVICE], check=False, timeout=20)
            UNIT.unlink(missing_ok=True)
            subprocess.run(["systemctl", "daemon-reload"], check=False, timeout=20)
        for path in reversed(created):
            shutil.rmtree(path)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vhost", type=Path)
    parser.add_argument("domain")
    args = parser.parse_args()
    install(args.vhost.resolve(strict=True), args.domain)
