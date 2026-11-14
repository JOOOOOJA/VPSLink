"""Owner-only invitation management; executed over the authenticated owner session."""
from pathlib import Path
import fcntl
import shutil

SHARES = Path("/root/.vpslink-shares")
AUTHORIZED = Path("/root/.ssh/authorized_keys")


def share_write(path, data):
    if path.is_symlink():
        raise ValueError("symlink")
    temp = path.with_name(path.name + "." + secrets.token_hex(8))
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def share_keys(share_id, new_line=None):
    if AUTHORIZED.is_symlink() or AUTHORIZED.parent.is_symlink():
        raise ValueError("symlink")
    AUTHORIZED.parent.mkdir(mode=0o700, exist_ok=True)
    before = AUTHORIZED.read_bytes() if AUTHORIZED.exists() else b""
    if len(before) > 1024 * 1024:
        raise ValueError("keys size")
    marker = (" vpslink-share-" + share_id).encode()
    lines = [line for line in before.splitlines(keepends=True) if not line.rstrip().endswith(marker)]
    after = b"".join(lines)
    if new_line:
        if after and not after.endswith(b"\n"):
            after += b"\n"
        after += new_line.encode() + b"\n"
    # Detect external edits before replacement; the Link lock serializes Link writers.
    if (AUTHORIZED.read_bytes() if AUTHORIZED.exists() else b"") != before:
        raise ValueError("keys changed")
    share_write(AUTHORIZED, after)


def revoke_peer(policy):
    source, peer = policy["Source"], policy["Peer"]
    path = managed_config(source["Container"], source["Interface"], source["Tool"], source["Label"])
    if not path:
        raise SetupError("layout")
    tag = hashlib.sha256(source["Id"].encode()).hexdigest()[:32]
    fd = os.open("/run/lock/thingsnotfun-awg-" + tag, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = command_bytes(source["Container"], ["cat", path])
        # Preserve every byte outside this exact peer block.
        blocks = re.split(br"(?im)(?=^\s*\[Peer\]\s*$)", before)
        kept = [blocks[0]]
        for block in blocks[1:]:
            keys = re.findall(br"(?im)^\s*PublicKey\s*=\s*([^\r\n#]+)", block)
            if len(keys) != 1:
                raise SetupError("layout")
            if keys[0].strip().decode() != peer:
                kept.append(block)
        after = b"".join(kept)
        if after != before:
            replace_config(source["Container"], path, before, after, keep_backup=True)
        command_bytes(source["Container"], [source["Tool"], "set", source["Interface"], "peer", peer, "remove"])
        live = pairs(command_bytes(source["Container"], [source["Tool"], "show", source["Interface"], "allowed-ips"]).decode())
        if peer in live:
            raise SetupError("remove")


def sharing(req):
    if os.geteuid() != 0:
        return {"Error": "root"}
    if SHARES.is_symlink():
        return {"Error": "storage"}
    SHARES.mkdir(mode=0o700, exist_ok=True)
    if SHARES.stat().st_uid != 0 or SHARES.stat().st_mode & 0o077:
        return {"Error": "storage"}
    fd = os.open(SHARES / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return sharing_locked(req)
    except (OSError, ValueError, KeyError, TypeError, SetupError, subprocess.TimeoutExpired):
        return {"Error": "sharing"}


def sharing_locked(req):
    if req.get("Action") == "List":
        rows = []
        for path in sorted(SHARES.glob("*/record.json"))[:100]:
            item = json.loads(path.read_text())
            rows.append({"Id": path.parent.name, "Name": item["Name"], "Peer": item["Peer"],
                         "Active": (path.parent / "policy.json").is_file()})
        return {"Ready": True, "Invitations": rows}
    share_id = req.get("ShareId", "")
    if not isinstance(share_id, str) or not re.fullmatch(r"[a-f0-9]{32}", share_id):
        return {"Error": "id"}
    folder = SHARES / share_id
    if req.get("Action") == "Revoke":
        policy = json.loads((folder / "record.json").read_text())
        (folder / "policy.json").unlink(missing_ok=True)
        share_keys(share_id)
        try:
            revoke_peer(policy)
        except (OSError, SetupError, subprocess.TimeoutExpired, ValueError):
            return {"Error": "peer_remove", "TransportRevoked": True}
        return {"Ready": True}
    if req.get("Action") != "Create" or folder.exists():
        return {"Error": "exists"}
    if len(list(SHARES.glob("*/record.json"))) >= 100:
        return {"Error": "limit"}
    ssh_key, name = req.get("SshKey", ""), req.get("Name", "")
    if not isinstance(ssh_key, str) or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}", ssh_key):
        return {"Error": "key"}
    blob = base64.b64decode(ssh_key.split()[1], validate=True)
    if len(blob) != 51 or blob[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20":
        return {"Error": "key"}
    if not isinstance(name, str) or not 1 <= len(name) <= 80 or any(ord(c) < 32 for c in name):
        return {"Error": "name"}
    source = next((s for s in (INVENTORY or {}).get("Sources", []) if s["Id"] == req.get("Id")), None)
    if not source or not source.get("CanProvision") or not B64KEY.fullmatch(req.get("Peer", "")):
        return {"Error": "source"}
    binding = next((p for p in source["Ports"] if p["Host"] == req.get("Host") and p["Port"] == req.get("Port")), None)
    if not binding:
        return {"Error": "target"}
    # Only create a new peer: never delegate or revoke an owner's existing peer.
    live = pairs(command_bytes(source["Container"], [source["Tool"], "show", source["Interface"], "allowed-ips"]).decode())
    path = managed_config(source["Container"], source["Interface"], source["Tool"], source["Label"])
    if not path:
        return {"Error": "source"}
    _, peers = config_sections(command_bytes(source["Container"], ["cat", path]))
    if req["Peer"] in live or any(p.get("publickey") == [req["Peer"]] for p in peers):
        return {"Error": "existing_peer"}
    result = provision({"Id": source["Id"], "Peer": req["Peer"]})
    if result.get("Error"):
        return result
    policy = {"Name": name, "Peer": req["Peer"], "Host": binding["Host"], "Port": binding["Port"],
              "Source": dict(source, Ports=[binding])}
    folder.mkdir(mode=0o700)
    # Keep recovery metadata even if installation fails. List/Revoke can clean up the peer.
    share_write(folder / "record.json", json.dumps(policy).encode())
    try:
        share_write(folder / "relay.py", base64.b64decode(SHARED_RELAY_SOURCE))
        share_write(folder / "client.py", base64.b64decode(SHARED_CLIENT_SOURCE))
        share_write(folder / "policy.json", json.dumps(policy).encode())
        command = '/usr/bin/python3 -I ' + str(folder / "client.py")
        share_keys(share_id, 'restrict,command="' + command + '" ' + ssh_key + ' vpslink-share-' + share_id)
        return {"Ready": True, "Vpn": result, "SourceId": source["Id"]}
    except (OSError, ValueError):
        (folder / "policy.json").unlink(missing_ok=True)
        raise
