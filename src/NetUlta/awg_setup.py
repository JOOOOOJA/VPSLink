"""Runs on the VPS as part of the ephemeral SSH relay."""

import base64
import hashlib


AWG_FIELDS = {name.lower(): name for name in (
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5", "Hpk",
    "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
    "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
)}
STANDARD_FIELDS = {"address", "privatekey", "listenport", "fwmark", "table", "mtu",
                   "preup", "postup", "predown", "postdown", "saveconfig", "dns"}


class SetupError(Exception):
    pass


def managed_config(container, iface, tool, label):
    if not IDENTIFIER.fullmatch(iface) or (tool != "awg" and not label.startswith("amnezia-awg")):
        return None
    if container and label.startswith("amnezia-awg"):
        paths = ["/opt/amnezia/awg/" + iface + ".conf",
                 "/opt/amnezia/awg3/" + iface + ".conf"]
    elif not container:
        paths = ["/etc/amnezia/amneziawg/" + iface + ".conf",
                 "/etc/wireguard/" + iface + ".conf"]
    else:
        return None
    prefix = prefix_for(container)
    found = [path for path in paths if run(
        *prefix, "sh", "-c", 'test -f "$1" && test ! -L "$1"', "sh", path
    ) is not None]
    return found[0] if len(found) == 1 else None


def command_bytes(container, args, input_data=None):
    prefix = ["docker", "exec"] + (["-i"] if input_data is not None else []) + [container] if container else []
    kwargs = {"input": input_data} if input_data is not None else {"stdin": subprocess.DEVNULL}
    result = subprocess.run(
        prefix + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=6, **kwargs
    )
    if result.returncode != 0 or len(result.stdout) > 256 * 1024:
        raise SetupError("command")
    return result.stdout


def config_sections(data):
    sections = []
    for raw in data.decode("utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].lower()
            if name not in ("interface", "peer"):
                raise SetupError("layout")
            sections.append((name, {}))
            continue
        key, sep, value = line.partition("=")
        if not sep or not sections:
            raise SetupError("layout")
        sections[-1][1].setdefault(key.strip().lower(), []).append(value.strip())
    if not sections or sections[0][0] != "interface" or any(name != "peer" for name, _ in sections[1:]):
        raise SetupError("layout")
    return sections[0][1], [fields for _, fields in sections[1:]]


def single(fields, key):
    values = fields.get(key, [])
    if len(values) != 1:
        raise SetupError("layout")
    return values[0]


def networks(values):
    return [ipaddress.ip_network(part, strict=False) for value in values for part in value.replace(",", " ").split()]


def client_address(server, occupied):
    network = server.network
    if network.prefixlen < 16 or network.prefixlen > 30:
        raise SetupError("subnet")
    for candidate in network.hosts():
        if candidate != server.ip and not any(candidate in used for used in occupied):
            return candidate
    raise SetupError("subnet_full")


def replace_config(container, path, before, after, keep_backup=False):
    digest = hashlib.sha256(before).hexdigest()
    # The fixed script refuses symlinks and compares the file before replacement.
    shell = r'''
set -eu
path=$1
expected=$2
save_backup=$3
check() {
    test ! -L "$path" && test -f "$path" || return 1
    sum=$(sha256sum "$path" | cut -d ' ' -f 1)
    test "$sum" = "$expected"
}
check || exit 1
umask 077
tmp=$(mktemp "$path.tfl.XXXXXX")
backup_tmp=
trap 'rm -f "$tmp"; if test -n "$backup_tmp"; then rm -f "$backup_tmp"; fi' EXIT
trap 'exit 1' HUP INT TERM
if test "$save_backup" = yes; then
    backup="$path.tfl-backup.$expected"
    if test ! -e "$backup"; then
        backup_tmp=$(mktemp "$path.tfl.backup.XXXXXX")
        cat "$path" > "$backup_tmp"
        ln "$backup_tmp" "$backup" || exit 1
    fi
    test ! -L "$backup" && test -f "$backup" || exit 1
    sum=$(sha256sum "$backup" | cut -d ' ' -f 1)
    test "$sum" = "$expected" || exit 1
fi
cp -p "$path" "$tmp"
cat > "$tmp"
check || exit 1
mv -f "$tmp" "$path"
'''
    command_bytes(container, ["sh", "-c", shell, "sh", path, digest, "yes" if keep_backup else "no"], after)


def provision_locked(source, peer, path):
    container, tool, iface = source["Container"], source["Tool"], source["Interface"]
    before = command_bytes(container, ["cat", path])
    settings, peers = config_sections(before)
    if set(settings) - set(AWG_FIELDS) - STANDARD_FIELDS:
        raise SetupError("layout")
    if "listenport" in settings and int(single(settings, "listenport")) != source["ListenPort"]:
        raise SetupError("changed")
    server_secret = single(settings, "privatekey")
    if not B64KEY.fullmatch(server_secret):
        raise SetupError("layout")
    derived = command_bytes(container, [tool, "pubkey"], (server_secret + "\n").encode("ascii")).decode().strip()
    live_key = command_bytes(container, [tool, "show", iface, "public-key"]).decode().strip()
    if derived != live_key or live_key != source.get("ServerKey") or not B64KEY.fullmatch(live_key):
        raise SetupError("changed")
    live = pairs(command_bytes(container, [tool, "show", iface, "allowed-ips"]).decode())
    occupied = networks([" ".join(row) for row in live.values() if row != ["(none)"]])
    for entry in peers:
        occupied.extend(networks(entry.get("allowedips", [])))
    addresses = [ipaddress.ip_interface(addr) for row in settings.get("address", [])
                 for addr in row.replace(",", " ").split()]
    v4 = [address for address in addresses if address.version == 4]
    if len(v4) != 1:
        raise SetupError("subnet")
    exported = {name: single(settings, key) for key, name in AWG_FIELDS.items() if key in settings}
    if any(not re.fullmatch(r"[ -~]{1,4096}", value) for value in exported.values()):
        raise SetupError("layout")
    matches = [entry for entry in peers if entry.get("publickey") == [peer]]
    if len(matches) > 1:
        raise SetupError("changed")
    if matches:
        allowed = ipaddress.ip_network(single(matches[0], "allowedips"), strict=True)
        psk = single(matches[0], "presharedkey")
        if allowed.version != 4 or allowed.prefixlen != 32 or allowed.network_address not in v4[0].network \
                or not B64KEY.fullmatch(psk):
            raise SetupError("changed")
        addr = allowed.network_address
        if peer in live and live[peer] != [str(allowed)]:
            raise SetupError("changed")
        after = before
    else:
        if peer in live:
            raise SetupError("changed")
        addr = client_address(v4[0], occupied)
        psk = base64.b64encode(secrets.token_bytes(32)).decode()
        entry = "\n\n# ThingsNotFun Link\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = {}/32\n"
        after = before.rstrip(b"\r\n") + entry.format(peer, psk, addr).encode("ascii")
        try:
            replace_config(container, path, before, after, keep_backup=True)
        except (SetupError, OSError, subprocess.TimeoutExpired):
            raise SetupError("changed")
    if peer not in live:
        try:
            command_bytes(container, [tool, "set", iface, "peer", peer, "preshared-key", "/dev/stdin",
                                      "allowed-ips", str(addr) + "/32"], (psk + "\n").encode())
            applied = pairs(command_bytes(container, [tool, "show", iface, "allowed-ips"]).decode())
            if applied.get(peer) != [str(addr) + "/32"]:
                raise SetupError("apply")
        except (SetupError, OSError, subprocess.TimeoutExpired):
            if after != before:
                try:
                    replace_config(container, path, after, before)
                    command_bytes(container, [tool, "set", iface, "peer", peer, "remove"])
                except (SetupError, OSError, subprocess.TimeoutExpired):
                    raise SetupError("rollback")
            raise SetupError("apply")
    return {"Address": str(addr), "ServerKey": live_key, "PresharedKey": psk, "Settings": exported}


def provision(req):
    import fcntl

    peer = req.get("Peer", "")
    source_id = req.get("Id", "")
    if not isinstance(peer, str) or not B64KEY.fullmatch(peer):
        return {"Error": "key"}
    source = next((s for s in (INVENTORY or {}).get("Sources", []) if s["Id"] == source_id), None)
    if not source or not source.get("CanProvision"):
        return {"Error": "layout"}
    path = managed_config(source["Container"], source["Interface"], source["Tool"], source["Label"])
    if not path:
        return {"Error": "layout"}
    tag = hashlib.sha256(source_id.encode()).hexdigest()[:32]
    lock = "/run/lock/thingsnotfun-awg-" + tag
    try:
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "rb") as handle:
            if os.fstat(fd).st_uid != os.geteuid():
                return {"Error": "permission"}
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return provision_locked(source, peer, path)
    except SetupError as error:
        return {"Error": str(error)}
    except BlockingIOError:
        return {"Error": "busy"}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"Error": "permission"}
