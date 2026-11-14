"""Ephemeral server half of TFL/1. Runs on OpenSSH stdin/stdout."""
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time

MAX_FRAME = 65535
MAX_UDP = 65507
HEADER = struct.Struct("!IB")
WRITE = threading.Lock()
CONTROL = threading.Lock()
UDP = None
STOP = threading.Event()
INVENTORY = None
IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z")
B64KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")


def send(kind, data=b""):
    if len(data) > MAX_FRAME:
        raise ValueError("frame")
    with WRITE:
        sys.stdout.buffer.write(HEADER.pack(len(data), ord(kind)) + data)
        sys.stdout.buffer.flush()


def reply(kind, obj):
    data = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_FRAME:
        data = b'{"Error":"inventory_size"}'
    send(kind, data)


def run(*args):
    try:
        out = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=3, check=False)
        if out.returncode == 0:
            return out.stdout[:12000].decode("utf-8", "replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def first(s):
    return (s or "").split("\n", 1)[0][:160]


def read_os():
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line[12:].strip().strip('"')[:160]
    except OSError:
        pass
    return sys.platform


def local_udp_test():
    payload = secrets.token_bytes(24)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(1)
        tx.settimeout(1)
        tx.sendto(payload, rx.getsockname())
        packet, addr = rx.recvfrom(128)
        rx.sendto(packet, addr)
        return tx.recvfrom(128)[0] == payload


def prefix_for(container):
    return ["docker", "exec", container] if container else []


def probe_vpn(container, ports, label=""):
    prefix = prefix_for(container)
    # Never request dump/private-key/preshared-keys, container env, or process arguments.
    for tool in ("awg", "wg"):
        listed = run(*prefix, tool, "show", "interfaces")
        if listed is None or (not listed and tool == "awg"):
            continue
        sources = []
        for iface in listed.split()[:8]:
            if not IDENTIFIER.fullmatch(iface):
                continue
            listen = run(*prefix, tool, "show", iface, "listen-port") or ""
            if not listen.isdecimal() or not 0 < int(listen) <= 65535:
                continue
            mapped = [p for p in ports if p["Inside"] == int(listen)] if container else [
                {"Host": "127.0.0.1", "Port": int(listen), "Inside": int(listen)}
            ]
            peer_keys = (run(*prefix, tool, "show", iface, "peers") or "").split()
            server_key = run(*prefix, tool, "show", iface, "public-key") or ""
            can_provision = bool(mapped and B64KEY.fullmatch(server_key) and managed_config(container, iface, tool, label))
            sources.append({
                "Id": (container or "host") + ":" + iface,
                "Container": container, "Interface": iface, "Tool": tool,
                "ListenPort": int(listen), "Ports": mapped,
                "Label": label or iface, "ServerKey": server_key, "CanProvision": can_provision,
                "PeerCount": sum(1 for key in peer_keys if B64KEY.fullmatch(key)),
                "PeerKeys": [key for key in peer_keys[:32] if B64KEY.fullmatch(key)],
            })
        if sources or tool == "wg":
            return first(run(*prefix, tool, "--version")), sources
    return "", []


def bindings(container):
    raw = run("docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", container)
    try:
        data = json.loads(raw or "{}") or {}
    except ValueError:
        return []
    results = []
    for k, records in list(data.items())[:32]:
        port, _, kind = k.partition("/")
        if kind != "udp" or not port.isdecimal():
            continue
        for record in (records or [])[:8]:
            try:
                host = ipaddress.ip_address(record["HostIp"])
                if host.is_unspecified:
                    host = ipaddress.ip_address("127.0.0.1" if host.version == 4 else "::1")
                external = int(record["HostPort"])
                if 0 < external <= 65535:
                    results.append({"Host": str(host), "Port": external, "Inside": int(port)})
            except (KeyError, ValueError):
                pass
    return results


def inventory():
    global INVENTORY
    details = []
    for args in (("ip", "-brief", "address"), ("ip", "-4", "route", "show"), ("ip", "-6", "route", "show"),
                 ("ss", "-H", "-uln")):
        text = run(*args)
        details.append(" ".join(args) + ":\n" + ("\n".join((text or "").splitlines()[:14])[:1500] or "—"))
    details += ["OS: " + read_os(), "Kernel: " + first(run("uname", "-r")), "Python: " + sys.version.split()[0]]
    for exe in ("openvpn", "xray"):
        ver = first(run(exe, "--version" if exe == "openvpn" else "version"))
        if ver:
            details.append(ver)
    version, sources = probe_vpn("", [])
    ports = [p for s in sources for p in s["Ports"]]
    if version:
        details.append(version)
    raw = run("docker", "ps", "--format", "{{json .}}")
    docker = raw is not None
    if docker:
        details.append("Docker: " + (first(run("docker", "--version")) or "OK"))
    for line in (raw or "").splitlines()[:12]:
        try:
            row = json.loads(line)
            name = str(row.get("Names", ""))[:80]
            cid = str(row.get("ID", ""))[:64]
            image = str(row.get("Image", ""))[:160]
            published = str(row.get("Ports", ""))[:220]
        except (ValueError, AttributeError):
            continue
        details.append("Docker: " + name + " | " + image + " | " + published)
        if not re.fullmatch(r"[a-f0-9]{12,64}", cid):
            continue
        match = (name + " " + image).lower()
        if not any(x in match for x in ("awg", "amnezia", "wireguard")) and "/udp" not in published:
            continue
        mapped = bindings(cid)
        version, found = probe_vpn(cid, mapped, name)
        sources.extend(found)
        # A VPN-named container may have no CLI; its mapped UDP can still be used.
        if found:
            ports.extend(p for s in found for p in s["Ports"])
        elif any(x in match for x in ("awg", "wireguard")):
            ports.extend(mapped)
        if version:
            details.append(name + " | " + version)
    if not docker:
        details.append("Docker: недоступен этой учётной записи или не установлен.")
    for s in sources:
        details.append(s["Id"] + " | " + s["Tool"] + " UDP " + str(s["ListenPort"]) +
                       " | peers: " + str(s["PeerCount"]))
    try:
        checked = local_udp_test()
    except OSError:
        checked = False
    INVENTORY = {"UdpEcho": checked, "Details": "\n".join(details)[:12000],
                 "Sources": sources[:24], "Ports": ports[:128]}
    return INVENTORY


def pairs(text):
    if text is None:
        return {}
    return {row[0]: row[1:] for line in text.splitlines() if (row := line.split()) and B64KEY.fullmatch(row[0])}


def telemetry(req):
    source_id = req.get("Id", "")
    sources = (INVENTORY or {}).get("Sources", [])
    source = next((s for s in sources if s["Id"] == source_id), None)
    if not source:
        return {"Error": "source"}
    key = req.get("Peer", "")
    if not isinstance(key, str) or not B64KEY.fullmatch(key):
        return {"Error": "peer"}
    prefix = prefix_for(source["Container"])
    tool, iface = source["Tool"], source["Interface"]
    hand = pairs(run(*prefix, tool, "show", iface, "latest-handshakes")).get(key)
    traffic = pairs(run(*prefix, tool, "show", iface, "transfer")).get(key)
    if not hand or not traffic or len(traffic) != 2:
        return {"Error": "peer_stats"}
    try:
        now = int(time.time())
        epoch, rx, tx = int(hand[0]), int(traffic[0]), int(traffic[1])
        if min(epoch, rx, tx) < 0:
            return {"Error": "peer_stats"}
        return {"Now": now, "Handshake": epoch, "Rx": rx, "Tx": tx}
    except (ValueError, IndexError):
        return {"Error": "peer_stats"}


def configure(data):
    global UDP
    try:
        req = json.loads(data)
        target = ipaddress.ip_address(req["Host"])
        port = req["Port"]
        if target.is_unspecified or target.is_multicast or str(target) == "255.255.255.255" or not 1 <= port <= 65535:
            raise ValueError()
        sock = socket.socket(socket.AF_INET if target.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            sock.connect((str(target), port))
            sock.settimeout(0.2)
        except BaseException:
            sock.close()
            raise
        if UDP:
            UDP.close()
        UDP = sock
        reply("S", {"Ready": True})
    except (OSError, ValueError, KeyError, TypeError):
        reply("S", {"Error": "target"})


def control(kind, data):
    try:
        if kind == "I":
            result = inventory()
        elif kind == "C":
            result = provision(json.loads(data))
        elif kind == "G":
            result = gateway_install(json.loads(data))
        else:
            result = telemetry(json.loads(data))
        reply(kind, result)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, IndexError, ImportError):
        reply(kind, {"Error": "inspection"})
    finally:
        CONTROL.release()


def dispatch(kind, data):
    if kind == "D" and UDP is not None and 0 < len(data) <= MAX_UDP:
        try:
            UDP.send(data)
        except (BlockingIOError, ConnectionRefusedError, socket.timeout):
            pass
    elif kind == "P" and len(data) == 8:
        send("P", data)
    elif kind == "S" and len(data) < 1024:
        configure(data)
    elif (kind in ("I", "T", "C") and len(data) < 1024) or (kind == "G" and len(data) < 8192):
        if CONTROL.acquire(blocking=False):
            threading.Thread(target=control, args=(kind, data), daemon=kind not in ("C", "G")).start()
        else:
            reply(kind, {"Error": "busy"})
    else:
        raise ValueError("frame type")


def udp_receive():
    while not STOP.is_set():
        sock = UDP
        if sock is None:
            STOP.wait(0.05)
            continue
        try:
            data = sock.recv(MAX_UDP)
            if data and sock is UDP and not STOP.is_set():
                send("D", data)
        except (BlockingIOError, ConnectionRefusedError, socket.timeout):
            pass
        except OSError:
            if sock is UDP and not STOP.is_set():
                STOP.wait(0.05)


def main():
    send("H", b"TFL/1")
    worker = threading.Thread(target=udp_receive, daemon=True)
    worker.start()
    try:
        while True:
            header = sys.stdin.buffer.read(HEADER.size)
            if not header:
                return
            size, kind = HEADER.unpack(header)
            if size > MAX_FRAME:
                raise ValueError("frame length")
            data = sys.stdin.buffer.read(size)
            if len(data) != size:
                raise ValueError("truncated frame")
            dispatch(chr(kind), data)
    finally:
        STOP.set()
        if UDP is not None:
            UDP.close()
        worker.join(0.5)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, struct.error):
        sys.exit(1)
