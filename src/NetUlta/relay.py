"""Ephemeral server half of TFL/1. Runs on OpenSSH stdin/stdout."""
from collections import deque
import gzip
import ipaddress
import io
import json
import os
import re
import select
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import tempfile

MAX_FRAME = 65535
MAX_UDP = 65507
UDP_RECEIVE_BUFFER = 256 * 1024
UDP_QUEUE_BYTES = 128 * 1024
UDP_QUEUE_PACKETS = 128
UDP_MAX_QUEUE_AGE = 0.1
HEADER = struct.Struct("!IB")
WRITE = threading.Lock()
CONTROL = threading.Lock()
UDP = None
STOP = threading.Event()
INVENTORY = None
IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z")
B64KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
QUIC_IMAGE = bytearray()
QUIC = None


def write_frame(kind, data):
    if len(data) > MAX_FRAME:
        raise ValueError("frame")
    sys.stdout.buffer.write(HEADER.pack(len(data), ord(kind)) + data)
    sys.stdout.buffer.flush()


def send(kind, data=b""):
    with WRITE:
        write_frame(kind, data)


class DatagramQueue:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.ready = threading.Condition()
        self.items = deque()
        self.size = 0
        self.closed = False

    def discard_first(self):
        item = self.items.popleft()
        self.size -= len(item[2])
        return item

    def expire(self, now):
        while self.items and now - self.items[0][0] >= UDP_MAX_QUEUE_AGE:
            self.discard_first()

    def put(self, sock, data):
        with self.ready:
            if self.closed:
                return
            now = self.clock()
            self.expire(now)
            while len(self.items) >= UDP_QUEUE_PACKETS or self.size + len(data) > UDP_QUEUE_BYTES:
                self.discard_first()
            self.items.append((now, sock, data))
            self.size += len(data)
            self.ready.notify()

    def get(self):
        with self.ready:
            while not self.closed:
                self.expire(self.clock())
                if self.items:
                    return self.discard_first()
                self.ready.wait()
            return None

    def close(self):
        with self.ready:
            self.closed = True
            self.items.clear()
            self.size = 0
            self.ready.notify_all()


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


def udp_destination(host, port):
    """Avoid Docker's lossy userland UDP hop, only for a verified local binding.

    Reinspect on each connection: a container IP saved in an invitation can become
    stale. Ambiguous/missing/non-bridge networks retain the published endpoint.
    No routes, Docker settings or firewall rules are changed.
    """
    original = (str(host), port)
    if not host.is_loopback or host.version != 4:
        return original
    matches = set()
    for source in (INVENTORY or {}).get("Sources", []):
        cid = source.get("Container", "")
        if not isinstance(cid, str) or not re.fullmatch(r"[a-f0-9]{12,64}", cid):
            continue
        for binding in source.get("Ports", []):
            inside = binding.get("Inside")
            if (binding.get("Host") == str(host) and binding.get("Port") == port and
                    isinstance(inside, int) and 0 < inside <= 65535):
                matches.add((cid, inside))
    if len(matches) != 1:
        return original
    cid, inside = next(iter(matches))
    if not any(b["Host"] == str(host) and b["Port"] == port and b["Inside"] == inside for b in bindings(cid)):
        return original
    try:
        networks = json.loads(run("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", cid) or "null")
        if not isinstance(networks, dict) or not networks:
            return original
        if len(networks) == 1:
            network = next(iter(networks.values()))
        else:
            # Amnezia also attaches a DNS network. Prefer the explicitly
            # configured primary network rather than guessing by dictionary order.
            mode = run("docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", cid)
            if mode == "default": mode = "bridge"
            selected = [value for name, value in networks.items() if isinstance(value, dict) and
                        (name == mode or value.get("NetworkID") == mode)]
            if len(selected) != 1:
                return original
            network = selected[0]
        network_id = network.get("NetworkID", "")
        if not isinstance(network_id, str) or not re.fullmatch(r"[a-f0-9]{64}", network_id):
            return original
        address = ipaddress.ip_address(network.get("IPAddress", ""))
        gateway = ipaddress.ip_address(network.get("Gateway", ""))
        if (address.version != 4 or gateway.version != 4 or
                any(ip.is_unspecified or ip.is_loopback or ip.is_multicast or
                    str(ip) == "255.255.255.255" for ip in (address, gateway))):
            return original
        if run("docker", "network", "inspect", "--format", "{{.Driver}}", network_id) != "bridge":
            return original
        # Require a local on-link route, not an external gateway. This checks
        # routing only; site-specific firewall rules can still reject UDP.
        route = json.loads(run("ip", "-j", "route", "get", str(address)) or "null")
        if not isinstance(route, list) or len(route) != 1 or route[0].get("prefsrc") != str(gateway) or route[0].get("gateway"):
            return original
        return str(address), inside
    except (ValueError, TypeError, AttributeError, KeyError):
        return original


def configure(data):
    global UDP
    try:
        req = json.loads(data)
        target = ipaddress.ip_address(req["Host"])
        port = req["Port"]
        if target.is_unspecified or target.is_multicast or str(target) == "255.255.255.255" or not 1 <= port <= 65535:
            raise ValueError()
        destination = udp_destination(target, port)
        sock = socket.socket(socket.AF_INET if target.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECEIVE_BUFFER)
            sock.connect(destination)
            sock.settimeout(0.2)
        except BaseException:
            sock.close()
            raise
        if UDP:
            UDP.close()
        UDP = sock
        reply("S", {"Ready": True, "Destination": str(destination[0]) + ":" + str(destination[1])})
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
        elif kind == "J":
            result = sharing(json.loads(data))
        else:
            result = telemetry(json.loads(data))
        reply(kind, result)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, IndexError, ImportError):
        reply(kind, {"Error": "inspection"})
    finally:
        CONTROL.release()


def start_quic(data):
    global QUIC
    if UDP is None or QUIC is not None or not QUIC_IMAGE or not re.fullmatch(b"[A-F0-9]{64}", data):
        reply("Q", {"Error": "quic request"})
        return
    try:
        host, port = UDP.getpeername()[:2]
        target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        limit = 20 * 1024 * 1024
        with gzip.GzipFile(fileobj=io.BytesIO(QUIC_IMAGE)) as blob:
            image = blob.read(limit + 1)
        QUIC_IMAGE.clear()
        if not image.startswith(b"\x7fELF") or len(image) > limit:
            raise ValueError("bad server binary")
        with tempfile.TemporaryDirectory(prefix="vpslink-quic-") as private:
            path = os.path.join(private, "bridge")
            with open(path, "wb") as out:
                out.write(image)
            os.chmod(path, 0o700)
            QUIC = subprocess.Popen([path, "server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, cwd=private)
            os.unlink(path)
        with QUIC.stdin as pipe:
            pipe.write(json.dumps({"Key": data.decode("ascii"), "Target": target}).encode("ascii") + b"\n")
        if not select.select([QUIC.stdout], [], [], 5)[0]:
            raise TimeoutError("QUIC listener startup")
        ready = QUIC.stdout.readline(512)
        if not ready:
            raise ValueError("QUIC listener refused")
        reply("Q", json.loads(ready))
    except (OSError, ValueError, EOFError):
        QUIC_IMAGE.clear()
        stop_quic()
        reply("Q", {"Error": "quic startup"})


def stop_quic():
    global QUIC
    process, QUIC = QUIC, None
    if process is None:
        return
    try:
        if process.poll() is None:
            process.terminate()
        process.wait(2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    finally:
        process.stdout.close()


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
    elif kind == "B" and QUIC is None and len(QUIC_IMAGE) + len(data) <= 8 * 1024 * 1024:
        QUIC_IMAGE.extend(data)
    elif kind == "Q":
        start_quic(data)
    elif (kind in ("I", "T", "C") and len(data) < 1024) or (kind in ("G", "J") and len(data) < 8192):
        if CONTROL.acquire(blocking=False):
            threading.Thread(target=control, args=(kind, data), daemon=kind not in ("C", "G", "J")).start()
        else:
            reply(kind, {"Error": "busy"})
    else:
        raise ValueError("frame type")


def udp_receive(queue):
    while not STOP.is_set():
        sock = UDP
        if sock is None:
            STOP.wait(0.05)
            continue
        try:
            data = sock.recv(MAX_UDP)
            if data and sock is UDP and not STOP.is_set():
                queue.put(sock, data)
        except (BlockingIOError, ConnectionRefusedError, socket.timeout):
            pass
        except OSError:
            if sock is UDP and not STOP.is_set():
                STOP.wait(0.05)


def udp_write(queue):
    try:
        while item := queue.get():
            queued_at, sock, data = item
            with WRITE:
                # Recheck age after waiting for the control frames and the previous write.
                if sock is UDP and not STOP.is_set() and queue.clock() - queued_at < UDP_MAX_QUEUE_AGE:
                    write_frame("D", data)
    except OSError:
        STOP.set()
        queue.close()


def main():
    send("H", b"TFL/1")
    queue = DatagramQueue()
    reader = threading.Thread(target=udp_receive, args=(queue,), daemon=True)
    writer = threading.Thread(target=udp_write, args=(queue,), daemon=True)
    reader.start()
    writer.start()
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
        stop_quic()
        queue.close()
        if UDP is not None:
            UDP.close()
        reader.join(0.5)
        writer.join(0.5)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, struct.error):
        sys.exit(1)
