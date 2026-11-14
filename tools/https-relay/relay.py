"""Authenticated HTTP upgrade from a local reverse proxy to the local SSH server."""
import argparse
import asyncio
import base64
import binascii
import hashlib
import hmac
import re
import struct
from pathlib import Path

MAX_CLIENTS = 16
HEADER_LIMIT = 8192
RESPONSE = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tfl-ssh\r\n\r\n"
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
FRAME_LIMIT = 1024 * 1024


class WebSocket:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.lock = asyncio.Lock()

    async def send(self, opcode, data):
        length = len(data)
        head = bytes((0x80 | opcode, length)) if length < 126 else (
            bytes((0x80 | opcode, 126)) + struct.pack('!H', length) if length < 65536 else
            bytes((0x80 | opcode, 127)) + struct.pack('!Q', length))
        async with self.lock:
            self.writer.write(head + data)
            await self.writer.drain()

    async def receive_to(self, target):
        fragmented = False
        while True:
            first, second = await self.reader.readexactly(2)
            final, opcode, length = bool(first & 128), first & 15, second & 127
            if first & 112 or not second & 128 or opcode not in (0, 2, 8, 9, 10):
                raise ValueError('Invalid WebSocket frame')
            if opcode >= 8 and (not final or length > 125):
                raise ValueError('Invalid control frame')
            if length == 126:
                length = struct.unpack('!H', await self.reader.readexactly(2))[0]
                if length < 126: raise ValueError('Noncanonical frame')
            elif length == 127:
                length = struct.unpack('!Q', await self.reader.readexactly(8))[0]
                if length < 65536: raise ValueError('Noncanonical frame')
            if length > FRAME_LIMIT: raise ValueError('Frame too large')
            mask = await self.reader.readexactly(4)
            data = bytearray(await self.reader.readexactly(length))
            for i in range(length): data[i] ^= mask[i % 4]
            if opcode == 8:
                await self.send(8, b'\x03\xe8')
                return
            if opcode == 9:
                await self.send(10, data)
                continue
            if opcode == 10: continue
            if (opcode == 0) != fragmented: raise ValueError('Invalid continuation')
            fragmented = not final
            target.write(data)
            await target.drain()

    async def send_from(self, reader):
        while data := await reader.read(32768):
            await self.send(2, data)
        await self.send(8, b'\x03\xe8')


async def reject(writer, code):
    writer.write(f"HTTP/1.1 {code}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode("ascii"))
    await writer.drain()


async def copy(reader, writer):
    while data := await reader.read(32768):
        writer.write(data)
        await writer.drain()
    if writer.can_write_eof():
        writer.write_eof()


class Relay:
    def __init__(self, token, path, ssh_port):
        self.authorization = b"Bearer " + token
        self.request = b"GET " + path.encode("ascii") + b" HTTP/1.1"
        self.ssh_port = ssh_port
        self.clients = 0

    async def handle(self, reader, writer):
        target = None
        tasks = ()
        try:
            if self.clients >= MAX_CLIENTS:
                await reject(writer, "503 Service Unavailable")
                return
            self.clients += 1
            try:
                request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                lines = request[:-4].split(b"\r\n")
                if lines[0] != self.request:
                    await reject(writer, "404 Not Found")
                    return
                headers = {}
                for line in lines[1:]:
                    key, sep, value = line.partition(b":")
                    key = key.lower()
                    if not sep or key in headers:
                        await reject(writer, "400 Bad Request")
                        return
                    headers[key] = value.strip()
                if not hmac.compare_digest(headers.get(b"authorization", b""), self.authorization):
                    await reject(writer, "401 Unauthorized")
                    return
                connection = headers.get(b"connection", b"").lower().split(b",")
                websocket = headers.get(b"upgrade", b"").lower() == b"websocket"
                if (b"upgrade" not in [part.strip() for part in connection] or
                        headers.get(b"upgrade", b"").lower() not in (b"tfl-ssh", b"websocket") or
                        headers.get(b"content-length", b"0") != b"0" or b"transfer-encoding" in headers):
                    await reject(writer, "400 Bad Request")
                    return
                response = RESPONSE
                if websocket:
                    key = headers.get(b"sec-websocket-key", b"")
                    try:
                        if headers.get(b"sec-websocket-version") != b"13" or len(base64.b64decode(key, validate=True)) != 16:
                            raise ValueError('Invalid handshake')
                    except (ValueError, binascii.Error):
                        await reject(writer, "400 Bad Request")
                        return
                    accept = base64.b64encode(hashlib.sha1(key + WS_GUID).digest())
                    response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
                try:
                    upstream, target = await asyncio.wait_for(
                        asyncio.open_connection("127.0.0.1", self.ssh_port), 4)
                except (OSError, asyncio.TimeoutError):
                    await reject(writer, "502 Bad Gateway")
                    return
                writer.write(response)
                await writer.drain()
                if websocket:
                    ws = WebSocket(reader, writer)
                    tasks = (asyncio.create_task(ws.receive_to(target)), asyncio.create_task(ws.send_from(upstream)))
                else:
                    tasks = (asyncio.create_task(copy(reader, target)), asyncio.create_task(copy(upstream, writer)))
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                self.clients -= 1
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError, ValueError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            if target is not None:
                target.close()
            writer.close()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)


async def serve(args):
    token = Path(args.token_file).read_bytes().strip()
    if not re.fullmatch(rb"[A-Za-z0-9_-]{43}", token):
        raise ValueError("Invalid HTTPS relay token")
    if not re.fullmatch(r"/[A-Za-z0-9/_-]{1,128}", args.path):
        raise ValueError("Invalid HTTPS relay path")
    relay = Relay(token, args.path, args.ssh_port)
    server = await asyncio.start_server(relay.handle, "127.0.0.1", args.listen_port, limit=HEADER_LIMIT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--path", default="/link-ssh")
    parser.add_argument("--listen-port", type=int, default=18091)
    parser.add_argument("--ssh-port", type=int, default=22)
    asyncio.run(serve(parser.parse_args()))
