import asyncio
import base64
import importlib.util
import pathlib
import struct
import unittest

spec = importlib.util.spec_from_file_location('relay', pathlib.Path(__file__).resolve().parents[1] / 'tools/https-relay/relay.py')
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.upstream_connections = 0
        async def echo(reader, writer):
            self.upstream_connections += 1
            try:
                await relay.copy(reader, writer)
            finally:
                writer.close()
                await writer.wait_closed()
        self.echo = await asyncio.start_server(echo, '127.0.0.1', 0)
        self.handler = relay.Relay(b'a' * 43, '/link-ssh', self.echo.sockets[0].getsockname()[1])
        self.server = await asyncio.start_server(self.handler.handle, '127.0.0.1', 0, limit=8192)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        self.echo.close()
        await self.server.wait_closed()
        await self.echo.wait_closed()

    async def connect(self, authorized=True, websocket=True):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        protocol = b'websocket' if websocket else b'tfl-ssh'
        token = b'a' * 43 if authorized else b'b' * 43
        writer.write(b'GET /link-ssh HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: ' + protocol +
                     b'\r\nAuthorization: Bearer ' + token + b'\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n')
        await writer.drain()
        return reader, writer, await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2)

    def frame(self, data, opcode=2, final=True):
        mask = b'1234'
        n = len(data)
        head = bytes([(128 if final else 0) | opcode, 128 | (n if n < 126 else 126)])
        if n >= 126: head += struct.pack('!H', n)
        return head + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(data))

    async def read_frame(self, reader):
        a, b = await asyncio.wait_for(reader.readexactly(2), 2)
        self.assertFalse(b & 128)
        n = b & 127
        if n == 126: n = struct.unpack('!H', await reader.readexactly(2))[0]
        if n == 127: n = struct.unpack('!Q', await reader.readexactly(8))[0]
        return a & 15, await reader.readexactly(n)

    async def test_auth_precedes_ssh(self):
        reader, writer, header = await self.connect(authorized=False)
        self.assertIn(b'401', header)
        self.assertEqual(self.upstream_connections, 0)
        writer.close()
        await writer.wait_closed()

    async def test_binary_fragments_ping_and_large_payload(self):
        reader, writer, header = await self.connect()
        self.assertIn(b's3pPLMBiTxaQ9kYGzzhZRbK+xOo=', header)
        payload = bytes(range(256)) * 200
        writer.write(self.frame(payload[:100], final=False) + self.frame(b'ping', opcode=9) + self.frame(payload[100:], opcode=0))
        await writer.drain()
        received = bytearray()
        pong = False
        while len(received) < len(payload) or not pong:
            opcode, data = await self.read_frame(reader)
            if opcode == 10:
                self.assertEqual(data, b'ping')
                pong = True
            else:
                self.assertEqual(opcode, 2)
                received.extend(data)
        self.assertEqual(received, payload)
        writer.write(self.frame(b'', opcode=8))
        await writer.drain()
        self.assertEqual((await self.read_frame(reader))[0], 8)
        writer.close()
        await writer.wait_closed()

    async def test_existing_raw_upgrade(self):
        reader, writer, header = await self.connect(websocket=False)
        self.assertIn(b'Upgrade: tfl-ssh', header)
        writer.write(b'SSH-2.0-fixture\r\n')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readline(), 2), b'SSH-2.0-fixture\r\n')
        writer.close()
        await writer.wait_closed()

    async def test_unmasked_client_frame_is_rejected(self):
        reader, writer, _ = await self.connect()
        writer.write(b'\x82\x03bad')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b'')
        writer.close()
        await writer.wait_closed()


if __name__ == '__main__':
    unittest.main()
