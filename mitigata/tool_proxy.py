"""GET-only HTTP proxy for reviewed crawlers. CONNECT is deliberately rejected."""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from .scope import ScopeDenied


class ToolProxy:
    def __init__(self, context):
        self.context = context
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle, "127.0.0.1", self.context.manifest.tools.proxy_port, limit=16384
        )

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def handle(self, reader, writer):
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            line = header.split(b"\r\n", 1)[0].decode("ascii")
            method, url, version = line.split(" ")
            if method != "GET" or version not in {"HTTP/1.0", "HTTP/1.1"} or urlsplit(url).scheme != "http":
                raise ScopeDenied(
                    "Tool proxy permits absolute HTTP GET only; HTTPS uses the brokered browser"
                )
            response = await self.context.broker.http(url, follow_redirects=False)
            headers = {
                k: v
                for k, v in response.headers.items()
                if k in {"content-type", "location", "www-authenticate", "server", "x-powered-by"}
            }
            headers.update({"Content-Length": str(len(response.body)), "Connection": "close"})
            head = (
                f"HTTP/1.1 {response.status} Response\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                + "\r\n"
            )
            writer.write(head.encode("latin1") + response.body)
            await writer.drain()
        except (
            ValueError,
            ScopeDenied,
            OSError,
            TimeoutError,
            asyncio.LimitOverrunError,
            asyncio.IncompleteReadError,
        ):
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
