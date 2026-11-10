from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import time
import urllib.parse
from collections import deque
from typing import Any

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class CdpError(RuntimeError):
    pass


class CdpSocket:
    """Minimal RFC 6455 WebSocket + CDP client using Python standard library only.

    Explicitly omits any `Origin` header during the HTTP Upgrade handshake to avoid
    Chromium remote-allow-origins rejection.
    """

    def __init__(self, ws_url: str, timeout: float = 5.0) -> None:
        u = urllib.parse.urlsplit(ws_url)
        if u.scheme != "ws" or u.hostname != "127.0.0.1" or not u.port:
            raise CdpError(f"refuse non-loopback ws: {ws_url}")
        self.ws_url = ws_url
        self.sock = socket.create_connection((u.hostname, u.port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = u.path or "/"
        if u.query:
            path = f"{path}?{u.query}"
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{u.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode("ascii"))
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise CdpError("handshake EOF")
            self.buf += chunk
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        if " 101 " not in lines[0] + " ":
            raise CdpError(f"handshake status: {lines[0]}")
        hdrs = {
            line.split(":", 1)[0].strip().lower(): line.split(":", 1)[1].strip()
            for line in lines[1:]
            if ":" in line
        }
        expect = base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")
        if hdrs.get("sec-websocket-accept") != expect:
            raise CdpError("bad Sec-WebSocket-Accept")
        self._id = 0
        self.events: deque[dict[str, Any]] = deque()
        self._frag_parts: list[bytes] = []

    def _exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise CdpError("socket EOF")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        hdr = bytes([0x80 | (opcode & 0x0F)])
        n = len(payload)
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack("!Q", n)
        mask = os.urandom(4)
        masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(hdr + mask + masked_payload)

    def recv_message(self) -> dict[str, Any]:
        while True:
            consumed = bytearray()
            try:
                head = self._exact(2)
                consumed.extend(head)
                b0, b1 = head[0], head[1]
                fin = b0 & 0x80
                op = b0 & 0x0F
                masked = b1 & 0x80
                n = b1 & 0x7F
                if masked:
                    raise CdpError("server frame must not be masked")
                if n == 126:
                    ext = self._exact(2)
                    consumed.extend(ext)
                    n = struct.unpack("!H", ext)[0]
                elif n == 127:
                    ext = self._exact(8)
                    consumed.extend(ext)
                    n = struct.unpack("!Q", ext)[0]
                data = self._exact(n)
            except (socket.timeout, TimeoutError, BlockingIOError):
                if consumed:
                    self.buf = bytes(consumed) + self.buf
                raise
            if op == 0x9:
                self._send_frame(0xA, data)
                continue
            if op == 0xA:
                continue
            if op == 0x8:
                raise CdpError("closed by peer")
            if op in (0x1, 0x0):
                self._frag_parts.append(data)
            if fin and self._frag_parts:
                raw = b"".join(self._frag_parts)
                self._frag_parts.clear()
                try:
                    return json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as e:
                    raise CdpError(f"invalid CDP JSON payload: {e}") from e

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = 10.0) -> dict[str, Any]:
        self._id += 1
        mid = self._id
        payload = json.dumps({"id": mid, "method": method, "params": params or {}}).encode("utf-8")
        self._send_frame(0x1, payload)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.sock.settimeout(max(0.1, deadline - time.monotonic()))
            msg = self.recv_message()
            if msg.get("id") == mid:
                if "error" in msg:
                    raise CdpError(f"{method}: {msg['error']}")
                return msg.get("result", {})
            self.events.append(msg)
        raise CdpError(f"{method}: timeout")

    def poll_events(self, timeout: float) -> list[dict[str, Any]]:
        self.sock.settimeout(timeout)
        try:
            while True:
                self.events.append(self.recv_message())
                self.sock.settimeout(0.0)
        except (socket.timeout, TimeoutError, BlockingIOError):
            pass
        finally:
            try:
                self.sock.settimeout(5.0)
            except OSError:
                pass
        out = list(self.events)
        self.events.clear()
        return out

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        finally:
            try:
                self.sock.close()
            except OSError:
                pass
