from __future__ import annotations

import json
import logging
import socket
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable


LOG = logging.getLogger(__name__)


class BridgeError(RuntimeError):
    """Raised when the x64dbg bridge is unavailable or rejects a request."""


@dataclass
class PendingCall:
    event: threading.Event = field(default_factory=threading.Event)
    result: Any | None = None
    error: str | None = None


class BridgeConnection:
    def __init__(self, sock: socket.socket, peer: tuple[str, int], event_limit: int) -> None:
        self.sock = sock
        self.peer = peer
        self.event_limit = event_limit
        self.session_id: str | None = None
        self.hello: dict[str, Any] = {}
        self.connected_at = time.time()
        self.last_seen = self.connected_at
        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._closed = False
        self._pending: dict[str, PendingCall] = {}
        self._events: deque[dict[str, Any]] = deque(maxlen=event_limit)
        self._reader = threading.Thread(target=self._reader_loop, name=f"x64dbg-bridge-{peer[1]}", daemon=True)
        self._on_close: Callable | None = None
        self._on_hello: Callable | None = None

    def start(self, on_hello: Callable, on_close: Callable) -> None:
        self._on_hello = on_hello
        self._on_close = on_close
        self._reader.start()

    def describe(self) -> dict[str, Any]:
        info = dict(self.hello)
        info.setdefault("peer_host", self.peer[0])
        info.setdefault("peer_port", self.peer[1])
        info.setdefault("connected_at", self.connected_at)
        info.setdefault("last_seen", self.last_seen)
        info.setdefault("session_id", self.session_id)
        info.setdefault("pending_events", len(self._events))
        return info

    def poll_events(self, limit: int = 50, clear: bool = True) -> list[dict[str, Any]]:
        with self._state_lock:
            items = list(self._events)[:limit]
            if clear:
                for _ in range(len(items)):
                    self._events.popleft()
            return items

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = 20.0) -> Any:
        if timeout <= 0:
            raise BridgeError("timeout must be > 0")
        request_id = str(uuid.uuid4())
        pending = PendingCall()
        with self._state_lock:
            if self._closed:
                raise BridgeError("bridge connection is closed")
            self._pending[request_id] = pending
        self._send(
            {
                "type": "request",
                "id": request_id,
                "method": method,
                "params": params or {},
            }
        )
        if not pending.event.wait(timeout):
            with self._state_lock:
                self._pending.pop(request_id, None)
            raise BridgeError(f"request timed out after {timeout:.1f}s")
        if pending.error:
            raise BridgeError(pending.error)
        return pending.result

    def close(self) -> None:
        self._mark_closed("closed by server")

    def _send(self, payload: dict[str, Any]) -> None:
        raw = (json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
        with self._send_lock:
            try:
                self.sock.sendall(raw)
            except OSError as exc:
                self._mark_closed(f"send failed: {exc}")
                raise BridgeError("failed to send request to x64dbg bridge") from exc

    def _reader_loop(self) -> None:
        buffer = b""
        try:
            while True:
                chunk = self.sock.recv(65536)
                if not chunk:
                    self._mark_closed("socket closed")
                    return
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    self._handle_line(line)
        except OSError as exc:
            self._mark_closed(f"recv failed: {exc}")

    def _handle_line(self, line: bytes) -> None:
        self.last_seen = time.time()
        try:
            message = json.loads(line.decode("utf-8"))
        except Exception as exc:
            LOG.warning("dropping malformed bridge payload from %s: %s", self.peer, exc)
            return
        kind = message.get("type")
        if kind == "hello":
            session_id = str(message.get("session_id") or "")
            if not session_id:
                LOG.warning("bridge hello missing session_id from %s", self.peer)
                return
            self.session_id = session_id
            self.hello = message
            if self._on_hello:
                self._on_hello(self)
            return
        if kind == "event":
            with self._state_lock:
                self._events.append(message)
            return
        if kind == "response":
            request_id = str(message.get("id") or "")
            with self._state_lock:
                pending = self._pending.pop(request_id, None)
            if pending is None:
                return
            if message.get("ok", False):
                pending.result = message.get("result")
            else:
                pending.error = str(message.get("error") or "bridge request failed")
            pending.event.set()
            return
        LOG.debug("ignoring unknown bridge message kind %r", kind)

    def _mark_closed(self, reason: str) -> None:
        callbacks: list[PendingCall] = []
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            callbacks = list(self._pending.values())
            self._pending.clear()
        for pending in callbacks:
            pending.error = f"bridge disconnected: {reason}"
            pending.event.set()
        try:
            self.sock.close()
        except OSError:
            pass
        if self._on_close:
            self._on_close(self)


class SessionRegistry:
    def __init__(self, host: str = "127.0.0.1", port: int = 47063, event_limit: int = 512) -> None:
        self.host = host
        self.port = port
        self.event_limit = event_limit
        self._sessions: dict[str, BridgeConnection] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None

    def start(self) -> None:
        if self._accept_thread:
            return
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen()
        self._sock = server
        self._accept_thread = threading.Thread(target=self._accept_loop, name="x64dbg-bridge-listener", daemon=True)
        self._accept_thread.start()
        LOG.info("listening for x64dbg bridge connections on %s:%s", self.host, self.port)

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._with_server_defaults(conn.describe()) for conn in self._sessions.values()]

    def call(self, session_id: str | None, method: str, params: dict[str, Any] | None = None, timeout: float = 20.0) -> Any:
        conn = self.resolve(session_id)
        return conn.call(method=method, params=params, timeout=timeout)

    def poll_events(self, session_id: str | None, limit: int = 50, clear: bool = True) -> list[dict[str, Any]]:
        conn = self.resolve(session_id)
        return conn.poll_events(limit=limit, clear=clear)

    def resolve(self, session_id: str | None) -> BridgeConnection:
        with self._lock:
            if session_id:
                conn = self._sessions.get(session_id)
                if not conn:
                    raise BridgeError(f"unknown session_id: {session_id}")
                return conn
            if not self._sessions:
                raise BridgeError(
                    f"no x64dbg session is connected to {self.host}:{self.port}; load the plugin inside x64dbg first"
                )
            if len(self._sessions) > 1:
                raise BridgeError("multiple x64dbg sessions are connected; pass session_id explicitly")
            return next(iter(self._sessions.values()))

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, peer = self._sock.accept()
            except OSError:
                return
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn = BridgeConnection(client, peer, self.event_limit)
            conn.start(on_hello=self._register_connection, on_close=self._unregister_connection)

    def _register_connection(self, conn: BridgeConnection) -> None:
        if not conn.session_id:
            return
        with self._lock:
            old = self._sessions.get(conn.session_id)
            self._sessions[conn.session_id] = conn
        if old and old is not conn:
            old.close()
        LOG.info("registered x64dbg session %s from %s", conn.session_id, conn.peer)

    def _unregister_connection(self, conn: BridgeConnection) -> None:
        if not conn.session_id:
            return
        with self._lock:
            current = self._sessions.get(conn.session_id)
            if current is conn:
                self._sessions.pop(conn.session_id, None)
        LOG.info("unregistered x64dbg session %s", conn.session_id)

    def _with_server_defaults(self, item: dict[str, Any]) -> dict[str, Any]:
        item = dict(item)
        item.setdefault("bridge_host", self.host)
        item.setdefault("bridge_port", self.port)
        return item
