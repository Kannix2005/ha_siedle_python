"""
Thread-safe transport for the fcm-receiver library.

fcm-receiver 0.1.1 crashes Home Assistant with SIGSEGV after a few reconnects
(issue #22). Its socket handler shares one stop event across connections and
clears it on every start(), so heartbeat and watchdog threads of earlier
connections never see the stop and pile up. Worse, its reader re-reads
``self.sock`` on every iteration: after a reconnect the old reader adopts the
new socket, and two threads call SSL_read on the same SSL object — native
memory corruption. A reconnect that was still dialling when close() ran also
finished anyway and left a zombie connection whose callbacks kept flipping our
connection state.

The classes here replace exactly those parts:
- one thread per connection, which owns its socket and is the only thread
  that ever reads from or writes to it (heartbeat and stale detection run
  inline, there are no extra threads),
- close() from another thread only signals; the owning reader closes the
  socket itself, so a socket is never closed under a running SSL_read,
- events and callbacks of a superseded connection are dropped,
- connecting is serialized with close(), so nothing reconnects after a stop.
"""

from __future__ import annotations

import logging
import select
import socket
import ssl
import threading
import time
from typing import Optional

from fcm_receiver import FCMClient
from fcm_receiver.fcm_socket import FCMSocketHandler

_LOGGER = logging.getLogger(__name__)

FCM_HOST = "mtalk.google.com"
FCM_PORT = 5228
DIAL_TIMEOUT = 30
POLL_INTERVAL = 1.0
JOIN_TIMEOUT = 5.0

_ssl_context: Optional[ssl.SSLContext] = None
_ssl_context_lock = threading.Lock()


def _get_ssl_context() -> ssl.SSLContext:
    """Build the TLS context once; loading the CA store is expensive."""
    global _ssl_context
    with _ssl_context_lock:
        if _ssl_context is None:
            _ssl_context = ssl.create_default_context()
        return _ssl_context


def dial_fcm(host: str = FCM_HOST, port: int = FCM_PORT) -> ssl.SSLSocket:
    """Open the TLS connection to FCM, without hanging forever on a dead network."""
    raw = socket.create_connection((host, port), timeout=DIAL_TIMEOUT)
    try:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        tls = _get_ssl_context().wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise
    # Reads are driven by select(); a timeout would only turn a slow peer
    # into a spurious disconnect.
    tls.settimeout(None)
    return tls


class _Connection:
    """State owned by exactly one reader thread."""

    def __init__(self, sock: ssl.SSLSocket) -> None:
        self.sock = sock
        self.stop = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.finished = False
        self.lock = threading.Lock()


class SafeFCMSocketHandler(FCMSocketHandler):
    """FCMSocketHandler with one self-contained thread per connection."""

    def __init__(self) -> None:
        super().__init__()
        self._conn: Optional[_Connection] = None
        self._conn_lock = threading.Lock()
        self._tls = threading.local()
        self._last_recv = time.time()
        self._last_send = time.time()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        sock = self.sock
        if sock is None:
            raise ConnectionError("FCM socket not connected")

        with self._conn_lock:
            previous = self._conn
            conn = _Connection(sock)
            self._conn = conn

        if previous is not None:
            # Normally already gone: a reconnect is triggered by the old
            # reader as its very last action.
            previous.stop.set()
            if (
                previous.thread is not None
                and previous.thread is not threading.current_thread()
            ):
                previous.thread.join(timeout=JOIN_TIMEOUT)

        now = time.time()
        self._last_recv = now
        self._last_send = now
        conn.thread = threading.Thread(
            target=self._run, args=(conn,), name="siedle_fcm_reader", daemon=True
        )
        conn.thread.start()

    def close(self, err: Optional[Exception] = None) -> None:
        # Called from inside a reader (protocol close, failed ping), close
        # that reader's own connection, never whichever one is current.
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            with self._conn_lock:
                conn = self._conn
        if conn is None:
            # Connected but not started yet (login failed before start()).
            sock, self.sock = self.sock, None
            self.is_alive = False
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            return

        conn.stop.set()
        thread = conn.thread
        if thread is None or not thread.is_alive():
            self._finish(conn, err)
        # Otherwise the reader notices within POLL_INTERVAL and cleans up.

    def join(self, timeout: float = JOIN_TIMEOUT) -> None:
        """Wait for the current reader to exit (never call from a reader)."""
        conn = self._conn
        if conn and conn.thread and conn.thread is not threading.current_thread():
            conn.thread.join(timeout=timeout)

    # -- I/O ---------------------------------------------------------------

    def send(self, data: bytes) -> None:
        conn = getattr(self._tls, "conn", None)
        sock = conn.sock if conn is not None else self.sock
        if sock is None:
            raise ConnectionError("FCM socket not connected")
        sock.sendall(data)
        self._last_send = time.time()
        self._last_activity = self._last_send

    def _run(self, conn: _Connection) -> None:
        self._tls.conn = conn
        err: Optional[Exception] = None
        try:
            self._loop(conn)
        except Exception as exc:  # noqa: BLE001 - any failure ends this connection
            err = exc
            _LOGGER.debug("FCM reader ended: %s", exc)
        finally:
            self._finish(conn, err)
            self._tls.conn = None

    def _loop(self, conn: _Connection) -> None:
        sock = conn.sock
        interval = self.heartbeat_interval_sec if self.heartbeat_interval_sec > 0 else 600
        stale_after = max(interval, 60) * 2

        while not conn.stop.is_set():
            # Decrypted bytes may already sit in the SSL buffer, where
            # select() cannot see them.
            if not sock.pending():
                readable, _, _ = select.select([sock], [], [], POLL_INTERVAL)
                if conn.stop.is_set():
                    return
            else:
                readable = True

            now = time.time()
            if readable:
                chunk = sock.recv(32 * 1024)
                if not chunk:
                    _LOGGER.debug("FCM connection closed by peer")
                    return
                self._last_recv = now
                self._last_activity = now
                self._buf.extend(chunk)
                self._on_data()
                continue

            if now - self._last_recv > stale_after:
                _LOGGER.debug("FCM connection silent for %ds, reconnecting", stale_after)
                return
            if now - self._last_send >= interval:
                self.send_heartbeat_ping()

    def _finish(self, conn: _Connection, err: Optional[Exception]) -> None:
        with conn.lock:
            if conn.finished:
                return
            conn.finished = True

        conn.stop.set()
        try:
            conn.sock.close()
        except OSError:
            pass

        with self._conn_lock:
            current = self._conn is conn
            if current:
                self._conn = None
                self.sock = None
                self.is_alive = False
                self.init()

        # Only the live connection may report a loss — a superseded one
        # would otherwise trigger a reconnect of a healthy connection.
        if current and self.on_close:
            try:
                self.on_close(err)
            except Exception:  # noqa: BLE001
                _LOGGER.debug("FCM on_close callback failed", exc_info=True)


class SafeFCMClient(FCMClient):
    """FCMClient that uses SafeFCMSocketHandler and never connects after close()."""

    def __init__(self) -> None:
        super().__init__()
        self._socket = SafeFCMSocketHandler()
        self._socket.on_message = self._on_message
        self._socket.on_close = self._on_socket_close
        self._socket.on_tag = self._on_tag_internal
        self._connect_lock = threading.Lock()

    def _connect_and_start(self) -> None:
        if self._stop.is_set():
            return
        sock = dial_fcm()
        with self._connect_lock:
            if self._stop.is_set():
                sock.close()
                return
            try:
                self._socket.heartbeat_interval_sec = self.heartbeat_interval_sec
                self._socket.init()
                self._socket.sock = sock
                self._socket.is_alive = True
                self._socket.send(self._build_login_request_packet())
                self._socket.start()
            except BaseException:
                self._socket.sock = None
                self._socket.is_alive = False
                try:
                    sock.close()
                except OSError:
                    pass
                raise

    def close(self) -> None:
        with self._connect_lock:
            self._stop.set()
            self._socket.close()
        self._socket.join()
        reconnector = self._reconnector
        if reconnector is not None and reconnector is not threading.current_thread():
            reconnector.join(timeout=JOIN_TIMEOUT)
