"""HTTP control plane for boxctl (issue boxctl-n2m.8).

Stdlib-only REST API exposing read-only views of the host inventory, run
log, and approval audit log, plus a sandbox-spawn endpoint guarded by
role-based access control.

Auth model: clients send `Authorization: Bearer <token>`. Tokens map to
roles in a YAML config at `~/.config/boxctl/daemon.yml`. Roles are
`reader` (read-only), `operator` (read + spawn), `admin` (everything).

Audit model: every request is appended to a daemon access log (JSONL);
sandbox spawns additionally append a record to the existing approval
audit log so the trail lives next to interactive `apply` decisions.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import yaml

from boxctl.core.sandbox import _NAME_RE as _SANDBOX_NAME_RE
from boxctl.core.sandbox import validate_image_ref
from boxctl.core.ssh import load_hosts


VALID_ROLES = ("reader", "operator", "admin")
ROLE_RANK = {"reader": 1, "operator": 2, "admin": 3}
ACTION_MIN_RANK = {"read": 1, "spawn": 2, "admin": 3}


@dataclass
class DaemonConfig:
    tokens: dict[str, str] = field(default_factory=dict)


def default_config_path() -> Path:
    env = os.environ.get("BOXCTL_DAEMON_CONFIG")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "boxctl" / "daemon.yml"


def default_access_log_path() -> Path:
    env = os.environ.get("BOXCTL_DAEMON_LOG")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "boxctl" / "daemon.jsonl"


def default_runs_log_path() -> Path:
    env = os.environ.get("BOXCTL_RUNS_LOG")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "boxctl" / "runs.jsonl"


def load_daemon_config(path: Path | str) -> DaemonConfig:
    """Parse the daemon YAML config; missing file -> empty config."""
    p = Path(path)
    if not p.exists():
        return DaemonConfig()
    raw = yaml.safe_load(p.read_text()) or {}
    tokens_raw = raw.get("tokens") or {}
    tokens: dict[str, str] = {}
    for tok, role in tokens_raw.items():
        if role not in VALID_ROLES:
            raise ValueError(
                f"invalid role {role!r} for token {tok!r}: must be one of {VALID_ROLES}"
            )
        tokens[str(tok)] = str(role)
    return DaemonConfig(tokens=tokens)


def role_allows(role: str | None, action: str) -> bool:
    """True iff `role` is permitted to perform `action`."""
    if role is None or role not in ROLE_RANK:
        return False
    needed = ACTION_MIN_RANK.get(action)
    if needed is None:
        return False
    return ROLE_RANK[role] >= needed


DEFAULT_AUTH_RATE_LIMIT = 10
DEFAULT_AUTH_RATE_WINDOW = 60


class RateLimiter:
    """Sliding-window failure counter keyed by a string (typically client IP).

    Used to throttle bearer-token brute-force attempts (gap analysis P1 #7).
    Only failed auths feed the counter; successful requests don't consume
    quota, so a busy legitimate client can't accidentally lock itself out.
    """

    def __init__(self, max_attempts: int = DEFAULT_AUTH_RATE_LIMIT,
                 window_seconds: float = DEFAULT_AUTH_RATE_WINDOW):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._buckets: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            # Drop entries older than the sliding window.
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_attempts:
                return False
            bucket.append(now)
            return True


SandboxSpawn = Callable[[str, str, str | None], dict[str, Any]]


@dataclass
class DaemonState:
    """All inputs/dependencies needed to serve requests.

    Carrying explicit paths and a `sandbox_spawn` callable keeps tests free
    of monkeypatching and lets the production wiring substitute the real
    podman-backed spawn at startup.
    """

    config: DaemonConfig
    inventory_path: Path
    approvals_log_path: Path
    runs_log_path: Path
    access_log_path: Path
    sandbox_spawn: SandboxSpawn
    rate_limiter: RateLimiter = field(default_factory=RateLimiter)
    _log_lock: threading.Lock = field(default_factory=threading.Lock)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _token_id(token: str | None) -> str | None:
    if not token:
        return None
    return token[:8]


def _append_access_log(state: DaemonState, entry: dict[str, Any]) -> None:
    with state._log_lock:
        state.access_log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(state.access_log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")


def _append_approval_log(state: DaemonState, entry: dict[str, Any]) -> None:
    with state._log_lock:
        state.approvals_log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(state.approvals_log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")


def _list_hosts(state: DaemonState) -> list[dict[str, Any]]:
    inv = load_hosts(state.inventory_path)
    out = []
    for name, h in sorted(inv.hosts.items()):
        out.append({
            "name": name,
            "host": h.host,
            "user": h.user,
            "port": h.port,
            "identity": h.identity,
        })
    return out


def make_handler(state: DaemonState) -> type[BaseHTTPRequestHandler]:
    """Build a request handler bound to the given DaemonState."""

    class Handler(BaseHTTPRequestHandler):
        # Quiet stderr -- tests assert on access log, not console noise.
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _auth(self) -> tuple[str | None, str | None]:
            header = self.headers.get("Authorization") or ""
            if not header.lower().startswith("bearer "):
                return None, None
            token = header[len("bearer "):].strip()
            role = state.config.tokens.get(token)
            return token, role

        def _send_json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload).encode()
            self._log_current(status)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_status(self, status: int, msg: str) -> None:
            body = json.dumps({"error": msg}).encode()
            self._log_current(status)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _log(self, status: int, method: str, path: str, token: str | None, role: str | None) -> None:
            entry = {
                "timestamp": _now_iso(),
                "method": method,
                "path": path,
                "status": status,
                "role": role,
                "token_id": _token_id(token),
            }
            try:
                _append_access_log(state, entry)
            except OSError:
                pass

        def _set_log_context(self, method: str, path: str, token: str | None, role: str | None) -> None:
            self._boxctl_log_context = (method, path, token, role)
            self._boxctl_logged = False

        def _log_current(self, status: int) -> None:
            if getattr(self, "_boxctl_logged", False):
                return
            context = getattr(self, "_boxctl_log_context", None)
            if context is None:
                return
            method, path, token, role = context
            self._boxctl_logged = True
            self._log(status, method, path, token, role)

        def _client_key(self) -> str:
            return self.client_address[0] if self.client_address else "unknown"

        def _handle(self, method: str, body: bytes | None = None) -> None:
            # Normalize the path once: strip query string (so /hosts?x=y
            # routes correctly -- issue boxctl-wux) and trim a trailing
            # slash. The access log records the path WITHOUT the query
            # string, since clients sometimes pass secrets that way and
            # we don't want them landing in daemon.jsonl
            # (gap analysis P1 #6).
            route = urlsplit(self.path).path
            if len(route) > 1 and route.endswith("/"):
                route = route.rstrip("/")
            token, role = self._auth()
            self._set_log_context(method, route, token, role)

            if token is None or role is None:
                # Failed-auth attempts feed the rate limiter so an IP that
                # spams bad tokens eventually gets 429'd
                # (gap analysis P1 #7).
                if not state.rate_limiter.allow(self._client_key()):
                    self._send_status(429, "too many failed auth attempts")
                    return
                if token is None:
                    self._send_status(401, "missing or malformed Authorization header")
                else:
                    self._send_status(403, "unknown token")
                return

            try:
                self._dispatch(method, route, role, body)
            except _HTTPError as e:
                self._send_status(e.status, e.message)

        def _dispatch(self, method: str, path: str, role: str, body: bytes | None) -> int:
            if method == "GET" and path == "/hosts":
                if not role_allows(role, "read"):
                    raise _HTTPError(403, "forbidden")
                self._log_current(200)
                self._send_json(200, _list_hosts(state))
                return 200
            if method == "GET" and path == "/runs":
                if not role_allows(role, "read"):
                    raise _HTTPError(403, "forbidden")
                self._log_current(200)
                self._send_json(200, _read_jsonl(state.runs_log_path))
                return 200
            if method == "GET" and path == "/approvals":
                if not role_allows(role, "read"):
                    raise _HTTPError(403, "forbidden")
                self._log_current(200)
                self._send_json(200, _read_jsonl(state.approvals_log_path))
                return 200
            if method == "POST" and path == "/sandbox":
                if not role_allows(role, "spawn"):
                    raise _HTTPError(403, "forbidden")
                if not body:
                    raise _HTTPError(400, "empty body")
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    raise _HTTPError(400, "malformed JSON")
                if not isinstance(payload, dict):
                    raise _HTTPError(400, "body must be a JSON object")
                name = payload.get("name")
                image = payload.get("image", "docker.io/library/debian:stable")
                source_host = payload.get("source_host")
                if not isinstance(name, str) or not name:
                    raise _HTTPError(400, "name is required")
                # Validate name at the daemon boundary (defense in depth).
                # The spawn callable will revalidate; the daemon also
                # rejects up front so test harnesses that inject a fake
                # spawn don't bypass the gate.
                if not _SANDBOX_NAME_RE.match(name):
                    raise _HTTPError(400, f"invalid sandbox name: {name!r}")
                if not isinstance(image, str):
                    raise _HTTPError(400, "image must be a string")
                try:
                    validate_image_ref(image)
                except ValueError as e:
                    raise _HTTPError(400, str(e))
                if source_host is not None and not isinstance(source_host, str):
                    raise _HTTPError(400, "source_host must be a string or null")
                try:
                    sandbox = state.sandbox_spawn(name, image, source_host)
                except (FileExistsError, ValueError, RuntimeError) as e:
                    raise _HTTPError(409, str(e))
                _append_approval_log(state, {
                    "timestamp": _now_iso(),
                    "decision": "sandbox_spawn",
                    "sandbox": name,
                    "image": image,
                    "source_host": source_host,
                    "role": role,
                })
                self._log_current(201)
                self._send_json(201, sandbox)
                return 201
            raise _HTTPError(404, "not found")

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            self._handle("POST", body=body)

    return Handler


class _HTTPError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message
        super().__init__(message)


def start_server(
    state: DaemonState,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> ThreadingHTTPServer:
    """Bind + start the HTTP server on a daemon thread. Returns the server.

    Caller is responsible for `server.shutdown()` + `server.server_close()`.
    """
    handler_cls = make_handler(state)
    server = ThreadingHTTPServer((host, port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


_LAST_SERVER: ThreadingHTTPServer | None = None
_shutdown_event = threading.Event()


def _wait_for_shutdown(server: ThreadingHTTPServer) -> None:
    """Block until either KeyboardInterrupt or _stop_running_server is called."""
    _shutdown_event.clear()
    while not _shutdown_event.is_set():
        if _shutdown_event.wait(timeout=0.5):
            break


def _stop_running_server() -> None:
    """Signal the active `boxctl daemon serve` to exit. Used by tests."""
    _shutdown_event.set()
