"""Tests for the daemon control plane (issue boxctl-n2m.8)."""

from __future__ import annotations

import json
import threading
import time
from http.client import HTTPConnection
from pathlib import Path

import pytest

from boxctl.core import daemon


# --- config + RBAC ------------------------------------------------------


def test_load_config_missing_file_returns_empty(tmp_path):
    cfg = daemon.load_daemon_config(tmp_path / "missing.yml")
    assert cfg.tokens == {}


def test_load_config_parses_token_role_map(tmp_path):
    cfg_file = tmp_path / "daemon.yml"
    cfg_file.write_text(
        "tokens:\n"
        "  alpha-token: reader\n"
        "  beta-token: operator\n"
        "  gamma-token: admin\n"
    )
    cfg = daemon.load_daemon_config(cfg_file)
    assert cfg.tokens == {
        "alpha-token": "reader",
        "beta-token": "operator",
        "gamma-token": "admin",
    }


def test_load_config_rejects_unknown_role(tmp_path):
    cfg_file = tmp_path / "daemon.yml"
    cfg_file.write_text("tokens:\n  bad: superuser\n")
    with pytest.raises(ValueError, match="superuser"):
        daemon.load_daemon_config(cfg_file)


def test_role_allows_reader_only_reads():
    assert daemon.role_allows("reader", "read") is True
    assert daemon.role_allows("reader", "spawn") is False
    assert daemon.role_allows("reader", "admin") is False


def test_role_allows_operator_can_spawn():
    assert daemon.role_allows("operator", "read") is True
    assert daemon.role_allows("operator", "spawn") is True
    assert daemon.role_allows("operator", "admin") is False


def test_role_allows_admin_all():
    for action in ("read", "spawn", "admin"):
        assert daemon.role_allows("admin", action) is True


def test_role_allows_unknown_role_denies():
    assert daemon.role_allows(None, "read") is False
    assert daemon.role_allows("ghost", "read") is False


# --- HTTP server fixture ------------------------------------------------


@pytest.fixture
def daemon_env(tmp_path, monkeypatch):
    """Set up an inventory, audit log, daemon config, and runs log under tmp_path."""
    inventory = tmp_path / "hosts.yml"
    inventory.write_text(
        "hosts:\n"
        "  web-1:\n"
        "    host: web-1.example.com\n"
        "    user: ops\n"
        "    port: 22\n"
        "  db-1:\n"
        "    host: 10.0.0.5\n"
        "    user: dba\n"
        "    port: 2222\n"
    )

    approvals_log = tmp_path / "audit.jsonl"
    approvals_log.write_text(
        json.dumps({
            "timestamp": "2026-04-14T10:00:00+00:00",
            "user": "alice",
            "playbook": "/tmp/p.yml",
            "decision": "approved",
            "task_count": 2,
        }) + "\n"
        + json.dumps({
            "timestamp": "2026-04-14T10:05:00+00:00",
            "user": "bob",
            "playbook": "/tmp/q.yml",
            "decision": "rejected",
            "task_count": 1,
        }) + "\n"
    )

    runs_log = tmp_path / "runs.jsonl"
    runs_log.write_text(
        json.dumps({
            "timestamp": "2026-04-14T11:00:00+00:00",
            "user": "alice",
            "script": "loadavg_analyzer",
            "host": "web-1",
            "exit_code": 0,
        }) + "\n"
    )

    daemon_log = tmp_path / "daemon.jsonl"

    cfg = daemon.DaemonConfig(
        tokens={
            "reader-tok": "reader",
            "operator-tok": "operator",
            "admin-tok": "admin",
        }
    )

    spawn_calls: list[dict] = []

    def fake_spawn(name, image, source_host):
        spawn_calls.append({"name": name, "image": image, "source_host": source_host})
        return {
            "name": name,
            "container_id": "fakecid12345",
            "image": image,
            "source_host": source_host,
            "created_at": 1700000000.0,
            "units_snapshot": [],
            "packages_snapshot": [],
        }

    state = daemon.DaemonState(
        config=cfg,
        inventory_path=inventory,
        approvals_log_path=approvals_log,
        runs_log_path=runs_log,
        access_log_path=daemon_log,
        sandbox_spawn=fake_spawn,
    )

    server = daemon.start_server(state, host="127.0.0.1", port=0)
    yield server, state, spawn_calls
    server.shutdown()
    server.server_close()


def _request(server, method, path, headers=None, body=None):
    addr = server.server_address
    conn = HTTPConnection(addr[0], addr[1], timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    payload = resp.read()
    conn.close()
    return resp.status, payload


# --- endpoints ----------------------------------------------------------


def test_get_hosts_with_reader_returns_inventory(daemon_env):
    server, _state, _spawn = daemon_env
    status, payload = _request(
        server, "GET", "/hosts",
        headers={"Authorization": "Bearer reader-tok"},
    )
    assert status == 200
    body = json.loads(payload)
    names = sorted(h["name"] for h in body)
    assert names == ["db-1", "web-1"]
    web = next(h for h in body if h["name"] == "web-1")
    assert web["host"] == "web-1.example.com"
    assert web["user"] == "ops"


def test_get_runs_returns_run_log(daemon_env):
    server, _state, _spawn = daemon_env
    status, payload = _request(
        server, "GET", "/runs",
        headers={"Authorization": "Bearer reader-tok"},
    )
    assert status == 200
    body = json.loads(payload)
    assert len(body) == 1
    assert body[0]["script"] == "loadavg_analyzer"


def test_get_approvals_returns_audit_log(daemon_env):
    server, _state, _spawn = daemon_env
    status, payload = _request(
        server, "GET", "/approvals",
        headers={"Authorization": "Bearer reader-tok"},
    )
    assert status == 200
    body = json.loads(payload)
    assert len(body) == 2
    decisions = [e["decision"] for e in body]
    assert decisions == ["approved", "rejected"]


def test_missing_authorization_returns_401(daemon_env):
    server, _state, _spawn = daemon_env
    status, _payload = _request(server, "GET", "/hosts")
    assert status == 401


def test_invalid_token_returns_403(daemon_env):
    server, _state, _spawn = daemon_env
    status, _payload = _request(
        server, "GET", "/hosts",
        headers={"Authorization": "Bearer wrong-tok"},
    )
    assert status == 403


def test_get_hosts_with_query_string_returns_200(daemon_env):
    """Query strings on otherwise-valid routes must not 404. Previously the
    dispatcher matched on raw self.path so /hosts?limit=10 fell through
    (issue boxctl-wux)."""
    server, _state, _spawn = daemon_env
    status, payload = _request(
        server, "GET", "/hosts?limit=10",
        headers={"Authorization": "Bearer reader-tok"},
    )
    assert status == 200
    body = json.loads(payload)
    assert sorted(h["name"] for h in body) == ["db-1", "web-1"]


def test_get_runs_with_query_string_returns_200(daemon_env):
    server, _state, _spawn = daemon_env
    status, _ = _request(
        server, "GET", "/runs?since=2026-04-01",
        headers={"Authorization": "Bearer reader-tok"},
    )
    assert status == 200


def test_get_hosts_with_trailing_slash_returns_200(daemon_env):
    """``/hosts/`` and ``/hosts`` should resolve to the same endpoint."""
    server, _state, _spawn = daemon_env
    status, _ = _request(
        server, "GET", "/hosts/",
        headers={"Authorization": "Bearer reader-tok"},
    )
    assert status == 200


def test_unknown_path_with_query_still_returns_404(daemon_env):
    server, _state, _spawn = daemon_env
    status, _ = _request(
        server, "GET", "/nope?x=y",
        headers={"Authorization": "Bearer reader-tok"},
    )
    assert status == 404


def test_access_log_strips_query_string(daemon_env):
    """Secrets passed in URL query strings (e.g. /hosts?api_key=xyz)
    should NOT land in the access log (gap analysis P1 #6)."""
    server, state, _spawn = daemon_env
    _request(
        server, "GET", "/hosts?api_key=secret-do-not-log",
        headers={"Authorization": "Bearer reader-tok"},
    )
    for _ in range(20):
        if state.access_log_path.exists() and state.access_log_path.stat().st_size > 0:
            break
        time.sleep(0.05)
    log_text = state.access_log_path.read_text()
    assert "secret-do-not-log" not in log_text
    assert "api_key" not in log_text
    # The path field should still be present, just without the query.
    assert any(json.loads(ln)["path"] == "/hosts" for ln in log_text.splitlines() if ln)


def test_access_log_written_before_response_body(daemon_env):
    """A client that has received the response body should also see the access log."""
    server, state, _spawn = daemon_env
    server.shutdown()
    server.server_close()

    handler_cls = daemon.make_handler(state)
    orig_send_json = handler_cls._send_json
    logged_before_body = []

    def recording_send_json(self, status, payload):
        if state.access_log_path.exists():
            log_text = state.access_log_path.read_text()
            logged_before_body.append(
                any(json.loads(ln)["path"] == "/hosts" for ln in log_text.splitlines() if ln)
            )
        else:
            logged_before_body.append(False)
        return orig_send_json(self, status, payload)

    handler_cls._send_json = recording_send_json
    patched_server = daemon.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=patched_server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _ = _request(
            patched_server, "GET", "/hosts",
            headers={"Authorization": "Bearer reader-tok"},
        )
        assert status == 200
    finally:
        patched_server.shutdown()
        patched_server.server_close()
        thread.join(timeout=2)

    assert logged_before_body == [True]


def test_post_sandbox_rejects_malformed_image(daemon_env):
    """Image references go through validate_image_ref before spawn so the
    daemon doesn't pull from arbitrary user-controlled registries
    (gap analysis P0 #5 / P1 #8)."""
    server, _state, spawn_calls = daemon_env
    body = json.dumps({"name": "sb1", "image": "img;rm -rf /"}).encode()
    status, _ = _request(
        server, "POST", "/sandbox",
        headers={
            "Authorization": "Bearer operator-tok",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        },
        body=body,
    )
    assert status == 400
    assert spawn_calls == []


class TestRateLimiter:
    """Unit-level checks of the rate limiter -- the integration test below
    exercises the daemon plumbing."""

    def test_allows_under_limit(self):
        from boxctl.core.daemon import RateLimiter

        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is True

    def test_blocks_over_limit(self):
        from boxctl.core.daemon import RateLimiter

        limiter = RateLimiter(max_attempts=2, window_seconds=60)
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is False

    def test_per_ip_independent(self):
        from boxctl.core.daemon import RateLimiter

        limiter = RateLimiter(max_attempts=1, window_seconds=60)
        assert limiter.allow("1.1.1.1") is True
        assert limiter.allow("2.2.2.2") is True
        assert limiter.allow("1.1.1.1") is False

    def test_window_expires(self, monkeypatch):
        """Old attempts age out so legitimate clients aren't locked out
        forever after a typo."""
        from boxctl.core import daemon as d

        clock = [1000.0]
        monkeypatch.setattr(d.time, "monotonic", lambda: clock[0])
        limiter = d.RateLimiter(max_attempts=2, window_seconds=10)
        assert limiter.allow("a") is True
        assert limiter.allow("a") is True
        assert limiter.allow("a") is False
        clock[0] = 1011.0  # past window
        assert limiter.allow("a") is True


def test_repeated_bad_tokens_eventually_429(daemon_env, monkeypatch):
    """Brute-forcing bearer tokens must eventually get rate-limited
    (gap analysis P1 #7). The default limit is generous enough not to
    affect normal use but tight enough to make brute force impractical."""
    server, state, _spawn = daemon_env
    from boxctl.core import daemon as d

    # Reset and shrink the limiter so the test runs quickly.
    state.rate_limiter = d.RateLimiter(max_attempts=3, window_seconds=60)

    statuses = []
    for _ in range(6):
        status, _ = _request(
            server, "GET", "/hosts",
            headers={"Authorization": "Bearer wrong-tok"},
        )
        statuses.append(status)
    # First 3 attempts are 403 (unknown token); subsequent get 429.
    assert statuses.count(429) >= 1
    assert statuses[-1] == 429


def test_successful_auth_doesnt_consume_quota(daemon_env):
    """Rate limit only counts FAILED attempts, so a steady stream of
    valid requests from one IP isn't blocked."""
    server, state, _spawn = daemon_env
    from boxctl.core import daemon as d

    state.rate_limiter = d.RateLimiter(max_attempts=3, window_seconds=60)

    for _ in range(10):
        status, _ = _request(
            server, "GET", "/hosts",
            headers={"Authorization": "Bearer reader-tok"},
        )
        assert status == 200


class TestDaemonMaliciousInputs:
    """Adversarial inputs must produce 4xx responses, not crashes or
    successful side effects (gap analysis P2 #13)."""

    def test_malformed_authorization_header(self, daemon_env):
        server, _state, _ = daemon_env
        # No Bearer prefix at all -- malformed.
        status, _ = _request(
            server, "GET", "/hosts",
            headers={"Authorization": "wrong-format-no-prefix"},
        )
        assert status == 401

    def test_authorization_with_only_bearer_keyword(self, daemon_env):
        server, _state, _ = daemon_env
        status, _ = _request(
            server, "GET", "/hosts",
            headers={"Authorization": "Bearer"},
        )
        # Empty token after the keyword -> auth fails. Should be 401 (no
        # token) or 403 (token "" not in map). Either is acceptable; not
        # 200, not 500.
        assert status in (401, 403)

    def test_oversized_body_rejected(self, daemon_env):
        """A 5MB JSON body shouldn't be loaded into memory then parsed --
        the daemon should reject before exhausting RAM."""
        server, _state, spawn_calls = daemon_env
        # Build a body that's syntactically valid but unreasonably large.
        big = b'{"name": "sb1", "image": "' + b"a" * (5 * 1024 * 1024) + b'"}'
        status, _ = _request(
            server, "POST", "/sandbox",
            headers={
                "Authorization": "Bearer operator-tok",
                "Content-Type": "application/json",
                "Content-Length": str(len(big)),
            },
            body=big,
        )
        # Either 400 (size cap) or 400 (image validation rejects long ref).
        assert status == 400
        assert spawn_calls == []

    def test_unicode_in_image_string_rejected(self, daemon_env):
        server, _state, spawn_calls = daemon_env
        # Non-ASCII characters aren't part of the OCI image grammar.
        body = json.dumps({"name": "sb1", "image": "img‮tag"}).encode()
        status, _ = _request(
            server, "POST", "/sandbox",
            headers={
                "Authorization": "Bearer operator-tok",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert status == 400
        assert spawn_calls == []

    def test_invalid_sandbox_name_rejected(self, daemon_env):
        """Names with shell metacharacters must not reach create_sandbox."""
        server, _state, spawn_calls = daemon_env
        body = json.dumps({"name": "bad;name", "image": "debian:stable"}).encode()
        status, _ = _request(
            server, "POST", "/sandbox",
            headers={
                "Authorization": "Bearer operator-tok",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        # The name validation happens inside spawn (raises ValueError),
        # which the dispatcher maps to 409. Either 400 or 409 is fine,
        # we just need NOT-201 and no real spawn.
        assert status in (400, 409)

    def test_post_sandbox_array_body_rejected(self, daemon_env):
        server, _state, _ = daemon_env
        body = json.dumps([1, 2, 3]).encode()
        status, _ = _request(
            server, "POST", "/sandbox",
            headers={
                "Authorization": "Bearer operator-tok",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert status == 400


def test_post_sandbox_rejects_non_string_image(daemon_env):
    server, _state, spawn_calls = daemon_env
    body = json.dumps({"name": "sb1", "image": 12345}).encode()
    status, _ = _request(
        server, "POST", "/sandbox",
        headers={
            "Authorization": "Bearer operator-tok",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        },
        body=body,
    )
    assert status == 400
    assert spawn_calls == []


def test_post_sandbox_with_operator_spawns_201(daemon_env):
    server, _state, spawn_calls = daemon_env
    body = json.dumps({"name": "sb1", "image": "debian:stable"}).encode()
    status, payload = _request(
        server, "POST", "/sandbox",
        headers={
            "Authorization": "Bearer operator-tok",
            "Content-Type": "application/json",
        },
        body=body,
    )
    assert status == 201
    assert spawn_calls == [{"name": "sb1", "image": "debian:stable", "source_host": None}]
    out = json.loads(payload)
    assert out["name"] == "sb1"
    assert out["container_id"] == "fakecid12345"


def test_post_sandbox_with_reader_returns_403(daemon_env):
    server, _state, spawn_calls = daemon_env
    body = json.dumps({"name": "sb1"}).encode()
    status, _payload = _request(
        server, "POST", "/sandbox",
        headers={
            "Authorization": "Bearer reader-tok",
            "Content-Type": "application/json",
        },
        body=body,
    )
    assert status == 403
    assert spawn_calls == []


def test_post_sandbox_malformed_json_returns_400(daemon_env):
    server, _state, _spawn = daemon_env
    status, _payload = _request(
        server, "POST", "/sandbox",
        headers={
            "Authorization": "Bearer operator-tok",
            "Content-Type": "application/json",
        },
        body=b"{not-json",
    )
    assert status == 400


def test_unknown_route_returns_404(daemon_env):
    server, _state, _spawn = daemon_env
    status, _payload = _request(
        server, "GET", "/nope",
        headers={"Authorization": "Bearer reader-tok"},
    )
    assert status == 404


# --- audit logging ------------------------------------------------------


def test_request_appended_to_access_log(daemon_env):
    server, state, _spawn = daemon_env
    _request(
        server, "GET", "/hosts",
        headers={"Authorization": "Bearer reader-tok"},
    )
    # Allow the BaseHTTPRequestHandler thread to flush
    for _ in range(20):
        if state.access_log_path.exists() and state.access_log_path.stat().st_size > 0:
            break
        time.sleep(0.05)

    lines = state.access_log_path.read_text().strip().splitlines()
    assert len(lines) >= 1
    entry = json.loads(lines[-1])
    assert entry["method"] == "GET"
    assert entry["path"] == "/hosts"
    assert entry["status"] == 200
    assert entry["role"] == "reader"
    assert entry["token_id"] == "reader-t"
    assert "timestamp" in entry


def test_unauthorized_request_logged_with_null_role(daemon_env):
    server, state, _spawn = daemon_env
    _request(server, "GET", "/hosts")
    for _ in range(20):
        if state.access_log_path.exists() and state.access_log_path.stat().st_size > 0:
            break
        time.sleep(0.05)
    entry = json.loads(state.access_log_path.read_text().strip().splitlines()[-1])
    assert entry["status"] == 401
    assert entry["role"] is None
    assert entry["token_id"] is None


def test_sandbox_spawn_logged_to_approvals(daemon_env):
    server, state, _spawn = daemon_env
    body = json.dumps({"name": "sb2", "image": "debian:stable"}).encode()
    _request(
        server, "POST", "/sandbox",
        headers={
            "Authorization": "Bearer operator-tok",
            "Content-Type": "application/json",
        },
        body=body,
    )
    # Approvals log should now contain a sandbox-spawn record at the end.
    text = state.approvals_log_path.read_text().strip().splitlines()
    last = json.loads(text[-1])
    assert last["decision"] == "sandbox_spawn"
    assert last["sandbox"] == "sb2"
    assert last["role"] == "operator"
