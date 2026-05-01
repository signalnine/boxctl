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
