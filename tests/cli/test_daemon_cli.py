"""CLI tests for `boxctl daemon` (issue boxctl-n2m.8)."""

from __future__ import annotations

import json
import threading
import time
from http.client import HTTPConnection

import pytest

from boxctl.cli import main


def test_daemon_help_lists_serve_subcommand(capsys):
    with pytest.raises(SystemExit):
        main(["daemon", "--help"])
    captured = capsys.readouterr()
    assert "serve" in captured.out


def test_daemon_serve_starts_server_and_stops_on_signal(tmp_path, monkeypatch, capsys):
    """`boxctl daemon serve` should bind, accept a request, and shut down cleanly."""
    inventory = tmp_path / "hosts.yml"
    inventory.write_text("hosts: {}\n")

    config = tmp_path / "daemon.yml"
    config.write_text("tokens:\n  smoke-tok: reader\n")

    log = tmp_path / "daemon.jsonl"
    monkeypatch.setenv("BOXCTL_DAEMON_LOG", str(log))

    runs = tmp_path / "runs.jsonl"
    runs.write_text("")
    monkeypatch.setenv("BOXCTL_RUNS_LOG", str(runs))

    approvals = tmp_path / "audit.jsonl"
    approvals.write_text("")
    monkeypatch.setenv("BOXCTL_AUDIT_LOG", str(approvals))

    holder: dict = {}

    def runner():
        try:
            holder["rc"] = main([
                "daemon",
                "serve",
                "--bind", "127.0.0.1",
                "--port", "0",
                "--config", str(config),
                "--inventory", str(inventory),
            ])
        except KeyboardInterrupt:
            holder["rc"] = 0

    th = threading.Thread(target=runner, daemon=True)
    th.start()

    # Wait for server bind
    deadline = time.time() + 5
    server = None
    from boxctl.core import daemon as daemon_mod
    while time.time() < deadline:
        server = daemon_mod._LAST_SERVER  # type: ignore[attr-defined]
        if server is not None:
            break
        time.sleep(0.05)
    assert server is not None, "daemon serve did not bind in time"

    addr = server.server_address
    conn = HTTPConnection(addr[0], addr[1], timeout=5)
    conn.request("GET", "/hosts", headers={"Authorization": "Bearer smoke-tok"})
    resp = conn.getresponse()
    assert resp.status == 200
    body = json.loads(resp.read())
    conn.close()
    assert body == []

    # Trigger graceful shutdown.
    daemon_mod._stop_running_server()
    th.join(timeout=5)
    assert holder.get("rc") == 0


def test_daemon_serve_warns_on_non_loopback_bind(tmp_path, monkeypatch, capsys):
    """Binding to non-loopback exposes the daemon to anyone on the
    network -- the operator deserves a clear stderr warning before that
    happens (gap analysis P2 #17)."""
    inventory = tmp_path / "hosts.yml"
    inventory.write_text("hosts: {}\n")
    config = tmp_path / "daemon.yml"
    config.write_text("tokens:\n  s: reader\n")

    monkeypatch.setenv("BOXCTL_DAEMON_LOG", str(tmp_path / "d.jsonl"))
    monkeypatch.setenv("BOXCTL_RUNS_LOG", str(tmp_path / "r.jsonl"))
    monkeypatch.setenv("BOXCTL_AUDIT_LOG", str(tmp_path / "a.jsonl"))

    holder: dict = {}

    def runner():
        holder["rc"] = main([
            "daemon", "serve",
            "--bind", "0.0.0.0",
            "--port", "0",
            "--config", str(config),
            "--inventory", str(inventory),
        ])

    th = threading.Thread(target=runner, daemon=True)
    th.start()

    # Wait for the server to bind, then shut down.
    from boxctl.core import daemon as daemon_mod
    deadline = time.time() + 5
    while time.time() < deadline:
        if daemon_mod._LAST_SERVER is not None:
            break
        time.sleep(0.05)
    daemon_mod._stop_running_server()
    th.join(timeout=5)

    err = capsys.readouterr().err
    assert "non-loopback" in err
    assert "0.0.0.0" in err


def test_daemon_serve_quiet_on_loopback_bind(tmp_path, monkeypatch, capsys):
    inventory = tmp_path / "hosts.yml"
    inventory.write_text("hosts: {}\n")
    config = tmp_path / "daemon.yml"
    config.write_text("tokens:\n  s: reader\n")

    monkeypatch.setenv("BOXCTL_DAEMON_LOG", str(tmp_path / "d.jsonl"))
    monkeypatch.setenv("BOXCTL_RUNS_LOG", str(tmp_path / "r.jsonl"))
    monkeypatch.setenv("BOXCTL_AUDIT_LOG", str(tmp_path / "a.jsonl"))

    holder: dict = {}

    def runner():
        holder["rc"] = main([
            "daemon", "serve",
            "--bind", "127.0.0.1",
            "--port", "0",
            "--config", str(config),
            "--inventory", str(inventory),
        ])

    th = threading.Thread(target=runner, daemon=True)
    th.start()

    from boxctl.core import daemon as daemon_mod
    deadline = time.time() + 5
    while time.time() < deadline:
        if daemon_mod._LAST_SERVER is not None:
            break
        time.sleep(0.05)
    daemon_mod._stop_running_server()
    th.join(timeout=5)

    err = capsys.readouterr().err
    assert "non-loopback" not in err
