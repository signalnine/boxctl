"""CLI tests for `boxctl apply` (issue boxctl-n2m.7)."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from boxctl.cli import main


SAMPLE_PLAYBOOK = """- name: Apply changes from sandbox demo
  hosts: all
  become: true
  tasks:
    - name: Install package nginx
      ansible.builtin.package:
        name: nginx
        state: present
    - name: Deploy /etc/nginx/sites-enabled/foo
      ansible.builtin.copy:
        dest: /etc/nginx/sites-enabled/foo
        content: "server { listen 80; }\\n"
        owner: root
        group: root
        mode: "0644"
    - name: Enable service nginx.service
      ansible.builtin.systemd:
        name: nginx.service
        enabled: true
        state: started
"""


@pytest.fixture
def playbook_file(tmp_path):
    p = tmp_path / "play.yml"
    p.write_text(SAMPLE_PLAYBOOK)
    return p


@pytest.fixture
def audit_log(tmp_path):
    return tmp_path / "audit.jsonl"


def test_apply_missing_playbook_returns_2(tmp_path, capsys):
    rc = main(["apply", str(tmp_path / "nope.yml")])
    assert rc == 2
    captured = capsys.readouterr()
    assert "not found" in captured.err


def test_apply_yes_flag_approves_and_logs(playbook_file, audit_log, capsys):
    rc = main([
        "apply",
        str(playbook_file),
        "--yes",
        "--no-color",
        "--audit-log", str(audit_log),
    ])
    assert rc == 0

    captured = capsys.readouterr()
    # Diff summary present
    assert "package" in captured.out
    assert "/etc/nginx/sites-enabled/foo" in captured.out
    assert "nginx.service" in captured.out
    # Full playbook is shown
    assert "--- playbook ---" in captured.out
    assert "ansible.builtin.copy" in captured.out
    # Decision summary printed
    assert "approved" in captured.out

    # Audit log contains exactly one approved entry with required fields.
    lines = audit_log.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["decision"] == "approved"
    assert entry["playbook"] == str(playbook_file)
    assert "timestamp" in entry
    assert entry["user"]
    assert entry["task_count"] == 3


def test_apply_rejected_via_n_returns_1(playbook_file, audit_log, capsys, monkeypatch):
    # Simulate user typing "n\n" on stdin.
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))

    rc = main([
        "apply",
        str(playbook_file),
        "--no-color",
        "--audit-log", str(audit_log),
    ])
    assert rc == 1

    entry = json.loads(audit_log.read_text().splitlines()[0])
    assert entry["decision"] == "rejected"


def test_apply_blank_input_rejects(playbook_file, audit_log, monkeypatch):
    """Default (just press enter) is reject -- safety first."""
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))

    rc = main([
        "apply",
        str(playbook_file),
        "--no-color",
        "--audit-log", str(audit_log),
    ])
    assert rc == 1
    entry = json.loads(audit_log.read_text().splitlines()[0])
    assert entry["decision"] == "rejected"


def test_apply_dry_run_no_prompt_no_log(playbook_file, audit_log, capsys):
    rc = main([
        "apply",
        str(playbook_file),
        "--dry-run",
        "--no-color",
        "--audit-log", str(audit_log),
    ])
    assert rc == 0
    assert not audit_log.exists()
    captured = capsys.readouterr()
    assert "/etc/nginx/sites-enabled/foo" in captured.out
    assert "approved" not in captured.out
    assert "rejected" not in captured.out


def test_apply_invalid_yaml_still_logs_with_errors(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text(":\n  not: [valid yaml\n")
    audit = tmp_path / "audit.jsonl"

    rc = main([
        "apply",
        str(bad),
        "--yes",
        "--no-color",
        "--audit-log", str(audit),
    ])
    # Approval still proceeds (operator chose --yes); errors are surfaced.
    assert rc == 0
    captured = capsys.readouterr()
    assert "invalid YAML" in captured.out or "Errors" in captured.out


def test_apply_no_color_suppresses_ansi(playbook_file, audit_log, capsys):
    main([
        "apply",
        str(playbook_file),
        "--yes",
        "--no-color",
        "--audit-log", str(audit_log),
    ])
    out = capsys.readouterr().out
    assert "\x1b[" not in out


def test_apply_appends_multiple_decisions(playbook_file, audit_log):
    for _ in range(3):
        main([
            "apply",
            str(playbook_file),
            "--yes",
            "--no-color",
            "--audit-log", str(audit_log),
        ])
    lines = audit_log.read_text().splitlines()
    assert len(lines) == 3
    for line in lines:
        assert json.loads(line)["decision"] == "approved"


def test_apply_help_lists_command():
    """`boxctl apply --help` works without error."""
    proc = subprocess.run(
        [sys.executable, "-m", "boxctl", "apply", "--help"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "playbook" in proc.stdout.lower()
