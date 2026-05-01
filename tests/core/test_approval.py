"""Tests for the playbook approval gate (issue boxctl-n2m.7)."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from boxctl.core import approval


# --- summarize_playbook -------------------------------------------------


def test_summarize_handles_empty_playbook():
    out = approval.summarize_playbook("---\n[]\n")
    assert out == {"tasks": [], "errors": []}


def test_summarize_extracts_package_install():
    pb = """- name: test
  hosts: all
  become: true
  tasks:
    - name: Install package nginx
      ansible.builtin.package:
        name: nginx
        state: present
"""
    out = approval.summarize_playbook(pb)
    assert len(out["tasks"]) == 1
    t = out["tasks"][0]
    assert t["kind"] == "add"
    assert t["module"] == "package"
    assert "nginx" in t["target"]


def test_summarize_extracts_copy_with_content():
    pb = """- name: test
  hosts: all
  become: true
  tasks:
    - name: Deploy /etc/foo.conf
      ansible.builtin.copy:
        dest: /etc/foo.conf
        content: "hello\\n"
        mode: "0644"
"""
    out = approval.summarize_playbook(pb)
    assert len(out["tasks"]) == 1
    t = out["tasks"][0]
    assert t["kind"] == "add"
    assert t["module"] == "copy"
    assert t["target"] == "/etc/foo.conf"


def test_summarize_extracts_file_absent_as_remove():
    pb = """- name: test
  hosts: all
  tasks:
    - name: Remove /etc/old.conf
      ansible.builtin.file:
        path: /etc/old.conf
        state: absent
"""
    out = approval.summarize_playbook(pb)
    assert len(out["tasks"]) == 1
    assert out["tasks"][0]["kind"] == "remove"
    assert out["tasks"][0]["target"] == "/etc/old.conf"


def test_summarize_extracts_systemd_enable_and_disable():
    pb = """- name: test
  hosts: all
  tasks:
    - name: Enable nginx.service
      ansible.builtin.systemd:
        name: nginx.service
        enabled: true
        state: started
    - name: Disable cron.service
      ansible.builtin.systemd:
        name: cron.service
        enabled: false
        state: stopped
"""
    out = approval.summarize_playbook(pb)
    assert len(out["tasks"]) == 2
    kinds = [t["kind"] for t in out["tasks"]]
    assert kinds == ["add", "remove"]


def test_summarize_invalid_yaml_records_error():
    out = approval.summarize_playbook(":\n  not: [valid yaml")
    assert out["tasks"] == []
    assert out["errors"]


def test_summarize_non_list_root_records_error():
    out = approval.summarize_playbook("just a string")
    assert out["tasks"] == []
    assert out["errors"]


# --- render_summary -----------------------------------------------------


def test_render_summary_no_color_uses_plain_markers():
    summary = {
        "tasks": [
            {"kind": "add", "module": "package", "target": "nginx", "name": "Install nginx"},
            {"kind": "remove", "module": "file", "target": "/etc/old", "name": "Remove old"},
        ],
        "errors": [],
    }
    out = approval.render_summary(summary, color=False)
    assert "+ package" in out
    assert "- file" in out
    assert "nginx" in out
    assert "/etc/old" in out
    # No ANSI escape codes when color is off.
    assert "\x1b[" not in out


def test_render_summary_color_emits_ansi():
    summary = {
        "tasks": [{"kind": "add", "module": "package", "target": "nginx", "name": "Install nginx"}],
        "errors": [],
    }
    out = approval.render_summary(summary, color=True)
    assert "\x1b[32m" in out  # green for add


def test_render_summary_empty_says_no_changes():
    out = approval.render_summary({"tasks": [], "errors": []}, color=False)
    assert "no changes" in out.lower() or "no tasks" in out.lower()


def test_render_summary_shows_errors():
    out = approval.render_summary({"tasks": [], "errors": ["bad yaml"]}, color=False)
    assert "bad yaml" in out


# --- prompt_approval ----------------------------------------------------


def test_prompt_approval_y_returns_true():
    assert approval.prompt_approval(stream=io.StringIO("y\n")) is True


def test_prompt_approval_yes_returns_true():
    assert approval.prompt_approval(stream=io.StringIO("yes\n")) is True


def test_prompt_approval_capital_y_returns_true():
    assert approval.prompt_approval(stream=io.StringIO("Y\n")) is True


def test_prompt_approval_n_returns_false():
    assert approval.prompt_approval(stream=io.StringIO("n\n")) is False


def test_prompt_approval_blank_returns_false():
    """Default (just press enter) is reject -- safety first."""
    assert approval.prompt_approval(stream=io.StringIO("\n")) is False


def test_prompt_approval_eof_returns_false():
    assert approval.prompt_approval(stream=io.StringIO("")) is False


# --- log_decision -------------------------------------------------------


def test_log_decision_appends_jsonl_with_required_fields(tmp_path):
    log = tmp_path / "audit.jsonl"
    approval.log_decision(
        playbook_path="/tmp/play.yml",
        decision="approved",
        summary={"tasks": [], "errors": []},
        log_path=log,
    )
    lines = log.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["decision"] == "approved"
    assert entry["playbook"] == "/tmp/play.yml"
    assert "timestamp" in entry
    assert "user" in entry
    assert entry["user"]  # non-empty


def test_log_decision_appends_to_existing_log(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text('{"existing": true}\n')
    approval.log_decision(
        playbook_path="p", decision="rejected", summary={"tasks": [], "errors": []}, log_path=log,
    )
    lines = log.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"existing": True}


def test_log_decision_creates_parent_dir(tmp_path):
    log = tmp_path / "nested" / "dir" / "audit.jsonl"
    approval.log_decision(
        playbook_path="p", decision="approved", summary={"tasks": [], "errors": []}, log_path=log,
    )
    assert log.exists()


def test_log_decision_records_task_count(tmp_path):
    log = tmp_path / "audit.jsonl"
    summary = {
        "tasks": [
            {"kind": "add", "module": "package", "target": "nginx", "name": "x"},
            {"kind": "remove", "module": "file", "target": "/etc/y", "name": "y"},
        ],
        "errors": [],
    }
    approval.log_decision(
        playbook_path="p", decision="approved", summary=summary, log_path=log,
    )
    entry = json.loads(log.read_text().splitlines()[0])
    assert entry["task_count"] == 2


# --- default_audit_log_path --------------------------------------------


def test_default_audit_log_path_honors_env(monkeypatch, tmp_path):
    monkeypatch.setenv("BOXCTL_AUDIT_LOG", str(tmp_path / "custom.jsonl"))
    p = approval.default_audit_log_path()
    assert p == tmp_path / "custom.jsonl"


def test_default_audit_log_path_uses_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("BOXCTL_AUDIT_LOG", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    p = approval.default_audit_log_path()
    assert tmp_path in p.parents
    assert p.name == "audit.jsonl"


# --- should_use_color --------------------------------------------------


def test_should_use_color_respects_no_color_env(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert approval.should_use_color(is_tty=True) is False


def test_should_use_color_respects_boxctl_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("BOXCTL_NO_COLOR", "1")
    assert approval.should_use_color(is_tty=True) is False


def test_should_use_color_off_when_not_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("BOXCTL_NO_COLOR", raising=False)
    assert approval.should_use_color(is_tty=False) is False


def test_should_use_color_on_when_tty_and_no_overrides(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("BOXCTL_NO_COLOR", raising=False)
    assert approval.should_use_color(is_tty=True) is True
