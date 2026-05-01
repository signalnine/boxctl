"""Tests for Ansible playbook generation from sandbox diffs (issue boxctl-n2m.6)."""

from __future__ import annotations

import subprocess

import pytest
import yaml

from boxctl.core import ansible as ans


def _completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _empty_diff(name: str = "demo", container_id: str = "cid") -> dict:
    return {
        "name": name,
        "container_id": container_id,
        "fs_changes": [],
        "unit_changes": {"added": [], "removed": [], "changed": []},
        "package_changes": {"added": [], "removed": []},
    }


# --- structure ----------------------------------------------------------


def test_generate_playbook_returns_valid_yaml_with_play_structure():
    out = ans.generate_playbook(_empty_diff(name="demo"))
    parsed = yaml.safe_load(out)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    play = parsed[0]
    assert play["hosts"] == "all"
    assert play["become"] is True
    assert "demo" in play["name"]
    assert play["tasks"] == []


def test_generate_playbook_handles_missing_optional_keys():
    """Playbook generator must tolerate diffs that lack package_changes etc."""
    minimal = {"name": "x", "fs_changes": [], "unit_changes": {"added": [], "removed": [], "changed": []}}
    out = ans.generate_playbook(minimal)
    parsed = yaml.safe_load(out)
    assert parsed[0]["tasks"] == []


# --- packages -----------------------------------------------------------


def test_generate_playbook_includes_package_install_for_added_packages():
    diff = _empty_diff()
    diff["package_changes"]["added"] = ["nginx", "curl"]
    out = ans.generate_playbook(diff)
    parsed = yaml.safe_load(out)
    tasks = parsed[0]["tasks"]
    pkg_tasks = [t for t in tasks if "ansible.builtin.package" in t]
    assert len(pkg_tasks) == 2
    pkg_names = sorted(t["ansible.builtin.package"]["name"] for t in pkg_tasks)
    assert pkg_names == ["curl", "nginx"]
    for t in pkg_tasks:
        assert t["ansible.builtin.package"]["state"] == "present"


# --- files --------------------------------------------------------------


def test_generate_playbook_emits_copy_for_etc_files_with_content_extraction():
    diff = _empty_diff()
    diff["fs_changes"] = [
        "A /etc/nginx",
        "A /etc/nginx/sites-enabled",
        "A /etc/nginx/sites-enabled/foo",
    ]
    runner = lambda cmd, **kw: _completed(stdout="server { listen 80; }\n")
    out = ans.generate_playbook(diff, runner=runner)
    parsed = yaml.safe_load(out)
    tasks = parsed[0]["tasks"]
    copy_tasks = [t for t in tasks if "ansible.builtin.copy" in t]
    assert len(copy_tasks) == 1, "directories should be skipped, only leaf file produces a copy task"
    args = copy_tasks[0]["ansible.builtin.copy"]
    assert args["dest"] == "/etc/nginx/sites-enabled/foo"
    assert "server { listen 80" in args["content"]
    assert args["mode"] == "0644"
    assert args["owner"] == "root"
    assert args["group"] == "root"


def test_generate_playbook_changed_files_treated_as_copy():
    diff = _empty_diff()
    diff["fs_changes"] = ["C /etc/ssh/sshd_config"]
    runner = lambda cmd, **kw: _completed(stdout="Port 2222\n")
    out = ans.generate_playbook(diff, runner=runner)
    parsed = yaml.safe_load(out)
    tasks = parsed[0]["tasks"]
    copy_tasks = [t for t in tasks if "ansible.builtin.copy" in t]
    assert len(copy_tasks) == 1
    assert copy_tasks[0]["ansible.builtin.copy"]["dest"] == "/etc/ssh/sshd_config"
    assert copy_tasks[0]["ansible.builtin.copy"]["content"] == "Port 2222\n"


def test_generate_playbook_skips_non_etc_paths():
    diff = _empty_diff()
    diff["fs_changes"] = ["A /var/log/nginx/access.log", "A /usr/sbin/nginx", "C /tmp/scratch"]
    out = ans.generate_playbook(diff)
    parsed = yaml.safe_load(out)
    tasks = parsed[0]["tasks"]
    copy_tasks = [t for t in tasks if "ansible.builtin.copy" in t]
    assert copy_tasks == [], "non-/etc paths should not produce copy tasks"


def test_generate_playbook_omits_content_when_extract_fails():
    diff = _empty_diff()
    diff["fs_changes"] = ["A /etc/foo.conf"]
    runner = lambda cmd, **kw: _completed(returncode=1, stderr="not found")
    out = ans.generate_playbook(diff, runner=runner)
    parsed = yaml.safe_load(out)
    tasks = parsed[0]["tasks"]
    copy_tasks = [t for t in tasks if "ansible.builtin.copy" in t]
    assert len(copy_tasks) == 1
    assert "content" not in copy_tasks[0]["ansible.builtin.copy"]


def test_generate_playbook_omits_content_when_no_container_id():
    diff = _empty_diff(container_id=None)
    diff["fs_changes"] = ["A /etc/foo.conf"]
    out = ans.generate_playbook(diff)
    parsed = yaml.safe_load(out)
    copy_tasks = [t for t in parsed[0]["tasks"] if "ansible.builtin.copy" in t]
    assert len(copy_tasks) == 1
    assert "content" not in copy_tasks[0]["ansible.builtin.copy"]


def test_generate_playbook_emits_file_absent_for_deleted_etc_files():
    diff = _empty_diff()
    diff["fs_changes"] = ["D /etc/old.conf"]
    out = ans.generate_playbook(diff)
    parsed = yaml.safe_load(out)
    tasks = parsed[0]["tasks"]
    file_tasks = [t for t in tasks if "ansible.builtin.file" in t]
    assert len(file_tasks) == 1
    assert file_tasks[0]["ansible.builtin.file"]["state"] == "absent"
    assert file_tasks[0]["ansible.builtin.file"]["path"] == "/etc/old.conf"


# --- units --------------------------------------------------------------


def test_generate_playbook_emits_systemd_for_added_units():
    diff = _empty_diff()
    diff["unit_changes"]["added"] = ["nginx.service\tenabled"]
    out = ans.generate_playbook(diff)
    parsed = yaml.safe_load(out)
    sys_tasks = [t for t in parsed[0]["tasks"] if "ansible.builtin.systemd" in t]
    assert len(sys_tasks) == 1
    args = sys_tasks[0]["ansible.builtin.systemd"]
    assert args["name"] == "nginx.service"
    assert args["enabled"] is True
    assert args["state"] == "started"


def test_generate_playbook_changed_unit_to_enabled_emits_enable_task():
    diff = _empty_diff()
    diff["unit_changes"]["changed"] = ["cron.service\tdisabled -> enabled"]
    out = ans.generate_playbook(diff)
    parsed = yaml.safe_load(out)
    sys_tasks = [t for t in parsed[0]["tasks"] if "ansible.builtin.systemd" in t]
    assert len(sys_tasks) == 1
    assert sys_tasks[0]["ansible.builtin.systemd"]["enabled"] is True


def test_generate_playbook_changed_unit_to_disabled_emits_disable_task():
    diff = _empty_diff()
    diff["unit_changes"]["changed"] = ["foo.service\tenabled -> disabled"]
    out = ans.generate_playbook(diff)
    parsed = yaml.safe_load(out)
    sys_tasks = [t for t in parsed[0]["tasks"] if "ansible.builtin.systemd" in t]
    assert len(sys_tasks) == 1
    assert sys_tasks[0]["ansible.builtin.systemd"]["enabled"] is False
    assert sys_tasks[0]["ansible.builtin.systemd"]["state"] == "stopped"


def test_generate_playbook_added_static_unit_does_not_emit_task():
    """static units are not enable-able; they should not get a systemd task."""
    diff = _empty_diff()
    diff["unit_changes"]["added"] = ["foo.timer\tstatic"]
    out = ans.generate_playbook(diff)
    parsed = yaml.safe_load(out)
    sys_tasks = [t for t in parsed[0]["tasks"] if "ansible.builtin.systemd" in t]
    assert sys_tasks == []


# --- acceptance criteria ------------------------------------------------


def test_generate_playbook_acceptance_nginx_e2e():
    """Acceptance: nginx package + sites-enabled/foo + nginx.service produce package + copy + systemd tasks in order."""
    diff = {
        "name": "nginxbox",
        "container_id": "cidnginx",
        "fs_changes": [
            "A /etc/nginx",
            "A /etc/nginx/sites-enabled",
            "A /etc/nginx/sites-enabled/foo",
        ],
        "unit_changes": {
            "added": ["nginx.service\tenabled"],
            "removed": [],
            "changed": [],
        },
        "package_changes": {"added": ["nginx"], "removed": []},
    }
    runner = lambda cmd, **kw: _completed(stdout="server { listen 80; }\n")
    out = ans.generate_playbook(diff, runner=runner)
    parsed = yaml.safe_load(out)
    play = parsed[0]
    tasks = play["tasks"]

    pkg_idx = next(i for i, t in enumerate(tasks) if "ansible.builtin.package" in t)
    copy_idx = next(i for i, t in enumerate(tasks) if "ansible.builtin.copy" in t)
    svc_idx = next(i for i, t in enumerate(tasks) if "ansible.builtin.systemd" in t)
    assert pkg_idx < copy_idx < svc_idx, "tasks must run in order: package install -> file deploy -> service enable"

    pkg = tasks[pkg_idx]["ansible.builtin.package"]
    assert pkg == {"name": "nginx", "state": "present"}

    copy_args = tasks[copy_idx]["ansible.builtin.copy"]
    assert copy_args["dest"] == "/etc/nginx/sites-enabled/foo"
    assert "server" in copy_args["content"]

    svc = tasks[svc_idx]["ansible.builtin.systemd"]
    assert svc["name"] == "nginx.service"
    assert svc["enabled"] is True
    assert svc["state"] == "started"


# --- extract_file_content ----------------------------------------------


def test_extract_file_content_returns_stdout_on_success():
    runner = lambda cmd, **kw: _completed(stdout="hello\n")
    assert ans.extract_file_content("cid", "/etc/x", runner=runner) == "hello\n"


def test_extract_file_content_returns_none_on_nonzero_exit():
    runner = lambda cmd, **kw: _completed(returncode=1, stderr="no such file")
    assert ans.extract_file_content("cid", "/etc/x", runner=runner) is None


def test_extract_file_content_returns_none_when_podman_missing():
    def runner(cmd, **kw):
        raise FileNotFoundError("podman")
    assert ans.extract_file_content("cid", "/etc/x", runner=runner) is None


def test_extract_file_content_invokes_podman_exec_cat():
    calls = []

    def runner(cmd, **kw):
        calls.append(list(cmd))
        return _completed(stdout="ok")

    ans.extract_file_content("cid", "/etc/foo", runner=runner)
    assert calls == [["podman", "exec", "cid", "cat", "/etc/foo"]]
