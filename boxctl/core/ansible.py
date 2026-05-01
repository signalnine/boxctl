"""Ansible playbook generation from sandbox diffs (issue boxctl-n2m.6).

Converts a diff produced by `sandbox.diff_sandbox()` into an Ansible
playbook that, when applied to a fresh host, reproduces the sandbox
mutations: package installs, /etc/* configuration files, and unit-state
changes.

The playbook is a single play targeting `hosts: all` with `become: true`.
File contents under /etc/ are extracted from the live container via
`podman exec cat` when a runner + container_id are available; otherwise
copy tasks are emitted with no content (the operator fills them in).
"""

from __future__ import annotations

import subprocess
from typing import Any, Callable

import yaml

Runner = Callable[..., subprocess.CompletedProcess]


def _default_runner(cmd, **kwargs):
    return subprocess.run(cmd, **kwargs)


def extract_file_content(
    container_id: str, path: str, runner: Runner | None = None
) -> str | None:
    """Return file content from inside the container, or None on any failure."""
    run = runner or _default_runner
    try:
        result = run(
            ["podman", "exec", container_id, "cat", path],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _is_leaf(path: str, all_paths: set[str]) -> bool:
    """True iff no other path in the diff is a strict descendant of `path`."""
    prefix = path.rstrip("/") + "/"
    for p in all_paths:
        if p == path:
            continue
        if p.startswith(prefix):
            return False
    return True


def _parse_unit_entry(entry: str) -> tuple[str, str]:
    """Split `name\\tstate` (or `name\\told -> new`) into (name, last_state)."""
    name_part, _, rest = entry.partition("\t")
    name = name_part.strip()
    rest = rest.strip()
    if "->" in rest:
        rest = rest.split("->")[-1].strip()
    return name, rest


def _package_tasks(diff: dict[str, Any]) -> list[dict[str, Any]]:
    pkgs = (diff.get("package_changes") or {}).get("added") or []
    return [
        {
            "name": f"Install package {pkg}",
            "ansible.builtin.package": {"name": pkg, "state": "present"},
        }
        for pkg in pkgs
    ]


def _file_tasks(
    diff: dict[str, Any],
    container_id: str | None,
    runner: Runner | None,
) -> list[dict[str, Any]]:
    fs_changes = diff.get("fs_changes") or []
    add_paths: list[str] = []
    del_paths: list[str] = []
    for raw in fs_changes:
        s = raw.strip()
        if len(s) < 3 or s[1] != " ":
            continue
        kind, path = s[0], s[2:].strip()
        if not path.startswith("/etc/"):
            continue
        if kind in ("A", "C"):
            add_paths.append(path)
        elif kind == "D":
            del_paths.append(path)

    all_added = set(add_paths)
    leaves = [p for p in add_paths if _is_leaf(p, all_added)]

    tasks: list[dict[str, Any]] = []
    for path in leaves:
        copy_args: dict[str, Any] = {
            "dest": path,
            "owner": "root",
            "group": "root",
            "mode": "0644",
        }
        if container_id:
            content = extract_file_content(container_id, path, runner=runner)
            if content is not None:
                copy_args["content"] = content
        tasks.append({
            "name": f"Deploy {path}",
            "ansible.builtin.copy": copy_args,
        })

    for path in del_paths:
        tasks.append({
            "name": f"Remove {path}",
            "ansible.builtin.file": {"path": path, "state": "absent"},
        })
    return tasks


def _unit_tasks(diff: dict[str, Any]) -> list[dict[str, Any]]:
    units = diff.get("unit_changes") or {}
    tasks: list[dict[str, Any]] = []

    for entry in units.get("added") or []:
        name, state = _parse_unit_entry(entry)
        if not name or state != "enabled":
            continue
        tasks.append({
            "name": f"Enable service {name}",
            "ansible.builtin.systemd": {
                "name": name,
                "enabled": True,
                "state": "started",
            },
        })

    for entry in units.get("changed") or []:
        name, state = _parse_unit_entry(entry)
        if not name:
            continue
        if state == "enabled":
            tasks.append({
                "name": f"Enable service {name}",
                "ansible.builtin.systemd": {
                    "name": name,
                    "enabled": True,
                    "state": "started",
                },
            })
        elif state == "disabled":
            tasks.append({
                "name": f"Disable service {name}",
                "ansible.builtin.systemd": {
                    "name": name,
                    "enabled": False,
                    "state": "stopped",
                },
            })

    return tasks


def generate_playbook(
    diff: dict[str, Any],
    container_id: str | None = None,
    runner: Runner | None = None,
    play_name: str | None = None,
) -> str:
    """Convert a sandbox diff into an Ansible playbook YAML string.

    Task ordering: packages first (so files target paths owned by the
    package), then file deploys, then service enable/disable.

    `container_id` defaults to `diff["container_id"]` when present; pass
    None explicitly to skip file-content extraction.
    """
    cid = container_id if container_id is not None else diff.get("container_id")
    name = diff.get("name", "sandbox")
    title = play_name or f"Apply changes from sandbox {name}"

    tasks: list[dict[str, Any]] = []
    tasks.extend(_package_tasks(diff))
    tasks.extend(_file_tasks(diff, cid, runner))
    tasks.extend(_unit_tasks(diff))

    play = {
        "name": title,
        "hosts": "all",
        "become": True,
        "tasks": tasks,
    }
    return yaml.safe_dump([play], sort_keys=False, default_flow_style=False)
