"""SSH-based remote script execution.

Ships a discovered boxctl script's source over stdin to ``python3 -`` on a
remote host and captures structured output. Hosts live in a YAML inventory
(default ``~/.config/boxctl/hosts.yml``) with optional groups for fan-out.
"""

from __future__ import annotations

import getpass
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml


@dataclass
class HostConfig:
    name: str
    host: str
    user: str = field(default_factory=getpass.getuser)
    port: int = 22
    identity: str | None = None


@dataclass
class Inventory:
    hosts: dict[str, HostConfig] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)


def load_hosts(path: Path | str) -> Inventory:
    """Parse YAML inventory; a missing file yields an empty Inventory."""
    p = Path(path)
    if not p.exists():
        return Inventory()
    raw = yaml.safe_load(p.read_text()) or {}
    hosts = {}
    for name, spec in (raw.get("hosts") or {}).items():
        spec = spec or {}
        hosts[name] = HostConfig(
            name=name,
            host=spec.get("host", name),
            user=spec.get("user", getpass.getuser()),
            port=int(spec.get("port", 22)),
            identity=spec.get("identity"),
        )
    groups = {k: list(v) for k, v in (raw.get("groups") or {}).items()}
    return Inventory(hosts=hosts, groups=groups)


def resolve_targets(inv: Inventory, selector: str) -> list[HostConfig]:
    """Resolve one or more host configs from a selector string.

    Accepts comma-separated names and ``group:<name>`` prefixes, e.g.
    ``prod-1``, ``group:web``, or ``prod-1,group:web``.
    """
    out: list[HostConfig] = []
    for part in [p.strip() for p in selector.split(",") if p.strip()]:
        if part.startswith("group:"):
            gname = part[len("group:") :]
            if gname not in inv.groups:
                raise KeyError(f"unknown group: {gname}")
            for hname in inv.groups[gname]:
                if hname not in inv.hosts:
                    raise KeyError(f"unknown host in group {gname}: {hname}")
                out.append(inv.hosts[hname])
        else:
            if part not in inv.hosts:
                raise KeyError(f"unknown host: {part}")
            out.append(inv.hosts[part])
    return out


def build_ssh_cmd(h: HostConfig, remote_cmd: str) -> list[str]:
    """Construct an argv list for invoking ``remote_cmd`` via ssh on host ``h``."""
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
    ]
    if h.port != 22:
        cmd += ["-p", str(h.port)]
    if h.identity:
        cmd += ["-i", h.identity]
    cmd += [f"{h.user}@{h.host}", remote_cmd]
    return cmd


Runner = Callable[..., subprocess.CompletedProcess]


def run_script_remote(
    script_path: Path,
    host: HostConfig,
    args: list[str] | None = None,
    timeout: int = 60,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Execute a local script remotely by piping its source to ``python3 -``."""
    args = args or []
    source = Path(script_path).read_text()
    quoted_args = " ".join(_shquote(a) for a in args)
    remote_cmd = f"python3 - {quoted_args}" if quoted_args else "python3 -"
    cmd = build_ssh_cmd(host, remote_cmd)
    run = runner if runner is not None else subprocess.run

    try:
        result = run(cmd, input=source, capture_output=True, text=True, timeout=timeout)
        return {
            "host": host.name,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "host": host.name,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"timed out after {timeout}s",
            "timed_out": True,
        }
    except FileNotFoundError:
        return {
            "host": host.name,
            "exit_code": 2,
            "stdout": "",
            "stderr": "ssh not found",
            "timed_out": False,
        }


def _shquote(s: str) -> str:
    if not s or any(c in s for c in " \t\n\"'\\$`"):
        return "'" + s.replace("'", "'\\''") + "'"
    return s


DEFAULT_INVENTORY = Path.home() / ".config" / "boxctl" / "hosts.yml"
