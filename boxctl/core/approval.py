"""Human approval gate for generated playbooks (issue boxctl-n2m.7).

Provides:
- summarize_playbook: parse a playbook YAML and extract a structured
  task summary suitable for display.
- render_summary: format the summary as colored text (or plain when
  color is disabled).
- prompt_approval: read a y/n decision from a stream.
- log_decision: append a JSONL audit entry recording the decision,
  timestamp, and current user.

Design choices:
- Default rejects on blank input or EOF -- approval must be explicit.
- Logs decisions for both approve and reject paths (the audit trail
  is the value, not the apply).
- Color respects NO_COLOR (de-facto standard) and BOXCTL_NO_COLOR.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

import yaml


_SIG_FIELD = "sig"


def _audit_key() -> bytes | None:
    """Return the HMAC key bytes if BOXCTL_AUDIT_KEY is set, else None."""
    raw = os.environ.get("BOXCTL_AUDIT_KEY")
    if not raw:
        return None
    return raw.encode("utf-8")


def _entry_payload(entry: dict[str, Any]) -> bytes:
    """Canonical JSON representation of an entry minus its signature.

    Sorted keys keep the encoding stable across Python versions and platforms;
    without that, two JSON encoders that emit fields in different orders
    would produce different MACs.
    """
    payload = {k: v for k, v in entry.items() if k != _SIG_FIELD}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(entry: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _entry_payload(entry), hashlib.sha256).hexdigest()


_RESET = "\x1b[0m"
_GREEN = "\x1b[32m"
_RED = "\x1b[31m"
_YELLOW = "\x1b[33m"
_BOLD = "\x1b[1m"


_MODULE_SHORT = {
    "ansible.builtin.package": "package",
    "ansible.builtin.copy": "copy",
    "ansible.builtin.file": "file",
    "ansible.builtin.systemd": "systemd",
}

_SYSTEMD_ADD_STATES = {"started", "restarted", "reloaded"}
_SYSTEMD_REMOVE_STATES = {"stopped", "absent", "masked"}


def _classify_systemd(args: dict[str, Any]) -> str:
    """Decide add/remove/change for a systemd task. Drives the operator's
    +/-/~ marker, so misclassifying a state-only task as remove (the old
    bug) directly undermines the approval gate -- issue boxctl-5bi.

    Precedence: explicit `enabled` wins, then `state` keywords, otherwise
    fall back to `change` (e.g. `daemon_reload`-only tasks).
    """
    enabled = args.get("enabled")
    if enabled is True:
        return "add"
    if enabled is False:
        return "remove"
    state = args.get("state")
    if state in _SYSTEMD_ADD_STATES:
        return "add"
    if state in _SYSTEMD_REMOVE_STATES:
        return "remove"
    return "change"


def _classify_task(task: dict[str, Any]) -> dict[str, Any] | None:
    """Map an Ansible task dict to a {kind, module, target, name} summary entry.

    kind is one of "add", "remove", or "change". Returns None for tasks
    we do not know how to summarize (still safe -- they will appear in
    the raw playbook view).
    """
    name = task.get("name", "")
    for full_module, short in _MODULE_SHORT.items():
        if full_module not in task:
            continue
        args = task[full_module] or {}
        if short == "package":
            target = args.get("name", "")
            kind = "remove" if args.get("state") == "absent" else "add"
            return {"kind": kind, "module": short, "target": target, "name": name}
        if short == "copy":
            return {
                "kind": "add",
                "module": short,
                "target": args.get("dest", ""),
                "name": name,
            }
        if short == "file":
            kind = "remove" if args.get("state") == "absent" else "add"
            return {
                "kind": kind,
                "module": short,
                "target": args.get("path", ""),
                "name": name,
            }
        if short == "systemd":
            return {
                "kind": _classify_systemd(args),
                "module": short,
                "target": args.get("name", ""),
                "name": name,
            }
    return None


def summarize_playbook(playbook: str) -> dict[str, Any]:
    """Parse a playbook YAML string into a structured summary."""
    errors: list[str] = []
    try:
        parsed = yaml.safe_load(playbook)
    except yaml.YAMLError as e:
        return {"tasks": [], "errors": [f"invalid YAML: {e}"]}

    if parsed is None:
        return {"tasks": [], "errors": []}
    if not isinstance(parsed, list):
        return {"tasks": [], "errors": ["playbook root must be a list of plays"]}

    tasks: list[dict[str, Any]] = []
    for play in parsed:
        if not isinstance(play, dict):
            errors.append("play entry is not a mapping")
            continue
        for task in play.get("tasks") or []:
            if not isinstance(task, dict):
                continue
            entry = _classify_task(task)
            if entry is not None:
                tasks.append(entry)
    return {"tasks": tasks, "errors": errors}


def render_summary(summary: dict[str, Any], color: bool) -> str:
    """Format a summary as a multi-line string for display."""
    lines: list[str] = []
    tasks = summary.get("tasks") or []
    errors = summary.get("errors") or []

    if not tasks and not errors:
        lines.append("no changes")
        return "\n".join(lines)

    if tasks:
        header = "Changes:"
        if color:
            header = f"{_BOLD}{header}{_RESET}"
        lines.append(header)
        markers = {"add": "+", "remove": "-", "change": "~"}
        colors = {"add": _GREEN, "remove": _RED, "change": _YELLOW}
        for t in tasks:
            kind = t.get("kind", "?")
            module = t.get("module", "?")
            target = t.get("target", "")
            marker = markers.get(kind, "?")
            line = f"  {marker} {module:<8} {target}"
            if color:
                col = colors.get(kind, _YELLOW)
                line = f"  {col}{marker}{_RESET} {col}{module:<8}{_RESET} {target}"
            lines.append(line)

    if errors:
        header = "Errors:"
        if color:
            header = f"{_BOLD}{_YELLOW}{header}{_RESET}"
        lines.append(header)
        for e in errors:
            line = f"  ! {e}"
            if color:
                line = f"  {_YELLOW}!{_RESET} {e}"
            lines.append(line)

    return "\n".join(lines)


def should_use_color(is_tty: bool) -> bool:
    """True iff color output is appropriate for the current environment."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("BOXCTL_NO_COLOR"):
        return False
    return is_tty


def prompt_approval(stream: TextIO | None = None) -> bool:
    """Read one line from `stream` (default sys.stdin) and return True iff
    it begins with `y` (case-insensitive). Blank lines and EOF return False.
    """
    src = stream if stream is not None else sys.stdin
    try:
        line = src.readline()
    except (EOFError, OSError):
        return False
    if not line:
        return False
    return line.strip().lower().startswith("y")


def default_audit_log_path() -> Path:
    """Resolve where to write the audit log.

    BOXCTL_AUDIT_LOG wins for tests/overrides; otherwise XDG_STATE_HOME
    (or ~/.local/state) under boxctl/audit.jsonl.
    """
    env = os.environ.get("BOXCTL_AUDIT_LOG")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "boxctl" / "audit.jsonl"


def _current_user() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):
        return os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"


def log_decision(
    playbook_path: str,
    decision: str,
    summary: dict[str, Any],
    log_path: Path | None = None,
    playbook_hash: str | None = None,
) -> Path:
    """Append a decision record to the audit log. Returns the path written to.

    When ``BOXCTL_AUDIT_KEY`` is set, the entry is HMAC-SHA256 signed under
    that key (gap analysis P0 #1) so a forged "approved" line stuck into the
    log file by anyone with write access is detectable via
    ``verify_audit_log``. When the key is unset, entries are written unsigned
    so existing logs (and dev workflows that don't care about integrity)
    keep working.

    ``playbook_hash`` is recorded alongside the path so a swap-after-display
    attack (P0 #2) can't make the audit record describe content the operator
    didn't actually see.
    """
    target = log_path if log_path is not None else default_audit_log_path()
    # Refuse to follow symlinks -- writing to /etc/hostname via a symlink
    # named audit.jsonl is a real risk in any shared-state-dir setup.
    if target.is_symlink():
        raise PermissionError(f"refusing to write audit log via symlink: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": _current_user(),
        "playbook": playbook_path,
        "decision": decision,
        "task_count": len(summary.get("tasks") or []),
    }
    if playbook_hash:
        entry["playbook_hash"] = playbook_hash
    key = _audit_key()
    if key is not None:
        entry[_SIG_FIELD] = _sign(entry, key)
    with open(target, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return target


def verify_audit_log(path: Path) -> dict[str, Any]:
    """Walk the audit log, classify each line as valid/invalid/unsigned.

    Returns ``{"valid": int, "invalid": [line_no...], "unsigned": int,
    "malformed": [line_no...]}``. Verification requires
    ``BOXCTL_AUDIT_KEY`` to be set (mirroring how ``log_decision`` signs
    only when a key is available). Lines without a ``sig`` field count as
    unsigned -- pre-HMAC rollouts kept readable, but a security tool can
    flag them.
    """
    key = _audit_key()
    if key is None:
        raise RuntimeError(
            "BOXCTL_AUDIT_KEY must be set to verify audit log integrity"
        )
    valid = 0
    unsigned = 0
    invalid: list[int] = []
    malformed: list[int] = []
    if not Path(path).exists():
        return {"valid": 0, "invalid": [], "unsigned": 0, "malformed": []}
    with open(path) as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                malformed.append(lineno)
                continue
            if not isinstance(entry, dict):
                malformed.append(lineno)
                continue
            sig = entry.get(_SIG_FIELD)
            if sig is None:
                unsigned += 1
                continue
            expected = _sign(entry, key)
            # Constant-time compare keeps the verifier from leaking
            # signature bytes through timing.
            if hmac.compare_digest(expected, sig):
                valid += 1
            else:
                invalid.append(lineno)
    return {
        "valid": valid,
        "invalid": invalid,
        "unsigned": unsigned,
        "malformed": malformed,
    }
