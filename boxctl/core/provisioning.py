"""Provision a boxctl-readonly user with a restricted SSH login shell.

boxctl's remote execution ships python source over stdin to ``python3 -``,
so the restricted shell only needs to permit that single invocation form
(plus a couple of harmless probes). Tool-level permissions (smartctl,
mdadm, etc.) are carried by the Unix user's own privileges, not by the
SSH shell allowlist.

Operators can widen the allowlist with ``extra_allowed_commands`` if they
genuinely need non-python invocations over SSH.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Callable

from boxctl.core.ssh import HostConfig, build_ssh_cmd


DEFAULT_SHELL_PATH = "/usr/local/bin/boxctl-restricted-shell"
DEFAULT_USERNAME = "boxctl-readonly"

_BASE_ALLOW = ("python3", "/usr/bin/python3", "true")

_META_CHARS = ";|&<>$`\n"

_ALLOW_RE = re.compile(r"^[A-Za-z0-9_./-]+$")


def _validate_allow_entry(name: str) -> str:
    """Reject allow-list entries containing shell metacharacters or spaces.

    Entries land in a shell ``case`` pattern, so an unvalidated value like
    ``"smartctl; rm -rf /"`` would break script generation at deploy time
    (and, if the shell were ever un-sandboxed, open a real injection path).
    """
    if not name or not _ALLOW_RE.match(name):
        raise ValueError(
            f"invalid allow-list entry: {name!r} "
            f"(must be non-empty and match {_ALLOW_RE.pattern})"
        )
    return name


def build_restricted_shell(extra_allowed: list[str] | None = None) -> str:
    """Render the /bin/sh script that gates SSH_ORIGINAL_COMMAND."""
    validated = [_validate_allow_entry(e) for e in (extra_allowed or [])]
    allow = list(_BASE_ALLOW) + validated
    bare_pattern = "|".join(allow)
    # Rendered for error messages.
    allowed_list = ", ".join(allow)

    # Metacharacter rejection uses alternation patterns (one per char) because
    # dash does not tolerate $, `, and newline inside a bracket expression.
    # Covers: ; | & < > $ ` newline
    meta_cases = "*\\;*|*\\|*|*\\&*|*\\<*|*\\>*|*\\$*|*\\`*"

    return f"""#!/bin/sh
# boxctl restricted login shell. Managed by boxctl source prepare; do not edit.
set -u

cmd="${{SSH_ORIGINAL_COMMAND:-}}"

if [ -z "$cmd" ]; then
    echo "boxctl-restricted-shell: interactive sessions are not permitted" >&2
    exit 126
fi

# Reject shell metacharacters outright: ; | & < > $ `
case "$cmd" in
    {meta_cases})
        echo "boxctl-restricted-shell: shell metacharacters are not permitted" >&2
        exit 126
        ;;
esac
# Reject embedded newlines.
case "$cmd" in
    *"
"*)
        echo "boxctl-restricted-shell: newlines are not permitted" >&2
        exit 126
        ;;
esac

set -- $cmd
bin=$1
shift

case "$bin" in
    {bare_pattern})
        exec "$bin" "$@"
        ;;
    *)
        echo "boxctl-restricted-shell: disallowed command: $bin" >&2
        echo "boxctl-restricted-shell: allowed: {allowed_list}" >&2
        exit 126
        ;;
esac
"""


def build_setup_script(username: str, pubkey: str, shell_path: str) -> str:
    """Render the bash script run on the remote (via sudo bash -s).

    Reads the restricted shell source from stdin FD 3 (not stdin, which this
    script itself occupies). Idempotent: re-running is safe.
    """
    pubkey_q = shlex.quote(pubkey.strip())
    username_q = shlex.quote(username)
    shell_q = shlex.quote(shell_path)

    return f"""#!/bin/bash
set -eu

USERNAME={username_q}
SHELL_PATH={shell_q}
PUBKEY={pubkey_q}

# Read the restricted shell from the heredoc appended below.
SHELL_SRC=$(cat <<'__BOXCTL_SHELL_EOF__'
__SHELL_PLACEHOLDER__
__BOXCTL_SHELL_EOF__
)

# Install the restricted shell.
install -m 0755 /dev/stdin "$SHELL_PATH" <<< "$SHELL_SRC"

# Register the shell with the system if /etc/shells exists.
if [ -f /etc/shells ] && ! grep -qxF "$SHELL_PATH" /etc/shells; then
    echo "$SHELL_PATH" >> /etc/shells
fi

# Create the user if missing.
if ! id -u "$USERNAME" >/dev/null 2>&1; then
    useradd -m -s "$SHELL_PATH" "$USERNAME"
else
    usermod -s "$SHELL_PATH" "$USERNAME"
fi

HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
install -d -m 0700 -o "$USERNAME" -g "$USERNAME" "$HOME_DIR/.ssh"

# Append the pubkey if it isn't already present.
AUTH="$HOME_DIR/.ssh/authorized_keys"
touch "$AUTH"
chmod 0600 "$AUTH"
chown "$USERNAME":"$USERNAME" "$AUTH"
if ! grep -qxF "$PUBKEY" "$AUTH"; then
    echo "$PUBKEY" >> "$AUTH"
fi

echo "boxctl: provisioned $USERNAME with shell $SHELL_PATH"
"""


def _combine(setup: str, shell: str) -> str:
    return setup.replace("__SHELL_PLACEHOLDER__", shell)


Runner = Callable[..., subprocess.CompletedProcess]


def prepare_host(
    host: HostConfig,
    username: str,
    pubkey: str,
    admin_user: str | None = None,
    shell_path: str = DEFAULT_SHELL_PATH,
    extra_allowed: list[str] | None = None,
    timeout: int = 60,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Provision the restricted user on ``host`` over SSH.

    The script is piped via ``sudo bash -s`` on the remote, so the
    connecting user must have passwordless sudo (or the key-auth'd session
    must already have a sudo credential). ``admin_user`` lets callers
    override the connecting user without rewriting the inventory.
    """
    shell_src = build_restricted_shell(extra_allowed=extra_allowed)
    setup_src = build_setup_script(username=username, pubkey=pubkey, shell_path=shell_path)
    full = _combine(setup_src, shell_src)

    conn_host = HostConfig(
        name=host.name,
        host=host.host,
        user=admin_user or host.user,
        port=host.port,
        identity=host.identity,
    )
    cmd = build_ssh_cmd(conn_host, "sudo bash -s")
    run = runner if runner is not None else subprocess.run

    try:
        result = run(cmd, input=full, capture_output=True, text=True, timeout=timeout)
        return {
            "host": host.name,
            "ok": result.returncode == 0,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "host": host.name,
            "ok": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"timed out after {timeout}s",
        }
    except FileNotFoundError:
        return {
            "host": host.name,
            "ok": False,
            "exit_code": 2,
            "stdout": "",
            "stderr": "ssh not found",
        }
