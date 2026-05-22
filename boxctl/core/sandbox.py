"""Container sandbox layer for mutation experiments (issue boxctl-n2m.5).

Wraps podman so a boxctl agent can spawn an ephemeral container, capture a
snapshot of relevant host state (currently: systemd unit-files), let an
operator mutate the sandbox, and observe a filesystem + unit-state diff
before destroying it.

The podman backend is invoked through a `runner` callable that returns a
`subprocess.CompletedProcess`, mirroring the dependency-injection pattern
used by `boxctl.core.ssh`. Tests pass a fake runner; production passes
`subprocess.run`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

Runner = Callable[..., subprocess.CompletedProcess]

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

# Image references arrive from operator input and the daemon's /sandbox
# POST body. Restrict to the OCI grammar plus optional registry, port, tag,
# or digest. List-based subprocess prevents shell injection regardless,
# but rejecting nonsense up front gives a clearer error than letting
# `podman pull` fail and avoids surprising registries (gap analysis P0 #5
# / P1 #8).
_IMAGE_RE = re.compile(
    r"^"
    r"(?:[A-Za-z0-9][A-Za-z0-9._-]*(?::[0-9]+)?/)?"            # optional registry[:port]/
    r"[A-Za-z0-9][A-Za-z0-9._/-]*"                              # repo path
    r"(?::[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})?"               # :tag or @sha256:digest
    r"$"
)
_IMAGE_MAX_LEN = 256

DEFAULT_IMAGE = "docker.io/library/debian:stable"

DEFAULT_MEMORY = "512m"
DEFAULT_PIDS_LIMIT = 256


def validate_image_ref(image: str) -> str:
    """Reject malformed image references before they reach podman.

    Returns the input on success; raises ValueError on bad input. The
    regex deliberately disallows whitespace, shell metacharacters, and
    overlong strings -- legitimate OCI refs need none of those.
    """
    if not isinstance(image, str) or not image:
        raise ValueError("image reference is required")
    if len(image) > _IMAGE_MAX_LEN:
        raise ValueError(f"image reference too long ({len(image)} > {_IMAGE_MAX_LEN})")
    if not _IMAGE_RE.match(image):
        raise ValueError(f"invalid image reference: {image!r}")
    return image


@dataclass
class Sandbox:
    name: str
    container_id: str
    image: str
    source_host: str | None
    created_at: float
    units_snapshot: list[str] = field(default_factory=list)
    packages_snapshot: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Sandbox":
        return cls(
            name=d["name"],
            container_id=d["container_id"],
            image=d["image"],
            source_host=d.get("source_host"),
            created_at=float(d["created_at"]),
            units_snapshot=list(d.get("units_snapshot") or []),
            packages_snapshot=list(d.get("packages_snapshot") or []),
        )


def state_dir() -> Path:
    """Directory holding sandbox state JSON files.

    Honours BOXCTL_SANDBOX_STATE_DIR for tests; otherwise falls back to
    XDG_STATE_HOME (or ~/.local/share) under boxctl/sandboxes.
    """
    env = os.environ.get("BOXCTL_SANDBOX_STATE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        base = Path(xdg)
    else:
        base = Path.home() / ".local" / "share"
    return base / "boxctl" / "sandboxes"


def _state_file(name: str) -> Path:
    return state_dir() / f"{name}.json"


def _default_runner(cmd, **kwargs):
    return subprocess.run(cmd, **kwargs)


def check_podman(runner: Runner | None = None) -> bool:
    """Return True iff podman is callable and `podman --version` exits 0."""
    run = runner or _default_runner
    try:
        result = run(["podman", "--version"], capture_output=True, text=True)
    except FileNotFoundError:
        return False
    return result.returncode == 0


def _parse_units(stdout: str) -> list[str]:
    out: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # systemctl list-unit-files columns are whitespace-separated.
        parts = line.split()
        if len(parts) < 2:
            continue
        out.append(f"{parts[0]}\t{parts[1]}")
    return sorted(out)


def snapshot_units(host: str | None = None, runner: Runner | None = None) -> list[str]:
    """Return sorted [\"unit\\tstate\", ...] from the local host.

    `host` is reserved for future remote support; current behavior runs
    systemctl locally regardless. Remote snapshotting will plug in once
    sandbox-from-remote-host work lands.
    """
    run = runner or _default_runner
    cmd = ["systemctl", "list-unit-files", "--no-legend", "--no-pager"]
    try:
        result = run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return []
    if result.returncode != 0:
        return []
    return _parse_units(result.stdout)


def _parse_packages(stdout: str) -> list[str]:
    out: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        out.add(line.split()[0])
    return sorted(out)


def snapshot_packages(host: str | None = None, runner: Runner | None = None) -> list[str]:
    """Return sorted list of installed dpkg package names from the local host.

    `host` is reserved for future remote support, mirroring snapshot_units.
    Returns [] if dpkg-query is unavailable or fails (non-Debian hosts).
    """
    run = runner or _default_runner
    cmd = ["dpkg-query", "-W", "-f=${Package}\n"]
    try:
        result = run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return []
    if result.returncode != 0:
        return []
    return _parse_packages(result.stdout)


def _validate_name(name: str) -> str:
    if not _NAME_RE.match(name or ""):
        raise ValueError(
            f"invalid sandbox name {name!r}: must match {_NAME_RE.pattern}"
        )
    return name


def _isolation_args() -> list[str]:
    """Safe-by-default flags for ``podman run``.

    A sandbox is for observing what mutations *would* do on a host -- it
    is not a containment boundary for adversarial code. Even so, the cost
    of the obvious flags is zero and the upside is that a runaway
    experiment can't reach the host network, escalate via Linux caps, or
    fork-bomb the box. (gap analysis P0 #4)
    """
    return [
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs=/tmp:rw,size=64m",
        "--tmpfs=/run:rw,size=16m",
        f"--memory={DEFAULT_MEMORY}",
        f"--pids-limit={DEFAULT_PIDS_LIMIT}",
    ]


def create_sandbox(
    name: str,
    image: str = DEFAULT_IMAGE,
    source_host: str | None = None,
    runner: Runner | None = None,
    unsafe: bool = False,
) -> Sandbox:
    """Spawn a long-lived podman container and persist sandbox state.

    By default the container runs with `--network=none`, all capabilities
    dropped, no-new-privileges, read-only rootfs (with tmpfs at /tmp + /run),
    and resource limits. ``unsafe=True`` opts out -- intended for the rare
    case where the operator legitimately needs network access (e.g. apt
    install validation), at which point the looser policy is explicit.
    """
    _validate_name(name)
    validate_image_ref(image)
    sf = _state_file(name)
    sf.parent.mkdir(parents=True, exist_ok=True)
    # Atomic create-if-not-exists: O_CREAT|O_EXCL races against any
    # concurrent caller, so two simultaneous `create_sandbox("x")` calls
    # can't both reach `podman run` and orphan one container.
    # (gap analysis P1 #10)
    try:
        fd = os.open(sf, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise FileExistsError(f"sandbox already exists: {name}")

    run = runner or _default_runner
    isolation = [] if unsafe else _isolation_args()
    cmd = (
        ["podman", "run", "-d", "--name", name]
        + isolation
        + [image, "sleep", "infinity"]
    )
    container_id: str | None = None
    try:
        result = run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"podman run failed (exit {result.returncode}): {result.stderr.strip()}"
            )
        container_id = (result.stdout or "").strip().splitlines()[-1] if result.stdout else ""
        if not container_id:
            raise RuntimeError("podman run produced no container id")

        units = snapshot_units(host=source_host, runner=runner)
        packages = snapshot_packages(host=source_host, runner=runner)

        sandbox = Sandbox(
            name=name,
            container_id=container_id,
            image=image,
            source_host=source_host,
            created_at=time.time(),
            units_snapshot=units,
            packages_snapshot=packages,
        )
        os.write(fd, json.dumps(sandbox.to_dict(), indent=2, sort_keys=True).encode())
    except BaseException:
        # Partial-failure cleanup: if podman did spawn a container but the
        # state write or snapshotting blew up, remove the container so the
        # operator isn't left chasing orphans.
        if container_id:
            try:
                run(
                    ["podman", "rm", "-f", container_id],
                    capture_output=True, text=True,
                )
            except Exception:
                pass
        try:
            os.close(fd)
        finally:
            sf.unlink(missing_ok=True)
        raise
    else:
        os.close(fd)
        return sandbox


def load_sandbox(name: str) -> Sandbox:
    _validate_name(name)
    sf = _state_file(name)
    if not sf.exists():
        raise FileNotFoundError(f"no such sandbox: {name}")
    return Sandbox.from_dict(json.loads(sf.read_text()))


def list_sandboxes() -> list[Sandbox]:
    d = state_dir()
    if not d.exists():
        return []
    out: list[Sandbox] = []
    for p in sorted(d.glob("*.json")):
        try:
            out.append(Sandbox.from_dict(json.loads(p.read_text())))
        except (OSError, ValueError, KeyError):
            continue
    return out


def _diff_units(before: list[str], after: list[str]) -> dict[str, list[str]]:
    before_map = dict(line.split("\t", 1) for line in before if "\t" in line)
    after_map = dict(line.split("\t", 1) for line in after if "\t" in line)

    added_names = sorted(set(after_map) - set(before_map))
    removed_names = sorted(set(before_map) - set(after_map))
    common = sorted(set(before_map) & set(after_map))
    changed = [
        f"{n}\t{before_map[n]} -> {after_map[n]}"
        for n in common
        if before_map[n] != after_map[n]
    ]
    return {
        "added": [f"{n}\t{after_map[n]}" for n in added_names],
        "removed": [f"{n}\t{before_map[n]}" for n in removed_names],
        "changed": changed,
    }


def diff_sandbox(name: str, runner: Runner | None = None) -> dict[str, Any]:
    """Compute filesystem + unit-state diffs against the recorded snapshot."""
    _validate_name(name)
    sandbox = load_sandbox(name)
    run = runner or _default_runner

    fs_result = run(
        ["podman", "diff", sandbox.container_id],
        capture_output=True,
        text=True,
    )
    fs_changes = [
        line for line in (fs_result.stdout or "").splitlines() if line.strip()
    ]

    units_after_result = run(
        [
            "podman",
            "exec",
            sandbox.container_id,
            "systemctl",
            "list-unit-files",
            "--no-legend",
            "--no-pager",
        ],
        capture_output=True,
        text=True,
    )
    units_after = _parse_units(units_after_result.stdout or "")
    unit_changes = _diff_units(sandbox.units_snapshot, units_after)

    packages_after_result = run(
        [
            "podman",
            "exec",
            sandbox.container_id,
            "dpkg-query",
            "-W",
            "-f=${Package}\n",
        ],
        capture_output=True,
        text=True,
    )
    packages_after = _parse_packages(packages_after_result.stdout or "")
    before_pkgs = set(sandbox.packages_snapshot)
    after_pkgs = set(packages_after)
    package_changes = {
        "added": sorted(after_pkgs - before_pkgs),
        "removed": sorted(before_pkgs - after_pkgs),
    }

    return {
        "name": sandbox.name,
        "container_id": sandbox.container_id,
        "fs_changes": fs_changes,
        "unit_changes": unit_changes,
        "package_changes": package_changes,
    }


def destroy_sandbox(name: str, runner: Runner | None = None) -> None:
    """Stop+remove the container and delete the state file.

    Idempotent on the podman side: if `podman rm -f` reports failure
    (typically because the container is already gone) we still remove the
    local state file so the operator is not left with orphaned bookkeeping.
    """
    _validate_name(name)
    sandbox = load_sandbox(name)
    run = runner or _default_runner
    try:
        run(
            ["podman", "rm", "-f", sandbox.container_id],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        # podman not present -- still clean up state.
        pass
    _state_file(name).unlink(missing_ok=True)
