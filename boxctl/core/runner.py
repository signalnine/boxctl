"""Script execution."""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from boxctl.core.metadata import parse_metadata

if TYPE_CHECKING:
    from boxctl.core.context import Context


def needs_privilege(script_path: Path) -> bool:
    """
    Check if script requires root privilege.

    Args:
        script_path: Path to the script

    Returns:
        True if script has privilege: root
    """
    try:
        content = script_path.read_text()
        metadata = parse_metadata(content)
        if metadata is None:
            return False
        return metadata.get("privilege") == "root"
    except (OSError, Exception):
        return False


@dataclass
class ScriptResult:
    """Result of running a script."""

    script_name: str
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool

    @property
    def success(self) -> bool:
        """True if script completed successfully."""
        return self.returncode == 0 and not self.timed_out


def run_script(
    script_path: Path,
    args: list[str] | None = None,
    timeout: int = 60,
    context: "Context | None" = None,
    use_sudo: bool = False,
) -> ScriptResult:
    """
    Run a script and capture its output.

    Args:
        script_path: Path to the script to run
        args: Arguments to pass to the script
        timeout: Timeout in seconds
        context: Optional execution context (for testing)
        use_sudo: Whether to run with sudo

    Returns:
        ScriptResult with output and exit code
    """
    cmd = ["python3", str(script_path)]
    if args:
        cmd.extend(args)

    if use_sudo:
        # Forward boxctl's import root to sudo. ``pip install -e --user``
        # registers the package via .pth files in the user's site-packages,
        # which root's python3 doesn't see -- without this, every root-priv
        # script crashes with ``ModuleNotFoundError: No module named 'boxctl'``.
        import boxctl
        boxctl_root = str(Path(boxctl.__file__).resolve().parent.parent)
        existing = os.environ.get("PYTHONPATH", "")
        parts = [p for p in existing.split(os.pathsep) if p]
        if boxctl_root not in parts:
            parts.insert(0, boxctl_root)
        cmd = ["sudo", f"PYTHONPATH={os.pathsep.join(parts)}"] + cmd

    if context is not None:
        # Use provided context (for testing)
        try:
            result = context.run(cmd, timeout=timeout)
            return ScriptResult(
                script_name=script_path.name,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                timed_out=False,
            )
        except subprocess.TimeoutExpired:
            return ScriptResult(
                script_name=script_path.name,
                returncode=None,
                stdout="",
                stderr="",
                timed_out=True,
            )

    # Direct execution
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=os.environ,
        )
        return ScriptResult(
            script_name=script_path.name,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=False,
        )
    except subprocess.TimeoutExpired:
        return ScriptResult(
            script_name=script_path.name,
            returncode=None,
            stdout="",
            stderr="",
            timed_out=True,
        )
