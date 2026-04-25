"""Tests for privilege escalation."""

import pytest
from pathlib import Path

from boxctl.core.runner import run_script, needs_privilege


PRIVILEGED_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health]
#   privilege: root
#   brief: Needs root

print("running as root")
'''

UNPRIVILEGED_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health]
#   brief: No privilege needed

print("running as user")
'''


class TestNeedsPrivilege:
    """Tests for needs_privilege function."""

    def test_returns_true_for_root_privilege(self, tmp_path):
        """Returns True when script has privilege: root."""
        script_file = tmp_path / "priv.py"
        script_file.write_text(PRIVILEGED_SCRIPT)

        assert needs_privilege(script_file) is True

    def test_returns_false_for_no_privilege(self, tmp_path):
        """Returns False when script has no privilege field."""
        script_file = tmp_path / "nopriv.py"
        script_file.write_text(UNPRIVILEGED_SCRIPT)

        assert needs_privilege(script_file) is False

    def test_returns_false_for_user_privilege(self, tmp_path):
        """Returns False when script has privilege: user."""
        script = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/test
#   tags: [test]
#   privilege: user
#   brief: User level

print("user")
'''
        script_file = tmp_path / "user.py"
        script_file.write_text(script)

        assert needs_privilege(script_file) is False


class TestRunScriptWithPrivilege:
    """Tests for run_script with privilege escalation."""

    def test_uses_sudo_for_privileged_script(self, mock_context, tmp_path, monkeypatch):
        """Uses sudo when script requires root privilege."""
        import boxctl

        script_file = tmp_path / "priv.py"
        script_file.write_text(PRIVILEGED_SCRIPT)

        # Runner always prepends boxctl's import root so sudo's python can
        # find the package (user-level editable installs are invisible to root).
        boxctl_root = str(Path(boxctl.__file__).resolve().parent.parent)
        monkeypatch.setenv("PYTHONPATH", ".")
        expected_pp = f"PYTHONPATH={boxctl_root}:."

        ctx = mock_context(
            tools_available=["sudo", "python3"],
            command_outputs={
                ("sudo", expected_pp, "python3", str(script_file)): "running as root\n",
            }
        )

        result = run_script(script_file, context=ctx, use_sudo=True)

        assert result.success is True
        assert ["sudo", expected_pp, "python3", str(script_file)] in ctx.commands_run

    def test_no_sudo_when_not_needed(self, mock_context, tmp_path):
        """Does not use sudo when script doesn't need privilege."""
        script_file = tmp_path / "nopriv.py"
        script_file.write_text(UNPRIVILEGED_SCRIPT)

        ctx = mock_context(
            tools_available=["python3"],
            command_outputs={
                ("python3", str(script_file)): "running as user\n",
            }
        )

        result = run_script(script_file, context=ctx, use_sudo=False)

        assert result.success is True
        assert ["python3", str(script_file)] in ctx.commands_run

    def test_sudo_with_arguments(self, mock_context, tmp_path, monkeypatch):
        """Passes arguments through sudo."""
        import boxctl

        script_file = tmp_path / "priv.py"
        script_file.write_text(PRIVILEGED_SCRIPT)

        boxctl_root = str(Path(boxctl.__file__).resolve().parent.parent)
        monkeypatch.setenv("PYTHONPATH", ".")
        expected_pp = f"PYTHONPATH={boxctl_root}:."

        ctx = mock_context(
            tools_available=["sudo", "python3"],
            command_outputs={
                ("sudo", expected_pp, "python3", str(script_file), "--arg", "value"): "output\n",
            }
        )

        result = run_script(
            script_file,
            args=["--arg", "value"],
            context=ctx,
            use_sudo=True,
        )

        assert result.success is True
        assert ["sudo", expected_pp, "python3", str(script_file), "--arg", "value"] in ctx.commands_run
