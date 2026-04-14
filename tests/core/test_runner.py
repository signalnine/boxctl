"""Tests for script runner."""

import subprocess
import pytest
from pathlib import Path

from boxctl.core.runner import run_script, ScriptResult


SAMPLE_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/test
#   tags: [test]
#   brief: Test script

import sys
print("hello from script")
sys.exit(0)
'''

FAILING_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/test
#   tags: [test]
#   brief: Failing script

import sys
print("about to fail", file=sys.stderr)
sys.exit(1)
'''

SLOW_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/test
#   tags: [test]
#   brief: Slow script

import time
time.sleep(10)
'''


class TestScriptResult:
    """Tests for ScriptResult dataclass."""

    def test_success_property(self):
        """success is True when returncode is 0."""
        result = ScriptResult(
            script_name="test.py",
            returncode=0,
            stdout="output",
            stderr="",
            timed_out=False,
        )
        assert result.success is True

    def test_success_false_on_nonzero(self):
        """success is False when returncode is non-zero."""
        result = ScriptResult(
            script_name="test.py",
            returncode=1,
            stdout="",
            stderr="error",
            timed_out=False,
        )
        assert result.success is False

    def test_success_false_on_timeout(self):
        """success is False when timed_out is True."""
        result = ScriptResult(
            script_name="test.py",
            returncode=None,
            stdout="",
            stderr="",
            timed_out=True,
        )
        assert result.success is False


class TestRunScript:
    """Tests for run_script function."""

    def test_runs_script_successfully(self, tmp_path):
        """Runs script and captures output."""
        script_file = tmp_path / "test.py"
        script_file.write_text(SAMPLE_SCRIPT)
        script_file.chmod(0o755)

        result = run_script(script_file)

        assert result.success is True
        assert result.returncode == 0
        assert "hello from script" in result.stdout
        assert result.timed_out is False

    def test_captures_failure(self, tmp_path):
        """Captures non-zero exit code and stderr."""
        script_file = tmp_path / "fail.py"
        script_file.write_text(FAILING_SCRIPT)
        script_file.chmod(0o755)

        result = run_script(script_file)

        assert result.success is False
        assert result.returncode == 1
        assert "about to fail" in result.stderr

    def test_respects_timeout(self, tmp_path):
        """Times out slow scripts."""
        script_file = tmp_path / "slow.py"
        script_file.write_text(SLOW_SCRIPT)
        script_file.chmod(0o755)

        result = run_script(script_file, timeout=1)

        assert result.success is False
        assert result.timed_out is True
        assert result.returncode is None

    def test_passes_arguments(self, tmp_path):
        """Passes arguments to script."""
        script = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/test
#   tags: [test]
#   brief: Args script

import sys
print(" ".join(sys.argv[1:]))
'''
        script_file = tmp_path / "args.py"
        script_file.write_text(script)
        script_file.chmod(0o755)

        result = run_script(script_file, args=["--foo", "bar"])

        assert "--foo bar" in result.stdout

    def test_script_name_in_result(self, tmp_path):
        """Result includes script name."""
        script_file = tmp_path / "named.py"
        script_file.write_text(SAMPLE_SCRIPT)
        script_file.chmod(0o755)

        result = run_script(script_file)

        assert result.script_name == "named.py"

    def test_uses_context_when_provided(self, mock_context):
        """Uses provided context for execution."""
        ctx = mock_context(
            tools_available=["python3"],
            command_outputs={
                ("python3", "/path/to/script.py"): "mocked output",
            }
        )

        result = run_script(
            Path("/path/to/script.py"),
            context=ctx,
        )

        assert result.stdout == "mocked output"
        assert ["python3", "/path/to/script.py"] in ctx.commands_run


class TestSudoPath:
    """Exercises the sudo branch of run_script via the MockContext."""

    def test_sudo_prepends_sudo(self, mock_context, monkeypatch):
        monkeypatch.delenv("PYTHONPATH", raising=False)
        ctx = mock_context(
            tools_available=["python3", "sudo"],
            command_outputs={("sudo", "python3", "/p/s.py"): "ok"},
        )
        run_script(Path("/p/s.py"), use_sudo=True, context=ctx)
        assert ["sudo", "python3", "/p/s.py"] in ctx.commands_run

    def test_sudo_with_pythonpath_passes_as_env_assignment(self, mock_context, monkeypatch):
        monkeypatch.setenv("PYTHONPATH", "/some/where:/lib")
        ctx = mock_context(
            tools_available=["python3", "sudo"],
            command_outputs={
                ("sudo", "PYTHONPATH=/some/where:/lib", "python3", "/p/s.py"): "ok",
            },
        )
        run_script(Path("/p/s.py"), use_sudo=True, context=ctx)
        # Each element is a separate argv token -- no shell eval of the path.
        last = ctx.commands_run[-1]
        assert last[:4] == ["sudo", "PYTHONPATH=/some/where:/lib", "python3", "/p/s.py"]
