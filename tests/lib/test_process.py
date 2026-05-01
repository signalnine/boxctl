"""Tests for process utilities."""

import pytest
import subprocess

from boxctl.lib.process import run_command, CommandError, check_tool


class TestRunCommand:
    """Tests for run_command function."""

    def test_runs_simple_command(self, mock_context):
        """Runs command and returns output."""
        ctx = mock_context(
            tools_available=["echo"],
            command_outputs={("echo", "hello"): "hello\n"},
        )

        output = run_command(["echo", "hello"], context=ctx)

        assert output == "hello\n"

    def test_raises_on_failure(self, mock_context):
        """Raises CommandError on non-zero exit when check=True."""
        ctx = mock_context(
            tools_available=["false"],
            command_outputs={("false",): subprocess.CalledProcessError(1, "false")},
        )

        with pytest.raises(CommandError, match="Command failed"):
            run_command(["false"], context=ctx, check=True)

    def test_returns_empty_on_quiet_failure(self, mock_context):
        """Returns None when check=False and command fails."""
        ctx = mock_context(
            tools_available=["false"],
            command_outputs={("false",): ""},
        )

        output = run_command(["false"], context=ctx)

        assert output == ""

    def test_returns_empty_when_check_false_and_subprocess_raises(self, mock_context):
        """check=False swallows subprocess exceptions and returns empty string."""
        ctx = mock_context(
            command_outputs={
                ("/nonexistent/binary",): FileNotFoundError("/nonexistent/binary"),
            },
        )

        output = run_command(["/nonexistent/binary"], context=ctx, check=False)

        assert output == ""

    def test_raises_when_check_true_and_subprocess_raises(self, mock_context):
        """check=True surfaces subprocess exceptions as CommandError."""
        ctx = mock_context(
            command_outputs={
                ("/nonexistent/binary",): FileNotFoundError("/nonexistent/binary"),
            },
        )

        with pytest.raises(CommandError, match="Command failed"):
            run_command(["/nonexistent/binary"], context=ctx, check=True)


class TestCheckTool:
    """Tests for check_tool function."""

    def test_returns_true_for_available_tool(self, mock_context):
        """Returns True when tool is in PATH."""
        ctx = mock_context(tools_available=["smartctl"])

        assert check_tool("smartctl", context=ctx) is True

    def test_returns_false_for_missing_tool(self, mock_context):
        """Returns False when tool is not in PATH."""
        ctx = mock_context(tools_available=[])

        assert check_tool("nonexistent", context=ctx) is False

    def test_raises_when_required(self, mock_context):
        """Raises CommandError when required tool is missing."""
        ctx = mock_context(tools_available=[])

        with pytest.raises(CommandError, match="Required tool"):
            check_tool("smartctl", required=True, context=ctx)
