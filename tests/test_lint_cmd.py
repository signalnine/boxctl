"""Tests for lint CLI command."""

import pytest
from pathlib import Path

from boxctl.cli import cmd_lint, create_parser


VALID_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health]
#   brief: Valid script

def run(args, output, context):
    return 0
'''

INVALID_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   tags: [health]
#   brief: Missing category

def run(args, output, context):
    return 0
'''


class TestLintCommand:
    """Tests for lint command."""

    def test_lint_valid_script(self, tmp_path, capsys):
        """Lint reports no errors for valid script."""
        (tmp_path / "valid.py").write_text(VALID_SCRIPT)

        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "lint"])
        result = cmd_lint(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "0 error(s)" in captured.out

    def test_lint_invalid_script(self, tmp_path, capsys):
        """Lint reports errors for invalid script."""
        (tmp_path / "invalid.py").write_text(INVALID_SCRIPT)

        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "lint"])
        result = cmd_lint(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "ERROR" in captured.out

    def test_lint_specific_script(self, tmp_path, capsys):
        """Lint specific script by name."""
        (tmp_path / "target.py").write_text(VALID_SCRIPT)
        (tmp_path / "other.py").write_text(INVALID_SCRIPT)

        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "lint", "target.py"])
        result = cmd_lint(args)

        assert result == 0  # Only linted the valid one

    def test_lint_json_output(self, tmp_path, capsys):
        """Lint supports JSON output."""
        (tmp_path / "test.py").write_text(VALID_SCRIPT)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "--format", "json",
            "lint",
        ])
        result = cmd_lint(args)

        captured = capsys.readouterr()
        assert '"results"' in captured.out
