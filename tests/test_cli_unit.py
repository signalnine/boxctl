"""Unit tests for CLI functions."""

import pytest
from pathlib import Path
from io import StringIO
import sys

from boxctl.cli import create_parser, cmd_list, cmd_show, cmd_search, main


SAMPLE_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart]
#   requires: [smartctl]
#   privilege: root
#   brief: Check disk health

def main():
    pass
'''


class TestCreateParser:
    """Tests for create_parser."""

    def test_creates_parser(self):
        """Creates an argument parser."""
        parser = create_parser()
        assert parser is not None

    def test_parser_has_subcommands(self):
        """Parser has expected subcommands."""
        parser = create_parser()
        args = parser.parse_args(["list"])
        assert args.command == "list"


class TestCmdList:
    """Tests for cmd_list function."""

    def test_lists_scripts(self, tmp_path, capsys):
        """Lists discovered scripts."""
        (tmp_path / "test.py").write_text(SAMPLE_SCRIPT)

        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "list"])
        result = cmd_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "test.py" in captured.out

    def test_lists_empty_directory(self, tmp_path, capsys):
        """Handles empty directory."""
        parser = create_parser()
        args = parser.parse_args(["--scripts-dir", str(tmp_path), "list"])
        result = cmd_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No scripts found" in captured.out

    def test_filters_by_category(self, tmp_path, capsys):
        """Filters by category."""
        (tmp_path / "test.py").write_text(SAMPLE_SCRIPT)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "list",
            "--category", "baremetal/disk",
        ])
        result = cmd_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "test.py" in captured.out

    def test_json_format(self, tmp_path, capsys):
        """Outputs JSON format."""
        (tmp_path / "test.py").write_text(SAMPLE_SCRIPT)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "--format", "json",
            "list",
        ])
        result = cmd_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert '"name": "test.py"' in captured.out


class TestCmdShow:
    """Tests for cmd_show function."""

    def test_shows_script_details(self, tmp_path, capsys):
        """Shows script metadata."""
        (tmp_path / "test.py").write_text(SAMPLE_SCRIPT)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "show", "test.py",
        ])
        result = cmd_show(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "test.py" in captured.out
        assert "baremetal/disk" in captured.out

    def test_shows_without_extension(self, tmp_path, capsys):
        """Finds script without .py extension."""
        (tmp_path / "test.py").write_text(SAMPLE_SCRIPT)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "show", "test",
        ])
        result = cmd_show(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "test.py" in captured.out

    def test_shows_not_found(self, tmp_path, capsys):
        """Returns error for missing script."""
        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "show", "missing",
        ])
        result = cmd_show(args)

        assert result == 2
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_show_json_format(self, tmp_path, capsys):
        """Shows JSON format."""
        (tmp_path / "test.py").write_text(SAMPLE_SCRIPT)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "--format", "json",
            "show", "test.py",
        ])
        result = cmd_show(args)

        assert result == 0
        captured = capsys.readouterr()
        assert '"name": "test.py"' in captured.out


class TestCmdSearch:
    """Tests for cmd_search function."""

    def test_searches_by_name(self, tmp_path, capsys):
        """Searches scripts by name."""
        (tmp_path / "test.py").write_text(SAMPLE_SCRIPT)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "search", "test",
        ])
        result = cmd_search(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "test.py" in captured.out

    def test_searches_by_tag(self, tmp_path, capsys):
        """Searches scripts by tag."""
        (tmp_path / "test.py").write_text(SAMPLE_SCRIPT)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "search", "health",
        ])
        result = cmd_search(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "test.py" in captured.out

    def test_searches_no_matches(self, tmp_path, capsys):
        """Handles no search matches."""
        (tmp_path / "test.py").write_text(SAMPLE_SCRIPT)

        parser = create_parser()
        args = parser.parse_args([
            "--scripts-dir", str(tmp_path),
            "search", "nonexistent",
        ])
        result = cmd_search(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No scripts matching" in captured.out


class TestMain:
    """Tests for main function."""

    def test_no_command_shows_help(self, capsys):
        """No command shows help."""
        result = main([])
        assert result == 0

    def test_list_command(self, tmp_path, capsys):
        """List command runs."""
        result = main(["--scripts-dir", str(tmp_path), "list"])
        assert result == 0


class TestCmdRunExitCode:
    """Exit-code propagation from run_script through cmd_run."""

    def _make_script(self, tmp_path):
        p = tmp_path / "scripts" / "baremetal"
        p.mkdir(parents=True)
        s = p / "stub.py"
        s.write_text(
            "#!/usr/bin/env python3\n"
            "# boxctl:\n"
            "#   category: baremetal/test\n"
            "#   tags: [test]\n"
            "#   requires: []\n"
            "#   privilege: user\n"
            "#   related: []\n"
            "#   brief: stub\n"
            "pass\n"
        )
        return tmp_path

    def test_none_returncode_maps_to_1(self, tmp_path, monkeypatch):
        """If runner returns returncode=None (crashed child), cmd_run exits 1, not 0."""
        from boxctl.core.runner import ScriptResult
        from boxctl import cli as cli_mod

        root = self._make_script(tmp_path)

        def fake_run_script(*a, **kw):
            return ScriptResult(
                script_name="stub.py", returncode=None, stdout="", stderr="", timed_out=False
            )

        monkeypatch.setattr(cli_mod, "run_script", fake_run_script)
        rc = main(["--scripts-dir", str(root), "run", "stub"])
        assert rc == 1

    def test_nonzero_returncode_preserved(self, tmp_path, monkeypatch):
        from boxctl.core.runner import ScriptResult
        from boxctl import cli as cli_mod

        root = self._make_script(tmp_path)

        def fake_run_script(*a, **kw):
            return ScriptResult(
                script_name="stub.py", returncode=42, stdout="", stderr="", timed_out=False
            )

        monkeypatch.setattr(cli_mod, "run_script", fake_run_script)
        rc = main(["--scripts-dir", str(root), "run", "stub"])
        assert rc == 42
