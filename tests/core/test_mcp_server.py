"""Tests for the MCP server tool layer."""

import asyncio
from pathlib import Path

import pytest

from boxctl.core.mcp_server import (
    create_server,
    list_scripts_tool,
    run_script_tool,
    search_scripts_tool,
    show_script_tool,
)


SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"


class TestListTool:
    def test_returns_name_category_brief_tags(self):
        result = list_scripts_tool(SCRIPTS_DIR)
        assert len(result) > 0
        first = result[0]
        assert set(first.keys()) >= {"name", "category", "brief", "tags"}

    def test_category_prefix_filter(self):
        result = list_scripts_tool(SCRIPTS_DIR, category="baremetal")
        assert len(result) > 0
        assert all(r["category"].startswith("baremetal") for r in result)

    def test_tag_filter(self):
        result = list_scripts_tool(SCRIPTS_DIR, tag="load")
        assert len(result) > 0
        assert all("load" in r["tags"] for r in result)

    def test_no_match_empty(self):
        assert list_scripts_tool(SCRIPTS_DIR, category="nosuchcategory") == []


class TestSearchTool:
    def test_returns_matches(self):
        result = search_scripts_tool(SCRIPTS_DIR, "load")
        assert len(result) > 0
        assert all(set(r.keys()) >= {"name", "category", "brief"} for r in result)

    def test_case_insensitive(self):
        a = search_scripts_tool(SCRIPTS_DIR, "LOAD")
        b = search_scripts_tool(SCRIPTS_DIR, "load")
        assert [r["name"] for r in a] == [r["name"] for r in b]

    def test_sorted_by_name(self):
        result = search_scripts_tool(SCRIPTS_DIR, "disk")
        names = [r["name"] for r in result]
        assert names == sorted(names)

    def test_no_match_empty(self):
        assert search_scripts_tool(SCRIPTS_DIR, "zzz_nomatch_zzz") == []


class TestShowTool:
    def test_known_script(self):
        result = show_script_tool(SCRIPTS_DIR, "loadavg_analyzer")
        assert result["name"].startswith("loadavg_analyzer")
        assert "category" in result
        assert "tags" in result
        assert "brief" in result

    def test_accepts_dotpy(self):
        result = show_script_tool(SCRIPTS_DIR, "loadavg_analyzer.py")
        assert "error" not in result

    def test_unknown(self):
        result = show_script_tool(SCRIPTS_DIR, "no_such_script_exists")
        assert "error" in result
        assert "not found" in result["error"]


class TestRunTool:
    def test_unknown_script(self):
        result = run_script_tool(SCRIPTS_DIR, "no_such_script_exists")
        assert "error" in result

    def test_known_script_returns_shape(self):
        # Pick a lightweight always-available script. loadavg_analyzer reads /proc/loadavg.
        result = run_script_tool(SCRIPTS_DIR, "loadavg_analyzer", args=["--format", "json"], timeout=10)
        assert set(result.keys()) == {"exit_code", "stdout", "stderr", "timed_out"}
        assert isinstance(result["exit_code"], int)
        assert result["timed_out"] is False


class TestRunToolRedaction:
    def _fake_script(self, tmp_path):
        scripts_dir = tmp_path / "scripts" / "baremetal"
        scripts_dir.mkdir(parents=True)
        p = scripts_dir / "leaky.py"
        p.write_text(
            "#!/usr/bin/env python3\n"
            "# boxctl:\n"
            "#   category: baremetal/test\n"
            "#   tags: [test]\n"
            "#   requires: []\n"
            "#   privilege: user\n"
            "#   related: []\n"
            "#   brief: leak an AWS key for redaction tests\n"
            "print('aws AKIAIOSFODNN7EXAMPLE leaked')\n"
        )
        return tmp_path

    def test_default_redacts_stdout(self, tmp_path):
        root = self._fake_script(tmp_path)
        result = run_script_tool(root, "leaky", timeout=10)
        assert "AKIA" not in result["stdout"]
        assert "[REDACTED:aws-key]" in result["stdout"]

    def test_opt_out_preserves_raw(self, tmp_path):
        root = self._fake_script(tmp_path)
        result = run_script_tool(root, "leaky", timeout=10, redact=False)
        assert "AKIAIOSFODNN7EXAMPLE" in result["stdout"]

    def test_env_var_disables(self, tmp_path, monkeypatch):
        monkeypatch.setenv("BOXCTL_NO_REDACT", "1")
        root = self._fake_script(tmp_path)
        result = run_script_tool(root, "leaky", timeout=10)
        assert "AKIAIOSFODNN7EXAMPLE" in result["stdout"]

    def test_privileged_script_uses_sudo(self, tmp_path, monkeypatch):
        """A script with privilege: root routes through sudo in run_script."""
        scripts_dir = tmp_path / "scripts" / "baremetal"
        scripts_dir.mkdir(parents=True)
        p = scripts_dir / "needs_root.py"
        p.write_text(
            "#!/usr/bin/env python3\n"
            "# boxctl:\n"
            "#   category: baremetal/test\n"
            "#   tags: [test]\n"
            "#   requires: []\n"
            "#   privilege: root\n"
            "#   related: []\n"
            "#   brief: needs sudo\n"
            "pass\n"
        )

        import boxctl.core.mcp_server as mcp_mod
        from boxctl.core.runner import ScriptResult

        captured = {}

        def fake_run_script(script_path, args=None, timeout=60, context=None, use_sudo=False):
            captured["use_sudo"] = use_sudo
            return ScriptResult(
                script_name=script_path.name, returncode=0, stdout="", stderr="", timed_out=False
            )

        monkeypatch.setattr(mcp_mod, "run_script", fake_run_script)
        res = run_script_tool(tmp_path, "needs_root", timeout=5)
        assert captured["use_sudo"] is True
        assert res["exit_code"] == 0


class TestCreateServer:
    def test_registers_four_tools(self):
        server = create_server(SCRIPTS_DIR)
        tools = asyncio.run(server.list_tools())
        names = {t.name for t in tools}
        assert names == {"list_scripts", "search_scripts", "show_script", "run_script"}


class TestCLIIntegration:
    def test_mcp_subcommand_registered(self):
        from boxctl.cli import create_parser
        parser = create_parser()
        # Parse with mcp subcommand; should not raise SystemExit.
        args = parser.parse_args(["mcp"])
        assert args.command == "mcp"
