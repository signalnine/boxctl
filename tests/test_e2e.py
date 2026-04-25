"""End-to-end tests: real boxctl CLI subprocess, real script discovery + execution.

These tests shell out to ``python -m boxctl`` so they exercise the same code path
users (and agents wrapping the CLI) actually hit -- argparse, discovery, runner,
output, redaction. They are slower than unit tests; a single full run takes a
few seconds.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"


def run_cli(*args: str, env: dict | None = None, input: str | None = None) -> subprocess.CompletedProcess:
    """Invoke ``boxctl`` as a subprocess with the repo's scripts dir wired in."""
    return subprocess.run(
        [sys.executable, "-m", "boxctl", "--scripts-dir", str(SCRIPTS_DIR), *args],
        capture_output=True,
        text=True,
        env=env,
        input=input,
        timeout=60,
    )


# --------------------------------------------------------------------------- #
# Golden-path discovery / inspection
# --------------------------------------------------------------------------- #


class TestDiscoveryGoldenPath:
    def test_list_finds_many_scripts(self):
        r = run_cli("list")
        assert r.returncode == 0
        # The project claims ~315 scripts; if a regression drops us below 100
        # something serious broke.
        assert r.stdout.count("\n") > 100

    def test_list_category_baremetal_only_baremetal(self):
        r = run_cli("list", "--category", "baremetal")
        assert r.returncode == 0
        # At least one known baremetal script shows up.
        assert "loadavg_analyzer" in r.stdout

    def test_list_category_k8s_has_no_baremetal(self):
        r = run_cli("list", "--category", "k8s")
        assert r.returncode == 0
        # Spot-check a baremetal-only name doesn't appear.
        assert "loadavg_analyzer" not in r.stdout

    def test_list_json_emits_one_object_per_line(self):
        r = run_cli("--format", "json", "list", "--category", "baremetal/cpu")
        assert r.returncode == 0
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        assert len(lines) > 0
        for ln in lines:
            obj = json.loads(ln)
            assert {"name", "category", "tags", "brief"} <= obj.keys()
            assert obj["category"].startswith("baremetal/cpu")

    def test_show_known_script_has_metadata_fields(self):
        r = run_cli("show", "loadavg_analyzer")
        assert r.returncode == 0
        assert "loadavg_analyzer" in r.stdout
        assert "baremetal/cpu" in r.stdout
        assert "Tags" in r.stdout or "tags" in r.stdout

    def test_show_unknown_exits_2(self):
        r = run_cli("show", "no_such_script_exists")
        assert r.returncode == 2
        assert "not found" in r.stderr.lower()

    def test_search_substring_matches(self):
        r = run_cli("search", "loadavg")
        assert r.returncode == 0
        assert "loadavg_analyzer" in r.stdout

    def test_search_no_match_prints_notice(self):
        r = run_cli("search", "zzz_definitely_nothing_zzz")
        # Search prints a friendly message and exits 0 on no match.
        assert r.returncode == 0
        assert "no scripts" in r.stdout.lower()


# --------------------------------------------------------------------------- #
# Real script execution
# --------------------------------------------------------------------------- #


class TestRunRealScript:
    """loadavg_analyzer only reads /proc/loadavg so it works in any Linux CI."""

    def test_run_produces_valid_json_structure(self):
        r = run_cli("--format", "json", "run", "loadavg_analyzer")
        # 0 if load healthy, 1 if load threshold exceeded. Either is "ran".
        assert r.returncode in (0, 1)
        assert r.stdout.strip().startswith("{")
        data = json.loads(r.stdout)
        # Core shape regardless of load value.
        assert "status" in data
        assert "cpu_count" in data
        assert "load" in data
        assert "raw" in data["load"]
        assert "1min" in data["load"]["raw"]

    def test_run_unknown_script_exits_2(self):
        r = run_cli("run", "no_such_script_exists")
        assert r.returncode == 2
        assert "not found" in r.stderr.lower()

    def test_run_plain_default_format(self):
        r = run_cli("run", "loadavg_analyzer")
        assert r.returncode in (0, 1)
        # Plain rendering is not JSON -- should not start with '{'.
        assert not r.stdout.strip().startswith("{")
        # Contains the title-cased key from _render_plain.
        assert "Cpu Count" in r.stdout or "cpu_count" in r.stdout


# --------------------------------------------------------------------------- #
# Discovery → show → run chain
# --------------------------------------------------------------------------- #


class TestDiscoveryShowRunChain:
    def test_json_list_entries_can_be_shown_and_run(self):
        """Every name from ``list`` must resolve for ``show`` and ``run``."""
        r = run_cli("--format", "json", "list", "--category", "baremetal/cpu")
        assert r.returncode == 0
        names = [json.loads(ln)["name"] for ln in r.stdout.splitlines() if ln.strip()]
        assert names, "expected at least one baremetal/cpu script"

        # Strip .py suffix to match the name form `boxctl show`/`run` accepts.
        target = names[0].removesuffix(".py")

        s = run_cli("show", target)
        assert s.returncode == 0, f"show failed for {target}: {s.stderr}"

        # Don't actually run every script -- some need tools. Just confirm
        # the framework accepts the name and dispatches (exit 2 == missing
        # tool is fine; the CLI reached runner).
        run = run_cli("--format", "json", "run", target, "--timeout", "10")
        assert run.returncode in (0, 1, 2), f"unexpected rc={run.returncode}"


# --------------------------------------------------------------------------- #
# Fixture-script CLI: redaction end-to-end
# --------------------------------------------------------------------------- #


@pytest.fixture
def leaky_scripts_dir(tmp_path):
    """Minimal scripts tree containing one script that prints an AWS key."""
    d = tmp_path / "baremetal"
    d.mkdir()
    (d / "leaky.py").write_text(
        "#!/usr/bin/env python3\n"
        "# boxctl:\n"
        "#   category: baremetal/test\n"
        "#   tags: [test]\n"
        "#   requires: []\n"
        "#   privilege: user\n"
        "#   related: []\n"
        "#   brief: leaks a fake AWS key for redaction tests\n"
        "import sys\n"
        "from boxctl.core.output import Output\n"
        "from boxctl.core.context import Context\n"
        "def run(args, output, context):\n"
        "    output.emit({'token': 'AKIAIOSFODNN7EXAMPLE'})\n"
        "    output.render(args[0] if args else 'json')\n"
        "    return 0\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(run(sys.argv[1:], Output(), Context()))\n"
    )
    return tmp_path


def _clean_env() -> dict:
    """os.environ copy with boxctl env state cleared, so redaction tests aren't
    contaminated by sibling tests that set BOXCTL_NO_REDACT in-process."""
    import os

    env = os.environ.copy()
    env.pop("BOXCTL_NO_REDACT", None)
    return env


def _run_cli_with_dir(scripts_dir: Path, *args: str, env: dict | None = None):
    return subprocess.run(
        [sys.executable, "-m", "boxctl", "--scripts-dir", str(scripts_dir), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class TestRedactionEndToEnd:
    def test_default_scrubs_aws_key_in_stdout(self, leaky_scripts_dir):
        r = _run_cli_with_dir(leaky_scripts_dir, "run", "leaky", "json", env=_clean_env())
        assert r.returncode == 0
        assert "AKIAIOSFODNN7EXAMPLE" not in r.stdout
        assert "[REDACTED:aws-key]" in r.stdout

    def test_no_redact_flag_preserves_raw(self, leaky_scripts_dir):
        env = _clean_env()
        env.setdefault("PYTHONPATH", str(REPO_ROOT))
        r = _run_cli_with_dir(
            leaky_scripts_dir, "--no-redact", "run", "leaky", "json", env=env
        )
        assert r.returncode == 0
        assert "AKIAIOSFODNN7EXAMPLE" in r.stdout


# --------------------------------------------------------------------------- #
# Lint on real scripts
# --------------------------------------------------------------------------- #


class TestLintEndToEnd:
    def test_lint_all_real_scripts_clean(self):
        r = run_cli("lint")
        # The project's own scripts must lint clean.
        assert r.returncode == 0, f"real scripts failed lint:\n{r.stdout}\n{r.stderr}"

    def test_lint_reports_missing_header(self, tmp_path):
        """A .py file claiming boxctl header but missing required fields fails."""
        bad = tmp_path / "broken.py"
        bad.write_text(
            "#!/usr/bin/env python3\n"
            "# boxctl:\n"
            "#   category: baremetal/test\n"
            "#   tags: [test]\n"
            "# (missing 'brief')\n"
            "pass\n"
        )
        r = subprocess.run(
            [sys.executable, "-m", "boxctl", "--scripts-dir", str(tmp_path), "lint"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 1
        assert "brief" in r.stdout.lower() or "brief" in r.stderr.lower()


# --------------------------------------------------------------------------- #
# Doctor
# --------------------------------------------------------------------------- #


class TestDoctorEndToEnd:
    def test_doctor_reports_script_totals(self):
        r = run_cli("doctor")
        # Exit 0 if all required tools present, 1 if some missing -- either is
        # "doctor worked."
        assert r.returncode in (0, 1)
        assert "Scripts:" in r.stdout
        assert "Required tools" in r.stdout or "required tools" in r.stdout.lower()

    def test_doctor_json_schema(self):
        r = run_cli("--format", "json", "doctor")
        assert r.returncode in (0, 1)
        data = json.loads(r.stdout)
        assert "scripts_total" in data
        assert "scripts_by_category" in data
        assert isinstance(data["scripts_by_category"], dict)


# --------------------------------------------------------------------------- #
# MCP server smoke test
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(
    shutil.which(sys.executable) is None, reason="python executable required"
)
class TestMCPStdioSmoke:
    """Speak minimal MCP protocol to the server subprocess and list its tools."""

    def test_initialize_and_list_tools(self):
        try:
            import mcp  # noqa: F401
        except ImportError:
            pytest.skip("mcp package not installed")

        # Run the MCP server client-side via the in-process SDK rather than
        # re-implementing the stdio framing ourselves.
        import asyncio

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        async def _run():
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "boxctl", "--scripts-dir", str(SCRIPTS_DIR), "mcp"],
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await asyncio.wait_for(session.initialize(), timeout=5)
                    tools = await asyncio.wait_for(session.list_tools(), timeout=5)
                    names = {t.name for t in tools.tools}
                    assert names == {
                        "list_scripts",
                        "search_scripts",
                        "show_script",
                        "run_script",
                    }

        asyncio.run(_run())
