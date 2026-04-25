"""Tests for SSH remote execution."""

import subprocess
from pathlib import Path

import pytest

from boxctl.core.ssh import (
    HostConfig,
    Inventory,
    _shquote,
    build_ssh_cmd,
    load_hosts,
    resolve_targets,
    run_script_remote,
)


class TestShquote:
    def test_empty_string_quotes_to_empty_single_quotes(self):
        assert _shquote("") == "''"

    def test_plain_alnum_unquoted(self):
        assert _shquote("abc123") == "abc123"

    def test_safe_cli_chars_unquoted(self):
        assert _shquote("--flag=value/path.txt") == "--flag=value/path.txt"
        assert _shquote("a,b:c+d@e%f-g_h.i") == "a,b:c+d@e%f-g_h.i"

    @pytest.mark.parametrize(
        "s",
        [
            "a b",
            "a\tb",
            "a\nb",
            'a"b',
            "a'b",
            "a\\b",
            "a$b",
            "a`b",
            "a;b",
            "a|b",
            "a&b",
            "a>b",
            "a<b",
            "a(b)",
            "*",
            "?",
            "[x]",
            "~user",
            "{a,b}",
            "#comment",
            "!bang",
        ],
    )
    def test_metacharacters_trigger_quoting(self, s):
        quoted = _shquote(s)
        assert quoted != s, f"expected {s!r} to be quoted but got {quoted!r}"
        assert quoted.startswith("'") and quoted.endswith("'")

    def test_roundtrip_through_sh(self):
        # Single quote inside value must survive a real sh -c echo.
        import subprocess as sp

        for value in ["it's", "a b c", "a;rm -rf /tmp/x", "$(id)", "`id`", "*"]:
            quoted = _shquote(value)
            r = sp.run(
                ["sh", "-c", f"printf %s {quoted}"],
                capture_output=True,
                text=True,
                check=True,
            )
            assert r.stdout == value, (
                f"{value!r} survived as {r.stdout!r} (quoted={quoted!r})"
            )


@pytest.fixture
def inventory_file(tmp_path):
    p = tmp_path / "hosts.yml"
    p.write_text(
        """
hosts:
  prod-1:
    host: 10.0.0.1
    user: boxctl
    port: 2222
    identity: ~/.ssh/id_ed25519
  prod-2:
    host: 10.0.0.2
groups:
  web: [prod-1, prod-2]
"""
    )
    return p


class TestLoadHosts:
    def test_loads_full_entry(self, inventory_file):
        inv = load_hosts(inventory_file)
        h = inv.hosts["prod-1"]
        assert h.name == "prod-1"
        assert h.host == "10.0.0.1"
        assert h.user == "boxctl"
        assert h.port == 2222
        assert h.identity == "~/.ssh/id_ed25519"

    def test_defaults(self, inventory_file):
        inv = load_hosts(inventory_file)
        h = inv.hosts["prod-2"]
        assert h.host == "10.0.0.2"
        assert h.port == 22
        assert h.identity is None

    def test_groups(self, inventory_file):
        inv = load_hosts(inventory_file)
        assert inv.groups["web"] == ["prod-1", "prod-2"]

    def test_missing_file_empty(self, tmp_path):
        inv = load_hosts(tmp_path / "nope.yml")
        assert inv.hosts == {}
        assert inv.groups == {}


class TestResolveTargets:
    def test_single_name(self, inventory_file):
        inv = load_hosts(inventory_file)
        r = resolve_targets(inv, "prod-1")
        assert [h.name for h in r] == ["prod-1"]

    def test_group_prefix(self, inventory_file):
        inv = load_hosts(inventory_file)
        r = resolve_targets(inv, "group:web")
        assert [h.name for h in r] == ["prod-1", "prod-2"]

    def test_comma_separated(self, inventory_file):
        inv = load_hosts(inventory_file)
        r = resolve_targets(inv, "prod-1,prod-2")
        assert [h.name for h in r] == ["prod-1", "prod-2"]

    def test_unknown_name(self, inventory_file):
        inv = load_hosts(inventory_file)
        with pytest.raises(KeyError):
            resolve_targets(inv, "nope")

    def test_unknown_group(self, inventory_file):
        inv = load_hosts(inventory_file)
        with pytest.raises(KeyError):
            resolve_targets(inv, "group:nope")

    def test_dedupes_name_then_group(self, inventory_file):
        inv = load_hosts(inventory_file)
        r = resolve_targets(inv, "prod-1,group:web")
        assert [h.name for h in r] == ["prod-1", "prod-2"]

    def test_dedupes_repeated_name(self, inventory_file):
        inv = load_hosts(inventory_file)
        r = resolve_targets(inv, "prod-1,prod-1,prod-2")
        assert [h.name for h in r] == ["prod-1", "prod-2"]


class TestBuildSSHCmd:
    def test_basic(self):
        h = HostConfig(name="a", host="h.local", user="u", port=22)
        cmd = build_ssh_cmd(h, "echo hi")
        assert cmd[0] == "ssh"
        assert "u@h.local" in cmd
        assert "echo hi" in cmd
        # Default port must NOT be added.
        assert "-p" not in cmd

    def test_custom_port(self):
        h = HostConfig(name="a", host="h.local", user="u", port=2222)
        cmd = build_ssh_cmd(h, "echo hi")
        i = cmd.index("-p")
        assert cmd[i + 1] == "2222"

    def test_identity(self):
        h = HostConfig(name="a", host="h.local", user="u", port=22, identity="/k.pem")
        cmd = build_ssh_cmd(h, "x")
        i = cmd.index("-i")
        assert cmd[i + 1] == "/k.pem"

    def test_safety_options(self):
        h = HostConfig(name="a", host="h.local", user="u", port=22)
        cmd = build_ssh_cmd(h, "x")
        joined = " ".join(cmd)
        assert "BatchMode=yes" in joined
        assert "ConnectTimeout=" in joined


class TestRunScriptRemote:
    def test_success(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("print('hi')\n")
        h = HostConfig(name="a", host="h", user="u", port=22)

        class R:
            def __call__(self, cmd, input, capture_output, text, timeout):
                assert cmd[0] == "ssh"
                assert "python3 -" in " ".join(cmd)
                assert "print('hi')" in input
                return subprocess.CompletedProcess(cmd, 0, stdout='{"ok":1}', stderr="")

        res = run_script_remote(script, h, args=["--format", "json"], timeout=30, runner=R())
        assert res == {"host": "a", "exit_code": 0, "stdout": '{"ok":1}', "stderr": "", "timed_out": False}

    def test_timeout(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("x=1\n")
        h = HostConfig(name="a", host="h", user="u", port=22)

        def runner(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, timeout=1)

        res = run_script_remote(script, h, args=[], timeout=1, runner=runner)
        assert res["timed_out"] is True
        assert res["exit_code"] == -1
        assert res["host"] == "a"

    def test_ssh_missing(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("x=1\n")
        h = HostConfig(name="a", host="h", user="u", port=22)

        def runner(cmd, **kw):
            raise FileNotFoundError("ssh")

        res = run_script_remote(script, h, args=[], timeout=5, runner=runner)
        assert res["exit_code"] == 2
        assert "ssh" in res["stderr"].lower()

    def test_remote_env_prepended_as_python_preamble(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("print('hi')\n")
        h = HostConfig(name="a", host="h", user="u", port=22)
        seen = {}

        def runner(cmd, input, capture_output, text, timeout):
            seen["cmd"] = cmd
            seen["input"] = input
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        run_script_remote(
            script,
            h,
            args=[],
            timeout=5,
            runner=runner,
            remote_env={"BOXCTL_NO_REDACT": "1"},
        )
        # Remote command stays 'python3 -' so the restricted shell still allows it.
        assert "python3 -" in " ".join(seen["cmd"])
        # Env lands inside the piped source as os.environ.setdefault.
        assert "BOXCTL_NO_REDACT" in seen["input"]
        assert "'1'" in seen["input"]
        assert "environ.setdefault" in seen["input"]
        assert "print('hi')" in seen["input"]

    def test_args_appended(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("pass\n")
        h = HostConfig(name="a", host="h", user="u", port=22)
        seen = {}

        def runner(cmd, **kw):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        run_script_remote(script, h, args=["--verbose", "-x", "1"], timeout=5, runner=runner)
        joined = " ".join(seen["cmd"])
        assert "--verbose" in joined
        assert "-x" in joined


class TestCLI:
    def test_run_accepts_host_flag(self):
        from boxctl.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["run", "loadavg_analyzer", "--host", "prod-1"])
        assert args.host == "prod-1"

    def test_run_accepts_inventory_flag(self):
        from boxctl.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(
            ["run", "loadavg_analyzer", "--host", "prod-1", "--inventory", "/tmp/h.yml"]
        )
        assert args.inventory == "/tmp/h.yml"

    def test_plain_format_per_host_blocks(self, tmp_path, monkeypatch, capsys):
        from boxctl.cli import main
        from boxctl.core import ssh as ssh_mod

        inv = tmp_path / "h.yml"
        inv.write_text(
            """
hosts:
  p1: {host: 10.0.0.1, user: u}
  p2: {host: 10.0.0.2, user: u}
groups:
  g: [p1, p2]
"""
        )

        def fake_remote(script_path, host, args, timeout, runner=None, **kwargs):
            return {
                "host": host.name,
                "exit_code": 0 if host.name == "p1" else 7,
                "stdout": f"{host.name} stdout\n",
                "stderr": "" if host.name == "p1" else "bad\n",
                "timed_out": False,
            }

        monkeypatch.setattr(ssh_mod, "run_script_remote", fake_remote)
        repo = Path(__file__).resolve().parents[2]
        rc = main(
            [
                "--scripts-dir",
                str(repo),
                "run",
                "loadavg_analyzer",
                "--host",
                "group:g",
                "--inventory",
                str(inv),
            ]
        )
        # Worst-case exit code (7 > 0).
        assert rc == 7
        out = capsys.readouterr()
        assert "=== p1 [OK] ===" in out.out
        assert "=== p2 [EXIT 7] ===" in out.out
        assert "p1 stdout" in out.out
        assert "bad" in out.err

    def test_json_format_still_json(self, tmp_path, monkeypatch, capsys):
        from boxctl.cli import main
        from boxctl.core import ssh as ssh_mod

        inv = tmp_path / "h.yml"
        inv.write_text("hosts: {p1: {host: 1.1.1.1, user: u}}\ngroups: {}\n")

        def fake_remote(script_path, host, args, timeout, runner=None, **kwargs):
            return {
                "host": "p1",
                "exit_code": 0,
                "stdout": "x",
                "stderr": "",
                "timed_out": False,
            }

        monkeypatch.setattr(ssh_mod, "run_script_remote", fake_remote)
        repo = Path(__file__).resolve().parents[2]
        rc = main(
            [
                "--scripts-dir",
                str(repo),
                "--format",
                "json",
                "run",
                "loadavg_analyzer",
                "--host",
                "p1",
                "--inventory",
                str(inv),
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert out.startswith("{")
        assert '"host": "p1"' in out

    def test_ssh_not_found_exits_2(self, tmp_path, monkeypatch):
        from boxctl.cli import main
        from boxctl.core import ssh as ssh_mod

        inv = tmp_path / "h.yml"
        inv.write_text("hosts: {p1: {host: h, user: u}}\ngroups: {}\n")

        def fake_remote(script_path, host, args, timeout, runner=None, **kwargs):
            return {
                "host": "p1",
                "exit_code": 2,
                "stdout": "",
                "stderr": "ssh not found",
                "timed_out": False,
            }

        monkeypatch.setattr(ssh_mod, "run_script_remote", fake_remote)
        repo = Path(__file__).resolve().parents[2]
        rc = main(
            [
                "--scripts-dir",
                str(repo),
                "run",
                "loadavg_analyzer",
                "--host",
                "p1",
                "--inventory",
                str(inv),
            ]
        )
        assert rc == 2

    def test_no_redact_flag_propagates_to_remote(self, tmp_path, monkeypatch):
        from boxctl.cli import main
        from boxctl.core import ssh as ssh_mod

        inv = tmp_path / "h.yml"
        inv.write_text("hosts: {p1: {host: 1.1.1.1, user: u}}\ngroups: {}\n")
        seen = {}

        def fake_remote(script_path, host, args, timeout, runner=None, remote_env=None):
            seen["remote_env"] = remote_env
            return {
                "host": host.name,
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            }

        monkeypatch.setattr(ssh_mod, "run_script_remote", fake_remote)
        # Ensure no stale env var from other tests.
        monkeypatch.delenv("BOXCTL_NO_REDACT", raising=False)
        repo = Path(__file__).resolve().parents[2]
        rc = main(
            [
                "--scripts-dir",
                str(repo),
                "--no-redact",
                "run",
                "loadavg_analyzer",
                "--host",
                "p1",
                "--inventory",
                str(inv),
            ]
        )
        assert rc == 0
        assert seen["remote_env"] == {"BOXCTL_NO_REDACT": "1"}

    def test_redact_default_no_env_sent_to_remote(self, tmp_path, monkeypatch):
        from boxctl.cli import main
        from boxctl.core import ssh as ssh_mod

        inv = tmp_path / "h.yml"
        inv.write_text("hosts: {p1: {host: 1.1.1.1, user: u}}\ngroups: {}\n")
        seen = {}

        def fake_remote(script_path, host, args, timeout, runner=None, remote_env=None):
            seen["remote_env"] = remote_env
            return {
                "host": host.name,
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
            }

        monkeypatch.setattr(ssh_mod, "run_script_remote", fake_remote)
        monkeypatch.delenv("BOXCTL_NO_REDACT", raising=False)
        repo = Path(__file__).resolve().parents[2]
        main(
            [
                "--scripts-dir",
                str(repo),
                "run",
                "loadavg_analyzer",
                "--host",
                "p1",
                "--inventory",
                str(inv),
            ]
        )
        assert seen["remote_env"] is None

    def test_unknown_selector_exits_2(self, tmp_path, monkeypatch, capsys):
        from boxctl.cli import main

        inv = tmp_path / "hosts.yml"
        inv.write_text("hosts: {}\ngroups: {}\n")
        monkeypatch.chdir(tmp_path)
        # Point scripts-dir at repo so 'loadavg_analyzer' resolves.
        repo = Path(__file__).resolve().parents[2]
        rc = main(
            [
                "--scripts-dir",
                str(repo),
                "run",
                "loadavg_analyzer",
                "--host",
                "nope",
                "--inventory",
                str(inv),
            ]
        )
        assert rc == 2
