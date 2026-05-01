"""CLI tests for `boxctl sandbox` (issue boxctl-n2m.5)."""

from __future__ import annotations

import json
import subprocess

import pytest

from boxctl import cli
from boxctl.core import sandbox as sb


def _completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class FakeRunner:
    def __init__(self, scripts: dict[tuple[str, ...], subprocess.CompletedProcess | Exception] | None = None):
        self.scripts = scripts or {}
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        key = tuple(cmd)
        if key in self.scripts:
            v = self.scripts[key]
            if isinstance(v, Exception):
                raise v
            return v
        for k, v in self.scripts.items():
            if key[: len(k)] == k:
                if isinstance(v, Exception):
                    raise v
                return v
        return _completed()


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("BOXCTL_SANDBOX_STATE_DIR", str(tmp_path / "sb"))
    return tmp_path / "sb"


@pytest.fixture
def good_runner():
    return FakeRunner({
        ("podman", "--version"): _completed(stdout="podman 4.9.0"),
        ("podman", "run"): _completed(stdout="cidA\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout="ssh.service enabled\n"),
    })


def test_parser_exposes_sandbox_subcommands():
    parser = cli.create_parser()
    args = parser.parse_args(["sandbox", "create", "demo"])
    assert args.command == "sandbox"
    assert args.sandbox_command == "create"
    assert args.name == "demo"


def test_sandbox_help_lists_subcommands(capsys):
    parser = cli.create_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["sandbox", "--help"])
    captured = capsys.readouterr()
    for sub in ("create", "list", "diff", "destroy"):
        assert sub in captured.out


def test_create_persists_sandbox(isolated_state, good_runner, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: good_runner)
    parser = cli.create_parser()
    args = parser.parse_args(["sandbox", "create", "demo", "--image", "img"])
    rc = cli.cmd_sandbox(args)
    assert rc == 0
    assert (isolated_state / "demo.json").exists()
    assert any(c[:2] == ["podman", "run"] for c in good_runner.calls)


def test_create_exits_2_when_podman_missing(isolated_state, monkeypatch, capsys):
    runner = FakeRunner({("podman", "--version"): FileNotFoundError("podman")})
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: runner)
    parser = cli.create_parser()
    args = parser.parse_args(["sandbox", "create", "demo"])
    rc = cli.cmd_sandbox(args)
    captured = capsys.readouterr()
    assert rc == 2
    assert "podman" in captured.err.lower()


def test_list_outputs_json_when_format_json(isolated_state, good_runner, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: good_runner)
    parser = cli.create_parser()
    cli.cmd_sandbox(parser.parse_args(["sandbox", "create", "a", "--image", "i"]))
    cli.cmd_sandbox(parser.parse_args(["sandbox", "create", "b", "--image", "i"]))
    capsys.readouterr()  # drain

    args = parser.parse_args(["--format", "json", "sandbox", "list"])
    rc = cli.cmd_sandbox(args)
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    names = sorted(s["name"] for s in payload)
    assert names == ["a", "b"]


def test_list_plain_output(isolated_state, good_runner, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: good_runner)
    parser = cli.create_parser()
    cli.cmd_sandbox(parser.parse_args(["sandbox", "create", "alpha", "--image", "img1"]))
    capsys.readouterr()

    rc = cli.cmd_sandbox(parser.parse_args(["sandbox", "list"]))
    assert rc == 0
    out = capsys.readouterr().out
    assert "alpha" in out
    assert "img1" in out


def test_diff_prints_changes(isolated_state, monkeypatch, capsys):
    create_runner = FakeRunner({
        ("podman", "--version"): _completed(),
        ("podman", "run"): _completed(stdout="ctrX\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout="ssh.service enabled\n"),
    })
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: create_runner)
    parser = cli.create_parser()
    cli.cmd_sandbox(parser.parse_args(["sandbox", "create", "d", "--image", "i"]))
    capsys.readouterr()

    diff_runner = FakeRunner({
        ("podman", "--version"): _completed(),
        ("podman", "diff", "ctrX"): _completed(stdout="A /etc/foo\n"),
        ("podman", "exec", "ctrX", "systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(
            stdout="ssh.service enabled\nnewunit.service enabled\n"
        ),
    })
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: diff_runner)

    rc = cli.cmd_sandbox(parser.parse_args(["sandbox", "diff", "d"]))
    out = capsys.readouterr().out
    assert rc == 0
    assert "A /etc/foo" in out
    assert "newunit.service" in out


def test_diff_json_format(isolated_state, monkeypatch, capsys):
    create_runner = FakeRunner({
        ("podman", "--version"): _completed(),
        ("podman", "run"): _completed(stdout="cj\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=""),
    })
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: create_runner)
    parser = cli.create_parser()
    cli.cmd_sandbox(parser.parse_args(["sandbox", "create", "j", "--image", "i"]))
    capsys.readouterr()

    diff_runner = FakeRunner({
        ("podman", "--version"): _completed(),
        ("podman", "diff", "cj"): _completed(stdout="A /etc/x\n"),
        ("podman", "exec", "cj", "systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=""),
    })
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: diff_runner)

    rc = cli.cmd_sandbox(parser.parse_args(["--format", "json", "sandbox", "diff", "j"]))
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["fs_changes"] == ["A /etc/x"]


def test_destroy_removes_sandbox(isolated_state, monkeypatch, capsys):
    create_runner = FakeRunner({
        ("podman", "--version"): _completed(),
        ("podman", "run"): _completed(stdout="killid\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=""),
    })
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: create_runner)
    parser = cli.create_parser()
    cli.cmd_sandbox(parser.parse_args(["sandbox", "create", "k", "--image", "i"]))
    capsys.readouterr()
    assert (isolated_state / "k.json").exists()

    destroy_runner = FakeRunner({
        ("podman", "--version"): _completed(),
        ("podman", "rm", "-f", "killid"): _completed(),
    })
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: destroy_runner)

    rc = cli.cmd_sandbox(parser.parse_args(["sandbox", "destroy", "k"]))
    assert rc == 0
    assert not (isolated_state / "k.json").exists()


def test_destroy_unknown_sandbox_exits_2(isolated_state, monkeypatch, capsys):
    runner = FakeRunner({("podman", "--version"): _completed()})
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: runner)
    parser = cli.create_parser()
    rc = cli.cmd_sandbox(parser.parse_args(["sandbox", "destroy", "nope"]))
    assert rc == 2
    assert "nope" in capsys.readouterr().err


def test_no_subcommand_prints_usage_and_exits_2(isolated_state, monkeypatch, capsys):
    runner = FakeRunner({("podman", "--version"): _completed()})
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: runner)
    parser = cli.create_parser()
    rc = cli.cmd_sandbox(parser.parse_args(["sandbox"]))
    assert rc == 2
    err = capsys.readouterr().err
    assert "sandbox" in err.lower()


def test_create_duplicate_exits_1(isolated_state, good_runner, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: good_runner)
    parser = cli.create_parser()
    cli.cmd_sandbox(parser.parse_args(["sandbox", "create", "dup", "--image", "i"]))
    capsys.readouterr()
    rc = cli.cmd_sandbox(parser.parse_args(["sandbox", "create", "dup", "--image", "i"]))
    assert rc == 1
    assert "exists" in capsys.readouterr().err.lower()


def test_create_invalid_name_exits_2(isolated_state, good_runner, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: good_runner)
    parser = cli.create_parser()
    rc = cli.cmd_sandbox(parser.parse_args(["sandbox", "create", "bad name"]))
    assert rc == 2
    assert "invalid" in capsys.readouterr().err.lower()


def test_main_dispatches_to_sandbox(isolated_state, good_runner, monkeypatch):
    monkeypatch.setattr(cli, "_sandbox_runner", lambda: good_runner)
    rc = cli.main(["sandbox", "create", "viamain", "--image", "i"])
    assert rc == 0
    assert (isolated_state / "viamain.json").exists()
