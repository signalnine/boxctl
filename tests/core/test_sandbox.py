"""Tests for the container sandbox layer (issue boxctl-n2m.5)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from boxctl.core import sandbox as sb


def _completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class FakeRunner:
    """Captures argv lists and returns scripted CompletedProcess values."""

    def __init__(self, responses: dict[tuple[str, ...], subprocess.CompletedProcess | Exception] | None = None):
        self.responses = responses or {}
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs) -> subprocess.CompletedProcess:
        self.calls.append(list(cmd))
        # Match by full tuple, then by leading prefix.
        key = tuple(cmd)
        if key in self.responses:
            v = self.responses[key]
            if isinstance(v, Exception):
                raise v
            return v
        for k, v in self.responses.items():
            if key[: len(k)] == k:
                if isinstance(v, Exception):
                    raise v
                return v
        return _completed()


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    d = tmp_path / "sandboxes"
    monkeypatch.setenv("BOXCTL_SANDBOX_STATE_DIR", str(d))
    return d


# --- state_dir ----------------------------------------------------------


def test_state_dir_honours_env_var(state_dir):
    assert sb.state_dir() == state_dir


def test_state_dir_default_under_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("BOXCTL_SANDBOX_STATE_DIR", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert sb.state_dir() == tmp_path / "boxctl" / "sandboxes"


# --- check_podman -------------------------------------------------------


def test_check_podman_true_when_version_succeeds():
    runner = FakeRunner({("podman", "--version"): _completed(stdout="podman 4.9.0\n")})
    assert sb.check_podman(runner) is True


def test_check_podman_false_when_missing():
    runner = FakeRunner({("podman", "--version"): FileNotFoundError("podman")})
    assert sb.check_podman(runner) is False


def test_check_podman_false_when_nonzero_exit():
    runner = FakeRunner({("podman", "--version"): _completed(returncode=1)})
    assert sb.check_podman(runner) is False


# --- snapshot_units -----------------------------------------------------


SAMPLE_UNITS = "ssh.service                  enabled\ncron.service                 disabled\nfoo.timer                    static\n"


def test_snapshot_units_local_returns_sorted_pairs():
    runner = FakeRunner({
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=SAMPLE_UNITS),
    })
    units = sb.snapshot_units(runner=runner)
    assert units == [
        "cron.service\tdisabled",
        "foo.timer\tstatic",
        "ssh.service\tenabled",
    ]


def test_snapshot_units_handles_blank_lines():
    runner = FakeRunner({
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout="\n\nssh.service enabled\n\n"),
    })
    units = sb.snapshot_units(runner=runner)
    assert units == ["ssh.service\tenabled"]


# --- create_sandbox -----------------------------------------------------


@pytest.fixture
def good_runner():
    return FakeRunner({
        ("podman", "run", "-d", "--name"): _completed(stdout="abc123def456\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=SAMPLE_UNITS),
    })


def test_create_sandbox_persists_state(state_dir, good_runner):
    s = sb.create_sandbox("demo", image="debian:stable", runner=good_runner)
    assert s.name == "demo"
    assert s.container_id.startswith("abc123")
    assert s.image == "debian:stable"
    assert s.source_host is None
    assert (state_dir / "demo.json").exists()
    payload = json.loads((state_dir / "demo.json").read_text())
    assert payload["name"] == "demo"
    assert payload["units_snapshot"][0].startswith("cron.service")


def test_create_sandbox_invokes_podman_run_with_correct_argv(state_dir, good_runner):
    sb.create_sandbox("demo2", image="debian:stable", runner=good_runner)
    podman_calls = [c for c in good_runner.calls if c[0] == "podman"]
    assert podman_calls, "expected at least one podman call"
    run_call = podman_calls[0]
    assert run_call[:4] == ["podman", "run", "-d", "--name"]
    assert "demo2" in run_call
    assert "debian:stable" in run_call
    assert run_call[-2:] == ["sleep", "infinity"]


@pytest.mark.parametrize("bad", ["", "has space", "with/slash", "a" * 65, "weird;name", ".dot"])
def test_create_sandbox_rejects_invalid_names(state_dir, good_runner, bad):
    with pytest.raises(ValueError):
        sb.create_sandbox(bad, image="debian:stable", runner=good_runner)


def test_create_sandbox_rejects_duplicate(state_dir, good_runner):
    sb.create_sandbox("dup", image="debian:stable", runner=good_runner)
    with pytest.raises(FileExistsError):
        sb.create_sandbox("dup", image="debian:stable", runner=good_runner)


# --- load / list --------------------------------------------------------


def test_load_sandbox_round_trip(state_dir, good_runner):
    sb.create_sandbox("rt", image="img", runner=good_runner)
    loaded = sb.load_sandbox("rt")
    assert loaded.name == "rt"
    assert loaded.image == "img"


def test_load_sandbox_missing_raises(state_dir):
    with pytest.raises(FileNotFoundError):
        sb.load_sandbox("nope")


def test_list_sandboxes_empty_when_dir_missing(state_dir):
    assert sb.list_sandboxes() == []


def test_list_sandboxes_returns_all(state_dir, good_runner):
    sb.create_sandbox("a", image="i", runner=good_runner)
    sb.create_sandbox("b", image="i", runner=good_runner)
    names = sorted(s.name for s in sb.list_sandboxes())
    assert names == ["a", "b"]


# --- diff_sandbox -------------------------------------------------------


def test_diff_sandbox_returns_fs_and_unit_changes(state_dir):
    create_runner = FakeRunner({
        ("podman", "run"): _completed(stdout="cid1\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(
            stdout="ssh.service enabled\ncron.service disabled\n"
        ),
    })
    sb.create_sandbox("d", image="i", runner=create_runner)

    diff_runner = FakeRunner({
        ("podman", "diff", "cid1"): _completed(stdout="A /etc/foo\nC /etc/ssh/sshd_config\nD /tmp/old\n"),
        ("podman", "exec", "cid1", "systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(
            stdout="ssh.service enabled\ncron.service enabled\nnewsvc.service enabled\n"
        ),
    })
    result = sb.diff_sandbox("d", runner=diff_runner)
    assert result["fs_changes"] == ["A /etc/foo", "C /etc/ssh/sshd_config", "D /tmp/old"]
    assert "newsvc.service\tenabled" in result["unit_changes"]["added"]
    # cron changed from disabled -> enabled
    changed_names = {entry.split("\t")[0] for entry in result["unit_changes"]["changed"]}
    assert "cron.service" in changed_names
    assert result["unit_changes"]["removed"] == []


# --- destroy_sandbox ----------------------------------------------------


def test_destroy_sandbox_removes_container_and_state(state_dir):
    create_runner = FakeRunner({
        ("podman", "run"): _completed(stdout="zid\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=""),
    })
    sb.create_sandbox("z", image="i", runner=create_runner)
    assert (state_dir / "z.json").exists()

    destroy_runner = FakeRunner({
        ("podman", "rm", "-f", "zid"): _completed(),
    })
    sb.destroy_sandbox("z", runner=destroy_runner)
    assert not (state_dir / "z.json").exists()
    assert ["podman", "rm", "-f", "zid"] in destroy_runner.calls


def test_destroy_sandbox_idempotent_on_podman_failure(state_dir):
    create_runner = FakeRunner({
        ("podman", "run"): _completed(stdout="badid\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=""),
    })
    sb.create_sandbox("ok", image="i", runner=create_runner)

    destroy_runner = FakeRunner({
        ("podman", "rm", "-f", "badid"): _completed(returncode=1, stderr="no such container"),
    })
    sb.destroy_sandbox("ok", runner=destroy_runner)
    assert not (state_dir / "ok.json").exists()


def test_destroy_sandbox_missing_raises(state_dir):
    with pytest.raises(FileNotFoundError):
        sb.destroy_sandbox("ghost", runner=FakeRunner())
