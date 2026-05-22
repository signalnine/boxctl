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


class TestSandboxSafeDefaults:
    """Sandbox containers must spawn with safe-by-default isolation flags
    so a misbehaving experiment can't reach the host network or escalate
    via Linux capabilities (gap analysis P0 #4)."""

    def test_default_flags_drop_caps_and_disable_network(self, state_dir, good_runner):
        sb.create_sandbox("safe", image="debian:stable", runner=good_runner)
        run_call = next(c for c in good_runner.calls if c[:2] == ["podman", "run"])
        assert "--network=none" in run_call
        assert "--cap-drop=ALL" in run_call
        assert "--security-opt=no-new-privileges" in run_call
        assert "--read-only" in run_call
        # tmpfs lets package installs / writes proceed without exposing host paths.
        assert any(a.startswith("--tmpfs=/tmp") for a in run_call)
        # Resource limits prevent runaway sandboxes from hosing the host.
        assert any(a.startswith("--memory=") for a in run_call)
        assert any(a.startswith("--pids-limit=") for a in run_call)

    def test_unsafe_flag_omits_isolation(self, state_dir, good_runner):
        """Operators sometimes legitimately need network or caps -- e.g.
        validating that an apt install would actually work. The opt-out
        keeps the door open without changing the default."""
        sb.create_sandbox(
            "loose", image="debian:stable", runner=good_runner, unsafe=True,
        )
        run_call = next(c for c in good_runner.calls if c[:2] == ["podman", "run"])
        assert "--network=none" not in run_call
        assert "--cap-drop=ALL" not in run_call


class TestImageValidation:
    """Image references reach create_sandbox from the daemon's /sandbox
    POST body, so they must be validated before podman pull (gap analysis
    P0 #5 + P1 #8)."""

    @pytest.mark.parametrize("good", [
        "debian:stable",
        "docker.io/library/debian:stable",
        "ghcr.io/foo/bar:1.2.3",
        "quay.io/coreos/etcd@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "registry.example.com:5000/team/img:tag",
    ])
    def test_valid_image_refs_accepted(self, good):
        # Direct test of the validator -- doesn't need a runner.
        sb.validate_image_ref(good)

    @pytest.mark.parametrize("bad", [
        "",
        "   ",
        "image with space:tag",
        "img;rm -rf /",
        "img\nls",
        "x" * 600,  # absurd length
        "img:bad tag",
        "$injection:tag",
    ])
    def test_invalid_image_refs_rejected(self, bad):
        with pytest.raises(ValueError):
            sb.validate_image_ref(bad)

    def test_create_sandbox_rejects_bad_image(self, state_dir, good_runner):
        with pytest.raises(ValueError, match="image"):
            sb.create_sandbox("bad", image="img;rm -rf /", runner=good_runner)


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


@pytest.mark.parametrize("bad", ["..", "../pwned", "/etc/passwd", "foo/bar", "", "has space"])
def test_load_sandbox_rejects_invalid_names(state_dir, bad):
    with pytest.raises(ValueError):
        sb.load_sandbox(bad)


@pytest.mark.parametrize("bad", ["..", "../pwned", "/etc/passwd", "foo/bar", "", "has space"])
def test_destroy_sandbox_rejects_invalid_names(state_dir, bad):
    with pytest.raises(ValueError):
        sb.destroy_sandbox(bad, runner=FakeRunner())


@pytest.mark.parametrize("bad", ["..", "../pwned", "/etc/passwd", "foo/bar", "", "has space"])
def test_diff_sandbox_rejects_invalid_names(state_dir, bad):
    with pytest.raises(ValueError):
        sb.diff_sandbox(bad, runner=FakeRunner())


def test_load_sandbox_path_traversal_blocked(state_dir, tmp_path):
    """Reproducer from boxctl-x3r: a state file written outside the
    configured state_dir via '..' must not be reachable through
    load_sandbox. Validation rejects the name before any file lookup."""
    outside = tmp_path / "pwned.json"
    outside.write_text(json.dumps({
        "name": "x", "container_id": "c", "image": "i",
        "source_host": None, "created_at": 1.0,
        "units_snapshot": [], "packages_snapshot": [],
    }))
    with pytest.raises(ValueError):
        sb.load_sandbox("../pwned")
    assert outside.exists()


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


# --- snapshot_packages (issue boxctl-n2m.6) -----------------------------


def test_snapshot_packages_returns_sorted_unique_names():
    runner = FakeRunner({
        ("dpkg-query", "-W", "-f=${Package}\n"): _completed(
            stdout="bash\ncoreutils\nbash\nzlib1g\n"
        ),
    })
    pkgs = sb.snapshot_packages(runner=runner)
    assert pkgs == ["bash", "coreutils", "zlib1g"]


def test_snapshot_packages_returns_empty_on_missing_dpkg():
    runner = FakeRunner({
        ("dpkg-query",): FileNotFoundError("dpkg-query"),
    })
    assert sb.snapshot_packages(runner=runner) == []


def test_snapshot_packages_returns_empty_on_nonzero_exit():
    runner = FakeRunner({
        ("dpkg-query", "-W", "-f=${Package}\n"): _completed(returncode=1, stderr="oops"),
    })
    assert sb.snapshot_packages(runner=runner) == []


# --- create_sandbox + diff_sandbox include packages ---------------------


def test_create_sandbox_captures_packages_snapshot(state_dir):
    runner = FakeRunner({
        ("podman", "run"): _completed(stdout="cidpkg\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=""),
        ("dpkg-query", "-W", "-f=${Package}\n"): _completed(stdout="bash\nlibc6\n"),
    })
    s = sb.create_sandbox("pkgbox", image="debian:stable", runner=runner)
    assert s.packages_snapshot == ["bash", "libc6"]
    payload = json.loads((state_dir / "pkgbox.json").read_text())
    assert payload["packages_snapshot"] == ["bash", "libc6"]


def test_diff_sandbox_returns_package_changes(state_dir):
    create_runner = FakeRunner({
        ("podman", "run"): _completed(stdout="cid2\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=""),
        ("dpkg-query", "-W", "-f=${Package}\n"): _completed(stdout="bash\nlibc6\n"),
    })
    sb.create_sandbox("pdiff", image="i", runner=create_runner)

    diff_runner = FakeRunner({
        ("podman", "diff", "cid2"): _completed(stdout=""),
        ("podman", "exec", "cid2", "systemctl"): _completed(stdout=""),
        ("podman", "exec", "cid2", "dpkg-query", "-W", "-f=${Package}\n"): _completed(
            stdout="bash\nlibc6\nnginx\n"
        ),
    })
    result = sb.diff_sandbox("pdiff", runner=diff_runner)
    assert "package_changes" in result
    assert result["package_changes"]["added"] == ["nginx"]
    assert result["package_changes"]["removed"] == []


def test_diff_sandbox_package_changes_detects_removed(state_dir):
    create_runner = FakeRunner({
        ("podman", "run"): _completed(stdout="cid3\n"),
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager"): _completed(stdout=""),
        ("dpkg-query", "-W", "-f=${Package}\n"): _completed(stdout="bash\nlibc6\nnano\n"),
    })
    sb.create_sandbox("rdiff", image="i", runner=create_runner)

    diff_runner = FakeRunner({
        ("podman", "diff", "cid3"): _completed(stdout=""),
        ("podman", "exec", "cid3", "systemctl"): _completed(stdout=""),
        ("podman", "exec", "cid3", "dpkg-query", "-W", "-f=${Package}\n"): _completed(
            stdout="bash\nlibc6\n"
        ),
    })
    result = sb.diff_sandbox("rdiff", runner=diff_runner)
    assert result["package_changes"]["added"] == []
    assert result["package_changes"]["removed"] == ["nano"]


def test_load_sandbox_tolerates_legacy_state_without_packages(state_dir, good_runner):
    """Older state files predate packages_snapshot; load must default to []."""
    sb.create_sandbox("legacy", image="i", runner=good_runner)
    sf = state_dir / "legacy.json"
    payload = json.loads(sf.read_text())
    payload.pop("packages_snapshot", None)
    sf.write_text(json.dumps(payload))
    loaded = sb.load_sandbox("legacy")
    assert loaded.packages_snapshot == []
