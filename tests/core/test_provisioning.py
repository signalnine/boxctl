"""Tests for host provisioning (restricted-shell + setup)."""

import subprocess
from pathlib import Path

import pytest

from boxctl.core.provisioning import (
    build_restricted_shell,
    build_setup_script,
    prepare_host,
)
from boxctl.core.ssh import HostConfig


class TestRestrictedShell:
    def test_is_posix_sh(self):
        s = build_restricted_shell()
        assert s.startswith("#!/bin/sh")

    def test_default_allowlist(self):
        s = build_restricted_shell()
        assert "python3" in s
        assert "/usr/bin/python3" in s
        assert "true" in s

    def test_extra_allowed(self):
        s = build_restricted_shell(extra_allowed=["smartctl", "mdadm"])
        assert "smartctl" in s
        assert "mdadm" in s

    def test_rejects_metacharacters(self):
        s = build_restricted_shell()
        # Script must inspect for shell metacharacters.
        for meta in [";", "|", "&", ">", "<", "$", "`"]:
            assert meta in s  # each appears in the rejection pattern

    def test_interactive_rejected(self):
        s = build_restricted_shell()
        assert "SSH_ORIGINAL_COMMAND" in s
        assert "126" in s


class TestSetupScript:
    def test_contains_useradd(self):
        s = build_setup_script(
            username="boxctl-readonly",
            pubkey="ssh-ed25519 AAAA... user@host",
            shell_path="/usr/local/bin/boxctl-restricted-shell",
        )
        assert "useradd" in s
        assert "boxctl-readonly" in s

    def test_installs_shell(self):
        s = build_setup_script(
            username="u",
            pubkey="ssh-ed25519 AAAA",
            shell_path="/usr/local/bin/my-shell",
        )
        assert "/usr/local/bin/my-shell" in s
        assert "0755" in s or "755" in s

    def test_authorized_keys(self):
        s = build_setup_script(
            username="u",
            pubkey="ssh-ed25519 AAAA user@x",
            shell_path="/s",
        )
        assert "authorized_keys" in s
        assert "ssh-ed25519 AAAA user@x" in s
        assert "0600" in s or "600" in s

    def test_strict_mode(self):
        s = build_setup_script("u", "ssh-ed25519 A", "/s")
        assert "set -eu" in s or "set -e" in s

    def test_idempotent(self):
        # Uses id -u <user> or getent to avoid double-creation.
        s = build_setup_script("u", "ssh-ed25519 A", "/s")
        assert "id -u" in s or "getent passwd" in s


class TestPrepareHost:
    def test_runner_receives_ssh_with_sudo(self):
        h = HostConfig(name="p1", host="10.0.0.1", user="admin", port=22)
        captured = {}

        def runner(cmd, **kw):
            captured["cmd"] = cmd
            captured["input"] = kw.get("input", "")
            return subprocess.CompletedProcess(cmd, 0, stdout="done", stderr="")

        res = prepare_host(
            h,
            username="boxctl-readonly",
            pubkey="ssh-ed25519 AAAA user@x",
            runner=runner,
        )
        assert res["host"] == "p1"
        assert res["ok"] is True
        assert captured["cmd"][0] == "ssh"
        joined = " ".join(captured["cmd"])
        assert "admin@10.0.0.1" in joined
        assert "sudo" in joined
        assert "bash" in joined
        # The setup + shell scripts get piped over stdin.
        assert "useradd" in captured["input"]
        assert "ssh-ed25519 AAAA user@x" in captured["input"]
        assert "#!/bin/sh" in captured["input"]

    def test_failure(self):
        h = HostConfig(name="p1", host="h", user="u")

        def runner(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="permission denied")

        res = prepare_host(h, "u2", "ssh-ed25519 A", runner=runner)
        assert res["ok"] is False
        assert "permission denied" in res["stderr"]

    def test_admin_user_override(self):
        h = HostConfig(name="p1", host="h", user="regular")
        captured = {}

        def runner(cmd, **kw):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        prepare_host(h, "u2", "ssh-ed25519 A", admin_user="root", runner=runner)
        assert "root@h" in " ".join(captured["cmd"])

    def test_extra_allowed_plumbed(self):
        h = HostConfig(name="p1", host="h", user="u")
        captured = {}

        def runner(cmd, **kw):
            captured["input"] = kw.get("input", "")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        prepare_host(
            h,
            "u2",
            "ssh-ed25519 A",
            extra_allowed=["smartctl"],
            runner=runner,
        )
        assert "smartctl" in captured["input"]


class TestCLI:
    def test_source_list_registered(self):
        from boxctl.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["source", "list"])
        assert args.command == "source"
        assert args.source_command == "list"

    def test_source_prepare_args(self):
        from boxctl.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(
            ["source", "prepare", "prod-1", "--pubkey", "/tmp/k.pub"]
        )
        assert args.source_command == "prepare"
        assert args.target == "prod-1"
        assert args.pubkey == "/tmp/k.pub"

    def test_source_prepare_missing_pubkey_exits_2(self, tmp_path, monkeypatch, capsys):
        from boxctl.cli import main
        inv = tmp_path / "h.yml"
        inv.write_text(
            """
hosts:
  p1: {host: 10.0.0.1, user: admin}
groups: {}
"""
        )
        rc = main(
            [
                "source",
                "prepare",
                "p1",
                "--pubkey",
                str(tmp_path / "no-such-file.pub"),
                "--inventory",
                str(inv),
            ]
        )
        assert rc == 2

    def test_source_prepare_unknown_host(self, tmp_path):
        from boxctl.cli import main
        pub = tmp_path / "k.pub"
        pub.write_text("ssh-ed25519 AAAA user@x\n")
        inv = tmp_path / "h.yml"
        inv.write_text("hosts: {}\ngroups: {}\n")
        rc = main(
            [
                "source",
                "prepare",
                "nope",
                "--pubkey",
                str(pub),
                "--inventory",
                str(inv),
            ]
        )
        assert rc == 2

    def test_source_list_json(self, tmp_path, capsys):
        from boxctl.cli import main
        inv = tmp_path / "h.yml"
        inv.write_text(
            """
hosts:
  p1: {host: 10.0.0.1, user: admin, port: 22}
  p2: {host: 10.0.0.2, user: root, port: 2222}
groups: {}
"""
        )
        rc = main(["--format", "json", "source", "list", "--inventory", str(inv)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "p1" in out and "p2" in out
        assert "10.0.0.2" in out
