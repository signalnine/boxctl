"""Tests for boxctl.core.config module."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

from boxctl.core.config import (
    load_config_file,
    get_config_value,
    get_issue_platform,
    detect_platform_from_remote,
    resolve_issue_platform,
)


class TestLoadConfigFile:
    """Tests for load_config_file."""

    def test_returns_empty_dict_if_file_missing(self, tmp_path):
        """Returns empty dict when file doesn't exist."""
        result = load_config_file(tmp_path / "nonexistent.yaml")
        assert result == {}

    def test_loads_yaml_file(self, tmp_path):
        """Loads and parses YAML config file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("issue_platform: github\nother: value\n")

        result = load_config_file(config_file)

        assert result == {"issue_platform": "github", "other": "value"}

    def test_returns_empty_dict_on_invalid_yaml(self, tmp_path, capsys):
        """Returns empty dict when YAML is invalid and warns to stderr."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("invalid: yaml: content: [")

        result = load_config_file(config_file)

        assert result == {}
        captured = capsys.readouterr()
        assert str(config_file) in captured.err
        assert "warning" in captured.err.lower()

    def test_missing_file_does_not_warn(self, tmp_path, capsys):
        """A missing config file is silent (common case)."""
        result = load_config_file(tmp_path / "nope.yaml")

        assert result == {}
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_returns_empty_dict_for_empty_file(self, tmp_path):
        """Returns empty dict for empty file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")

        result = load_config_file(config_file)

        assert result == {}


class TestGetConfigValue:
    """Tests for get_config_value."""

    def test_returns_none_when_no_config(self, tmp_path, monkeypatch):
        """Returns None when no config files exist."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))

        result = get_config_value("issue_platform")

        assert result is None

    def test_project_config_takes_precedence(self, tmp_path, monkeypatch):
        """Project config overrides user config."""
        monkeypatch.chdir(tmp_path)

        # Create user config
        user_config_dir = tmp_path / ".config" / "boxctl"
        user_config_dir.mkdir(parents=True)
        (user_config_dir / "config.yaml").write_text("issue_platform: gitlab")

        # Create project config
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: github")

        # Patch Path.home() to return tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_config_value("issue_platform")

        assert result == "github"

    def test_user_config_used_as_fallback(self, tmp_path, monkeypatch):
        """User config used when no project config."""
        monkeypatch.chdir(tmp_path)

        # Create user config only
        user_config_dir = tmp_path / ".config" / "boxctl"
        user_config_dir.mkdir(parents=True)
        (user_config_dir / "config.yaml").write_text("issue_platform: gitlab")

        # Patch Path.home() to return tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = get_config_value("issue_platform")

        assert result == "gitlab"


class TestGetIssuePlatform:
    """Tests for get_issue_platform."""

    def test_returns_configured_platform(self, tmp_path, monkeypatch):
        """Returns platform from config."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: github")

        result = get_issue_platform()

        assert result == "github"


class TestDetectPlatformFromRemote:
    """Tests for detect_platform_from_remote."""

    def test_detects_github(self):
        """Detects GitHub from remote URL."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="git@github.com:user/repo.git\n",
                returncode=0,
            )

            result = detect_platform_from_remote()

            assert result == "github"

    def test_detects_github_https(self):
        """Detects GitHub from HTTPS URL."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="https://github.com/user/repo.git\n",
                returncode=0,
            )

            result = detect_platform_from_remote()

            assert result == "github"

    def test_detects_gitlab(self):
        """Detects GitLab from remote URL."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="git@gitlab.com:user/repo.git\n",
                returncode=0,
            )

            result = detect_platform_from_remote()

            assert result == "gitlab"

    def test_detects_self_hosted_gitlab(self):
        """Detects self-hosted GitLab from remote URL."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="git@gitlab.company.com:user/repo.git\n",
                returncode=0,
            )

            result = detect_platform_from_remote()

            assert result == "gitlab"

    def test_returns_none_for_unknown_host(self):
        """Returns None for unknown hosting provider."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="git@bitbucket.org:user/repo.git\n",
                returncode=0,
            )

            result = detect_platform_from_remote()

            assert result is None

    def test_returns_none_on_git_error(self):
        """Returns None when git command fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git")

            result = detect_platform_from_remote()

            assert result is None

    def test_returns_none_when_not_git_repo(self):
        """Returns None when not in a git repository."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            result = detect_platform_from_remote()

            assert result is None


class TestResolveIssuePlatform:
    """Tests for resolve_issue_platform."""

    def test_prefers_config_over_auto_detect(self, tmp_path, monkeypatch):
        """Config takes precedence over auto-detection."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: gitlab")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="git@github.com:user/repo.git\n",
                returncode=0,
            )

            result = resolve_issue_platform()

            assert result == "gitlab"

    def test_falls_back_to_auto_detect(self, tmp_path, monkeypatch):
        """Falls back to auto-detect when no config."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="git@github.com:user/repo.git\n",
                returncode=0,
            )

            result = resolve_issue_platform()

            assert result == "github"

    def test_returns_none_when_nothing_works(self, tmp_path, monkeypatch):
        """Returns None when no config and auto-detect fails."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git")

            result = resolve_issue_platform()

            assert result is None
