"""Configuration loading with layered overrides."""

import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


def load_config_file(path: Path) -> dict[str, Any]:
    """Load a YAML config file if it exists.

    Missing files return ``{}`` silently. Malformed YAML emits a one-line
    stderr warning naming the file and parser error, then returns ``{}``,
    so misconfiguration is surfaced instead of silently dropped.
    """
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except OSError:
        return {}
    except yaml.YAMLError as e:
        print(f"boxctl: warning: failed to parse {path}: {e}", file=sys.stderr)
        return {}


def get_config_value(key: str) -> str | None:
    """Get config value with project -> user -> None precedence."""
    # Project config
    project_config = Path('.boxctl.yaml')
    data = load_config_file(project_config)
    if key in data:
        return data[key]

    # User config
    user_config = Path.home() / '.config' / 'boxctl' / 'config.yaml'
    data = load_config_file(user_config)
    if key in data:
        return data[key]

    return None


def get_issue_platform() -> str | None:
    """Get configured issue platform (github or gitlab)."""
    return get_config_value('issue_platform')


def detect_platform_from_remote() -> str | None:
    """Auto-detect platform from git remote URL."""
    try:
        result = subprocess.run(
            ['git', 'remote', 'get-url', 'origin'],
            capture_output=True,
            text=True,
            check=True,
        )
        url = result.stdout.strip()

        if 'github.com' in url:
            return 'github'
        elif 'gitlab.com' in url or 'gitlab' in url:
            return 'gitlab'
    except Exception:
        pass

    return None


def resolve_issue_platform() -> str | None:
    """Resolve issue platform using config then auto-detect."""
    # Check config first
    platform = get_issue_platform()
    if platform:
        return platform

    # Auto-detect from git remote
    return detect_platform_from_remote()
