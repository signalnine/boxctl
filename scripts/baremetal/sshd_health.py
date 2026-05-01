#!/usr/bin/env python3
# boxctl:
#   category: baremetal/services
#   tags: [health, service, sshd, security, daemon]
#   requires: [sshd]
#   privilege: root
#   related: [systemd_service_monitor]
#   brief: Monitor SSH daemon health, configuration, and connection limits

"""
Monitor SSH daemon health, configuration, and connection limits.

Checks sshd service status, current connection counts, MaxSessions/MaxStartups
limits, authentication settings, and identifies potential security or
capacity issues. Useful for monitoring bastion hosts and jump servers.

Exit codes:
    0 - SSH daemon healthy, no issues detected
    1 - Warnings or errors found
    2 - sshd not installed or not running
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_sshd_running(context: Context) -> bool:
    """Check if sshd service is running."""
    # Try systemctl first
    result = context.run(["systemctl", "is-active", "sshd"], check=False)
    if result.returncode == 0 and result.stdout.strip() == "active":
        return True

    # Try alternative service name
    result = context.run(["systemctl", "is-active", "ssh"], check=False)
    if result.returncode == 0 and result.stdout.strip() == "active":
        return True

    # Fall back to process check
    result = context.run(["pgrep", "-x", "sshd"], check=False)
    return result.returncode == 0


def get_sshd_config(context: Context) -> dict[str, str]:
    """Parse sshd configuration."""
    config = {}

    # Get effective configuration via sshd -T
    result = context.run(["sshd", "-T"], check=False)

    if result.returncode != 0:
        # Try reading config file directly
        if context.file_exists("/etc/ssh/sshd_config"):
            content = context.read_file("/etc/ssh/sshd_config")
            for line in content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        config[parts[0].lower()] = parts[1]
        return config

    # Parse sshd -T output
    for line in result.stdout.split("\n"):
        line = line.strip()
        if line:
            parts = line.split(None, 1)
            if len(parts) == 2:
                config[parts[0].lower()] = parts[1]

    return config


def get_active_connections(context: Context) -> dict[str, Any]:
    """Get count of active SSH connections."""
    connections: dict[str, Any] = {
        "total": 0,
        "established": 0,
        "by_user": {},
    }

    # Count established SSH connections
    result = context.run(
        ["ss", "-tn", "state", "established", "( dport = :22 or sport = :22 )"],
        check=False,
    )
    if result.returncode == 0:
        lines = result.stdout.strip().split("\n")
        # Subtract header line if present
        connections["established"] = max(0, len(lines) - 1)

    # Count sshd processes (each session has a child sshd)
    result = context.run(["pgrep", "-c", "sshd"], check=False)
    if result.returncode == 0:
        try:
            # Subtract 1 for the main sshd process
            total = max(0, int(result.stdout.strip()) - 1)
            connections["total"] = total
        except ValueError:
            pass

    # Get connections by user from who command
    result = context.run(["who"], check=False)
    if result.returncode == 0:
        for line in result.stdout.split("\n"):
            if line.strip():
                parts = line.split()
                if parts:
                    user = parts[0]
                    connections["by_user"][user] = connections["by_user"].get(user, 0) + 1

    return connections


def analyze_config(
    config: dict[str, str], connections: dict[str, Any]
) -> list[dict[str, str]]:
    """Analyze configuration for issues."""
    issues = []

    # Check MaxSessions limit
    max_sessions = int(config.get("maxsessions", "10"))
    if max_sessions > 0 and connections["total"] > max_sessions * 0.8:
        issues.append(
            {
                "severity": "warning",
                "message": f"Approaching MaxSessions limit: {connections['total']}/{max_sessions} sessions",
            }
        )

    # Security checks
    permit_root = config.get("permitrootlogin", "no")
    if permit_root == "yes":
        issues.append(
            {
                "severity": "warning",
                "message": "PermitRootLogin is set to yes (password auth allowed for root)",
            }
        )

    if config.get("passwordauthentication", "yes") == "yes":
        issues.append(
            {
                "severity": "info",
                "message": "PasswordAuthentication is enabled (consider key-only auth)",
            }
        )

    if config.get("permitemptypasswords", "no") == "yes":
        issues.append(
            {
                "severity": "critical",
                "message": "PermitEmptyPasswords is enabled (security risk!)",
            }
        )

    if config.get("x11forwarding", "no") == "yes":
        issues.append(
            {
                "severity": "info",
                "message": "X11Forwarding is enabled",
            }
        )

    client_alive_interval = int(config.get("clientaliveinterval", "0"))
    if client_alive_interval == 0:
        issues.append(
            {
                "severity": "info",
                "message": "ClientAliveInterval not set (zombie sessions may persist)",
            }
        )

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = sshd not available
    """
    parser = argparse.ArgumentParser(
        description="Monitor SSH daemon health and configuration"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json", "table"], default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show warnings, suppress info"
    )
    opts = parser.parse_args(args)

    # Check if sshd is installed
    if not context.check_tool("sshd"):
        output.error("sshd not found. Install openssh-server package.")

        output.render(opts.format, "Monitor SSH daemon health, configuration, and connection limits")
        return 2

    # Check if sshd is running
    running = check_sshd_running(context)

    result: dict[str, Any] = {
        "running": running,
        "config": {},
        "connections": {"total": 0, "established": 0, "by_user": {}},
        "issues": [],
    }

    if not running:
        result["issues"].append(
            {"severity": "critical", "message": "sshd daemon is not running"}
        )
        output.emit(result)
        output.error("sshd daemon is not running")

        output.render(opts.format, "Monitor SSH daemon health, configuration, and connection limits")
        return 2

    # Get config and connections
    result["config"] = get_sshd_config(context)
    result["connections"] = get_active_connections(context)
    result["issues"] = analyze_config(result["config"], result["connections"])

    # Filter issues if warn-only mode
    if opts.warn_only:
        result["issues"] = [
            i for i in result["issues"] if i["severity"] != "info"
        ]

    # Remove verbose details if not requested
    if not opts.verbose:
        result["config"] = {
            k: v
            for k, v in result["config"].items()
            if k in ("port", "maxsessions", "permitrootlogin", "passwordauthentication")
        }
        result["connections"].pop("by_user", None)

    output.emit(result)

    # Set summary
    conn = result["connections"]
    issue_count = len(result["issues"])
    if issue_count > 0:
        critical = sum(1 for i in result["issues"] if i["severity"] == "critical")
        output.set_summary(f"sshd running, {conn['total']} sessions, {issue_count} issues ({critical} critical)")
    else:
        output.set_summary(f"sshd healthy, {conn['total']} sessions")

    # Determine exit code
    has_issues = any(
        i["severity"] in ("warning", "critical") for i in result["issues"]
    )

    output.render(opts.format, "Monitor SSH daemon health, configuration, and connection limits")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
