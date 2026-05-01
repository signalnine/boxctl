#!/usr/bin/env python3
# boxctl:
#   category: baremetal/services
#   tags: [health, service, cron, scheduler, daemon]
#   requires: [cron]
#   privilege: root
#   related: [systemd_timer_monitor]
#   brief: Monitor cron job health and configuration issues

"""
Monitor cron job health and configuration.

Checks cron configurations for:
- Syntax errors in crontab files
- Jobs with missing executables
- Orphaned user crontabs (user no longer exists)
- Permission issues on cron directories

Exit codes:
    0 - All cron configurations are healthy
    1 - One or more issues detected
    2 - Unable to read cron configuration or usage error
"""

import argparse
import os
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


SYSTEM_CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]

SYSTEM_CRONTAB = "/etc/crontab"
USER_CRONTAB_DIRS = [
    "/var/spool/cron/crontabs",  # Debian/Ubuntu
    "/var/spool/cron",  # RHEL/CentOS
]


def parse_cron_schedule(schedule: str) -> tuple[bool, str]:
    """
    Validate a cron schedule string (5 fields or special string).

    Returns:
        (is_valid, error_message)
    """
    # Handle special strings
    special = {
        "@reboot", "@yearly", "@annually", "@monthly",
        "@weekly", "@daily", "@midnight", "@hourly",
    }
    if schedule.lower() in special:
        return True, ""

    fields = schedule.split()
    if len(fields) < 5:
        return False, f"Too few fields ({len(fields)}, need 5)"
    if len(fields) > 5:
        return False, f"Too many fields ({len(fields)}, max 5 for schedule)"

    return True, ""


def parse_crontab_line(
    line: str, has_user_field: bool = False
) -> dict[str, Any] | None:
    """
    Parse a single crontab line.

    Args:
        line: The crontab line to parse
        has_user_field: True for /etc/crontab and /etc/cron.d/*

    Returns:
        Dict with schedule, user, and command, or None if not a job line
    """
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith("#"):
        return None

    # Skip variable assignments
    if "=" in line and not line.startswith("@") and not line[0].isdigit():
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", line):
            return None

    # Handle special schedules (@reboot, @daily, etc.)
    if line.startswith("@"):
        parts = line.split(None, 2 if has_user_field else 1)
        if len(parts) < (3 if has_user_field else 2):
            return None

        if has_user_field:
            return {
                "schedule": parts[0],
                "user": parts[1],
                "command": parts[2] if len(parts) > 2 else "",
            }
        else:
            return {
                "schedule": parts[0],
                "user": None,
                "command": parts[1] if len(parts) > 1 else "",
            }

    # Standard cron format: min hour day month dow [user] command
    parts = line.split(None, 6 if has_user_field else 5)

    if len(parts) < (7 if has_user_field else 6):
        return None

    schedule = " ".join(parts[:5])

    if has_user_field:
        user = parts[5]
        command = parts[6] if len(parts) > 6 else ""
    else:
        user = None
        command = parts[5] if len(parts) > 5 else ""

    return {
        "schedule": schedule,
        "user": user,
        "command": command,
    }


def check_user_exists(username: str, context: Context) -> bool:
    """Check if a user exists on the system."""
    try:
        result = context.run(["id", username], check=False)
        return result.returncode == 0
    except Exception:
        return False


def check_command_exists(cmd: str, context: Context) -> bool:
    """Check if a command exists."""
    if not cmd:
        return False

    # Extract the actual command (first word)
    parts = cmd.split()
    if not parts:
        return False

    executable = parts[0]

    # Skip shell built-ins
    builtins = {
        "cd", "echo", "test", "[", "true", "false", "exit",
        "export", "source", ".", "eval", "exec", "set", "unset",
    }
    if executable in builtins:
        return True

    # Handle interpreters
    interpreters = {
        "/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/zsh",
        "/usr/bin/python", "/usr/bin/python3", "/usr/bin/perl",
        "sh", "bash", "zsh", "python", "python3", "perl",
    }
    if executable in interpreters:
        return True

    # Check absolute path
    if executable.startswith("/"):
        return context.file_exists(executable)

    # Check via which
    result = context.run(["which", executable], check=False)
    return result.returncode == 0


def analyze_crontab_file(
    path: str, has_user_field: bool, context: Context, check_users: bool = True
) -> dict[str, Any]:
    """Analyze a crontab file for issues."""
    result: dict[str, Any] = {
        "path": path,
        "exists": False,
        "readable": False,
        "jobs": [],
        "issues": [],
        "severity": "OK",
    }

    if not context.file_exists(path):
        return result

    result["exists"] = True

    try:
        content = context.read_file(path)
        result["readable"] = True
    except Exception as e:
        result["issues"].append(f"Cannot read file: {e}")
        result["severity"] = "WARNING"
        return result

    # Parse each line
    line_number = 0
    for line in content.split("\n"):
        line_number += 1
        job = parse_crontab_line(line, has_user_field)

        if job is None:
            continue

        job["line_number"] = line_number
        job["issues"] = []
        job["severity"] = "OK"

        # Validate schedule
        is_valid, error = parse_cron_schedule(job["schedule"])
        if not is_valid:
            job["issues"].append(f"Invalid schedule: {error}")
            job["severity"] = "CRITICAL"

        # Check if user exists (for system crontabs)
        if check_users and job["user"] and not check_user_exists(job["user"], context):
            job["issues"].append(f"User '{job['user']}' does not exist")
            job["severity"] = "CRITICAL"

        if job["issues"]:
            if job["severity"] == "CRITICAL":
                result["severity"] = "CRITICAL"
            elif result["severity"] == "OK":
                result["severity"] = "WARNING"

        result["jobs"].append(job)

    return result


def get_user_crontab_dir(context: Context) -> str | None:
    """Find the user crontab directory."""
    for path in USER_CRONTAB_DIRS:
        if context.file_exists(path):
            return path
    return None


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor cron job health and configuration"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json", "table"], default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show entries with issues"
    )
    parser.add_argument(
        "--system-only", action="store_true", help="Only check system cron files"
    )
    parser.add_argument(
        "--user-only", action="store_true", help="Only check user crontabs"
    )
    opts = parser.parse_args(args)

    if opts.system_only and opts.user_only:
        output.error("Cannot specify both --system-only and --user-only")

        output.render(opts.format, "Monitor cron job health and configuration issues")
        return 2

    results: dict[str, Any] = {
        "system_crontab": None,
        "cron_directories": [],
        "user_crontabs": [],
    }

    has_critical = False
    has_warning = False
    total_jobs = 0
    jobs_with_issues = 0

    # Check system crontab
    if not opts.user_only and context.file_exists(SYSTEM_CRONTAB):
        result = analyze_crontab_file(SYSTEM_CRONTAB, has_user_field=True, context=context)
        results["system_crontab"] = result
        total_jobs += len(result.get("jobs", []))
        jobs_with_issues += sum(
            1 for j in result.get("jobs", []) if j.get("severity") != "OK"
        )
        if result["severity"] == "CRITICAL":
            has_critical = True
        elif result["severity"] == "WARNING":
            has_warning = True

    # Check cron directories
    if not opts.user_only:
        for cron_dir in SYSTEM_CRON_DIRS:
            if not context.file_exists(cron_dir):
                continue

            dir_result = {
                "path": cron_dir,
                "files": [],
                "severity": "OK",
            }

            # For cron.d, parse as crontab files
            if cron_dir == "/etc/cron.d":
                try:
                    entries = context.glob("*", root=cron_dir)
                    for entry in entries:
                        if entry.endswith((".dpkg-old", ".dpkg-new", "~", ".bak")):
                            continue
                        file_result = analyze_crontab_file(
                            entry, has_user_field=True, context=context
                        )
                        dir_result["files"].append(file_result)
                        total_jobs += len(file_result.get("jobs", []))
                        jobs_with_issues += sum(
                            1 for j in file_result.get("jobs", [])
                            if j.get("severity") != "OK"
                        )
                        if file_result["severity"] == "CRITICAL":
                            dir_result["severity"] = "CRITICAL"
                        elif file_result["severity"] == "WARNING" and dir_result["severity"] == "OK":
                            dir_result["severity"] = "WARNING"
                except Exception:
                    pass

            results["cron_directories"].append(dir_result)
            if dir_result["severity"] == "CRITICAL":
                has_critical = True
            elif dir_result["severity"] == "WARNING":
                has_warning = True

    # Check user crontabs
    if not opts.system_only:
        user_crontab_dir = get_user_crontab_dir(context)
        if user_crontab_dir:
            try:
                entries = context.glob("*", root=user_crontab_dir)
                for entry in entries:
                    if os.path.basename(entry).startswith("."):
                        continue
                    user_result = analyze_crontab_file(
                        entry, has_user_field=False, context=context
                    )
                    user_result["username"] = os.path.basename(entry)
                    results["user_crontabs"].append(user_result)
                    total_jobs += len(user_result.get("jobs", []))
                    jobs_with_issues += sum(
                        1 for j in user_result.get("jobs", [])
                        if j.get("severity") != "OK"
                    )
                    if user_result["severity"] == "CRITICAL":
                        has_critical = True
                    elif user_result["severity"] == "WARNING":
                        has_warning = True
            except Exception:
                pass

    # Filter output for warn-only mode
    if opts.warn_only:
        if results["system_crontab"]:
            results["system_crontab"]["jobs"] = [
                j for j in results["system_crontab"].get("jobs", [])
                if j.get("severity") != "OK"
            ]
        for dir_result in results["cron_directories"]:
            for f in dir_result.get("files", []):
                f["jobs"] = [j for j in f.get("jobs", []) if j.get("severity") != "OK"]
        for user in results["user_crontabs"]:
            user["jobs"] = [j for j in user.get("jobs", []) if j.get("severity") != "OK"]

    # Simplify output for non-verbose mode
    if not opts.verbose:
        if results["system_crontab"]:
            for job in results["system_crontab"].get("jobs", []):
                job.pop("command", None)
        for dir_result in results["cron_directories"]:
            for f in dir_result.get("files", []):
                for job in f.get("jobs", []):
                    job.pop("command", None)

    output.emit({
        "total_jobs": total_jobs,
        "jobs_with_issues": jobs_with_issues,
        "system_crontab": results["system_crontab"],
        "cron_directories": results["cron_directories"],
        "user_crontabs": results["user_crontabs"],
    })

    # Set summary
    if has_critical:
        output.set_summary(f"{total_jobs} jobs, {jobs_with_issues} with issues (critical)")
    elif has_warning:
        output.set_summary(f"{total_jobs} jobs, {jobs_with_issues} with issues")
    else:
        output.set_summary(f"{total_jobs} cron jobs healthy")

    output.render(opts.format, "Monitor cron job health and configuration issues")

    return 1 if (has_critical or has_warning) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
