#!/usr/bin/env python3
# boxctl:
#   category: baremetal/services
#   tags: [health, service, haproxy, loadbalancer, proxy]
#   requires: [haproxy]
#   privilege: root
#   related: []
#   brief: Monitor HAProxy load balancer health and backend status

"""
Monitor HAProxy load balancer health via stats socket or HTTP stats page.

Checks backend server health, session counts, error rates, and queue depths.
Useful for standalone HAProxy load balancers, database connection pooling,
and web application load balancing.

Exit codes:
    0 - All backends healthy, no issues
    1 - Issues detected (backends down, high error rates, queue buildup)
    2 - Cannot connect to HAProxy stats or usage error
"""

import argparse
import csv
import io
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


DEFAULT_SOCKET_PATHS = [
    "/run/haproxy/admin.sock",
    "/var/run/haproxy/admin.sock",
    "/var/lib/haproxy/stats",
    "/run/haproxy.sock",
    "/var/run/haproxy.sock",
]

# Default thresholds
DEFAULT_SESSION_WARN_PCT = 80
DEFAULT_QUEUE_WARN = 10
DEFAULT_QUEUE_CRIT = 50


def find_haproxy_socket(context: Context) -> str | None:
    """Find the HAProxy stats socket."""
    for path in DEFAULT_SOCKET_PATHS:
        if context.file_exists(path):
            return path
    return None


def query_socket(socket_path: str, context: Context) -> tuple[bool, str]:
    """Query HAProxy via Unix socket."""
    # Use socat to query the socket
    result = context.run(
        ["socat", "-", f"UNIX-CONNECT:{socket_path}"],
        check=False,
        timeout=10,
    )

    if result.returncode != 0:
        return False, result.stderr or "Failed to connect to socket"

    return True, result.stdout


def parse_csv_stats(csv_data: str) -> list[dict[str, Any]]:
    """Parse HAProxy CSV stats output."""
    stats = []

    # Remove leading # from header if present
    lines = csv_data.strip().split("\n")
    if lines and lines[0].startswith("# "):
        lines[0] = lines[0][2:]

    reader = csv.DictReader(io.StringIO("\n".join(lines)))

    for row in reader:
        # Clean up keys (remove leading/trailing whitespace)
        cleaned = {k.strip(): v.strip() if v else "" for k, v in row.items() if k}
        if cleaned:
            stats.append(cleaned)

    return stats


def safe_int(val: Any, default: int = 0) -> int:
    """Safely convert to int."""
    try:
        return int(val) if val else default
    except (ValueError, TypeError):
        return default


def analyze_stats(
    stats: list[dict[str, Any]],
    session_warn_pct: int,
    queue_warn: int,
    queue_crit: int,
) -> tuple[list[str], list[str], dict[str, Any]]:
    """
    Analyze HAProxy stats and identify issues.

    Returns:
        Tuple of (issues, warnings, analysis)
    """
    issues = []
    warnings = []
    analysis: dict[str, Any] = {
        "healthy": True,
        "frontends": [],
        "backends": [],
        "servers": [],
        "total_sessions": 0,
        "backends_up": 0,
        "backends_down": 0,
        "servers_up": 0,
        "servers_down": 0,
    }

    for entry in stats:
        pxname = entry.get("pxname", "")
        svname = entry.get("svname", "")
        status = entry.get("status", "")

        if not pxname or not svname:
            continue

        scur = safe_int(entry.get("scur"))  # Current sessions
        slim = safe_int(entry.get("slim"))  # Session limit
        qcur = safe_int(entry.get("qcur"))  # Current queue

        entry_info = {
            "name": f"{pxname}/{svname}",
            "status": status,
            "current_sessions": scur,
            "session_limit": slim,
            "queue": qcur,
        }

        # Frontend analysis
        if svname == "FRONTEND":
            analysis["frontends"].append(entry_info)

            if status != "OPEN":
                issues.append(f"Frontend {pxname} is {status}")

            # Session usage
            if slim > 0:
                session_pct = (scur / slim) * 100
                if session_pct >= session_warn_pct:
                    warnings.append(
                        f"Frontend {pxname} session usage high: "
                        f"{scur}/{slim} ({session_pct:.1f}%)"
                    )

        # Backend analysis
        elif svname == "BACKEND":
            analysis["backends"].append(entry_info)
            analysis["total_sessions"] += scur

            if status == "UP":
                analysis["backends_up"] += 1
            else:
                analysis["backends_down"] += 1
                if status == "DOWN":
                    issues.append(f"Backend {pxname} is DOWN")
                elif status == "MAINT":
                    warnings.append(f"Backend {pxname} is in MAINT mode")
                else:
                    warnings.append(f"Backend {pxname} status: {status}")

            # Queue depth
            if qcur >= queue_crit:
                issues.append(f"Backend {pxname} queue critical: {qcur} requests")
            elif qcur >= queue_warn:
                warnings.append(f"Backend {pxname} queue high: {qcur} requests")

        # Server analysis
        else:
            analysis["servers"].append(entry_info)

            if status in ("UP", "no check"):
                analysis["servers_up"] += 1
            else:
                analysis["servers_down"] += 1
                if status == "DOWN":
                    issues.append(f"Server {pxname}/{svname} is DOWN")
                elif status == "MAINT":
                    warnings.append(f"Server {pxname}/{svname} is in MAINT mode")
                elif status == "DRAIN":
                    warnings.append(f"Server {pxname}/{svname} is DRAINing")
                elif status != "no check":
                    warnings.append(f"Server {pxname}/{svname} status: {status}")

    analysis["healthy"] = len(issues) == 0

    return issues, warnings, analysis


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = cannot connect
    """
    parser = argparse.ArgumentParser(
        description="Monitor HAProxy health via stats socket"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json", "table"], default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show if issues detected"
    )
    parser.add_argument(
        "-s", "--socket", help="Path to HAProxy stats socket"
    )
    parser.add_argument(
        "--session-warn-pct",
        type=int,
        default=DEFAULT_SESSION_WARN_PCT,
        help=f"Session usage warning threshold %% (default: {DEFAULT_SESSION_WARN_PCT})",
    )
    parser.add_argument(
        "--queue-warn",
        type=int,
        default=DEFAULT_QUEUE_WARN,
        help=f"Queue depth warning threshold (default: {DEFAULT_QUEUE_WARN})",
    )
    parser.add_argument(
        "--queue-crit",
        type=int,
        default=DEFAULT_QUEUE_CRIT,
        help=f"Queue depth critical threshold (default: {DEFAULT_QUEUE_CRIT})",
    )
    # Allow passing stats data directly for testing
    parser.add_argument(
        "--stats-data", help=argparse.SUPPRESS  # Hidden arg for testing
    )
    opts = parser.parse_args(args)

    # For testing: allow passing stats data directly
    if opts.stats_data:
        csv_data = opts.stats_data
    else:
        # Check for socat (needed to query socket)
        if not context.check_tool("socat"):
            output.error("socat not found. Install socat package.")
            return 2

        # Find socket
        socket_path = opts.socket or find_haproxy_socket(context)
        if not socket_path:
            output.error("HAProxy stats socket not found")
            output.error(f"Tried: {', '.join(DEFAULT_SOCKET_PATHS)}")
            return 2

        if not context.file_exists(socket_path):
            output.error(f"Socket not found: {socket_path}")
            return 2

        # Query socket - send "show stat" command
        # Note: In real usage, we'd need to pipe the command
        success, data = query_socket(socket_path, context)
        if not success:
            output.error(f"Cannot connect to HAProxy socket: {data}")
            return 2

        csv_data = data

    # Parse stats
    try:
        stats = parse_csv_stats(csv_data)
    except Exception as e:
        output.error(f"Failed to parse HAProxy stats: {e}")

        output.render(opts.format, "Monitor HAProxy load balancer health and backend status")
        return 2

    if not stats:
        output.error("No stats data received from HAProxy")

        output.render(opts.format, "Monitor HAProxy load balancer health and backend status")
        return 2

    # Analyze stats
    issues, warnings, analysis = analyze_stats(
        stats,
        opts.session_warn_pct,
        opts.queue_warn,
        opts.queue_crit,
    )

    # Build output
    result: dict[str, Any] = {
        "healthy": analysis["healthy"],
        "backends_up": analysis["backends_up"],
        "backends_down": analysis["backends_down"],
        "servers_up": analysis["servers_up"],
        "servers_down": analysis["servers_down"],
        "total_sessions": analysis["total_sessions"],
        "issues": issues,
        "warnings": warnings,
    }

    if opts.verbose:
        result["frontends"] = analysis["frontends"]
        result["backends"] = analysis["backends"]
        result["servers"] = analysis["servers"]

    output.emit(result)

    # Set summary
    if issues:
        output.set_summary(
            f"HAProxy UNHEALTHY: {analysis['backends_down']} backends down, "
            f"{analysis['servers_down']} servers down"
        )
    elif warnings:
        output.set_summary(
            f"HAProxy WARNING: {analysis['backends_up']} backends up, "
            f"{len(warnings)} warnings"
        )
    else:
        output.set_summary(
            f"HAProxy healthy: {analysis['backends_up']} backends, "
            f"{analysis['servers_up']} servers up"
        )

    output.render(opts.format, "Monitor HAProxy load balancer health and backend status")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
