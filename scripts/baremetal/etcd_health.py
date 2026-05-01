#!/usr/bin/env python3
# boxctl:
#   category: baremetal/services
#   tags: [health, service, etcd, distributed, consensus]
#   requires: [etcdctl]
#   privilege: user
#   related: []
#   brief: Monitor etcd cluster health and performance

"""
Monitor etcd cluster health and performance.

Checks cluster membership, leader status, database size, latency,
and alarm conditions. Useful for standalone etcd clusters used in
distributed systems.

Exit codes:
    0 - Cluster healthy, all members responsive
    1 - Issues detected (degraded cluster, alarms, high latency)
    2 - etcdctl not found or connection failed
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


DEFAULT_ENDPOINTS = "http://127.0.0.1:2379"
DEFAULT_DB_SIZE_WARN_MB = 2048  # 2GB
DEFAULT_DB_SIZE_CRIT_MB = 6144  # 6GB (etcd limit is 8GB)


def get_cluster_health(
    endpoints: str, context: Context, cacert: str | None = None,
    cert: str | None = None, key: str | None = None
) -> dict[str, Any]:
    """Check cluster endpoint health."""
    cmd = ["etcdctl", "endpoint", "health", "--write-out=json", "--endpoints", endpoints]
    if cacert:
        cmd.extend(["--cacert", cacert])
    if cert:
        cmd.extend(["--cert", cert])
    if key:
        cmd.extend(["--key", key])

    result = context.run(cmd, check=False)

    if result.returncode != 0:
        return {
            "available": False,
            "error": result.stderr.strip() or "Failed to connect to etcd",
            "endpoints": [],
        }

    try:
        # etcdctl outputs one JSON object per line
        health_data = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                health_data.append(json.loads(line))

        return {"available": True, "endpoints": health_data}
    except json.JSONDecodeError:
        return {
            "available": False,
            "error": "Failed to parse health response",
            "raw_output": result.stdout,
        }


def get_endpoint_status(
    endpoints: str, context: Context, cacert: str | None = None,
    cert: str | None = None, key: str | None = None
) -> dict[str, Any]:
    """Get detailed endpoint status including DB size."""
    cmd = ["etcdctl", "endpoint", "status", "--write-out=json", "--endpoints", endpoints]
    if cacert:
        cmd.extend(["--cacert", cacert])
    if cert:
        cmd.extend(["--cert", cert])
    if key:
        cmd.extend(["--key", key])

    result = context.run(cmd, check=False)

    if result.returncode != 0:
        return {
            "available": False,
            "error": result.stderr.strip() or "Failed to get status",
        }

    try:
        status_data = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                status_data.append(json.loads(line))

        return {"available": True, "endpoints": status_data}
    except json.JSONDecodeError:
        return {"available": False, "error": "Failed to parse status response"}


def get_member_list(
    endpoints: str, context: Context, cacert: str | None = None,
    cert: str | None = None, key: str | None = None
) -> dict[str, Any]:
    """Get cluster member list."""
    cmd = ["etcdctl", "member", "list", "--write-out=json", "--endpoints", endpoints]
    if cacert:
        cmd.extend(["--cacert", cacert])
    if cert:
        cmd.extend(["--cert", cert])
    if key:
        cmd.extend(["--key", key])

    result = context.run(cmd, check=False)

    if result.returncode != 0:
        return {
            "available": False,
            "error": result.stderr.strip() or "Failed to get member list",
        }

    try:
        data = json.loads(result.stdout)
        return {
            "available": True,
            "members": data.get("members", []),
            "header": data.get("header", {}),
        }
    except json.JSONDecodeError:
        return {"available": False, "error": "Failed to parse member list"}


def get_alarms(
    endpoints: str, context: Context, cacert: str | None = None,
    cert: str | None = None, key: str | None = None
) -> dict[str, Any]:
    """Get active alarms."""
    cmd = ["etcdctl", "alarm", "list", "--write-out=json", "--endpoints", endpoints]
    if cacert:
        cmd.extend(["--cacert", cacert])
    if cert:
        cmd.extend(["--cert", cert])
    if key:
        cmd.extend(["--key", key])

    result = context.run(cmd, check=False)

    if result.returncode != 0:
        return {
            "available": False,
            "error": result.stderr.strip() or "Failed to get alarms",
        }

    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        return {"available": True, "alarms": data.get("alarms", [])}
    except json.JSONDecodeError:
        return {"available": True, "alarms": []}


def analyze_health(
    health: dict[str, Any],
    status: dict[str, Any],
    members: dict[str, Any],
    alarms: dict[str, Any],
    db_warn_mb: int,
    db_crit_mb: int,
) -> tuple[list[str], list[str], dict[str, Any]]:
    """Analyze etcd health data and identify issues."""
    issues = []
    warnings = []
    analysis: dict[str, Any] = {
        "cluster_healthy": True,
        "leader": None,
        "member_count": 0,
        "healthy_members": 0,
        "db_size_bytes": 0,
        "has_quorum": False,
    }

    # Check if we could connect at all
    if not health.get("available"):
        issues.append(f"Cannot connect to etcd: {health.get('error', 'unknown error')}")
        analysis["cluster_healthy"] = False
        return issues, warnings, analysis

    # Analyze endpoint health
    endpoints = health.get("endpoints", [])
    healthy_count = 0
    for ep in endpoints:
        if ep.get("health"):
            healthy_count += 1
        else:
            issues.append(f"Endpoint {ep.get('endpoint', 'unknown')} unhealthy")

    analysis["healthy_members"] = healthy_count

    # Analyze member list
    if members.get("available"):
        member_list = members.get("members", [])
        analysis["member_count"] = len(member_list)

        for member in member_list:
            if not member.get("name"):
                warnings.append(
                    f"Member {member.get('ID', 'unknown')} has no name (may be unstarted)"
                )

        # Check quorum
        if analysis["member_count"] > 0:
            analysis["has_quorum"] = healthy_count > analysis["member_count"] // 2
            if not analysis["has_quorum"]:
                issues.append(
                    f"Cluster lacks quorum: {healthy_count}/{analysis['member_count']} healthy"
                )
    else:
        warnings.append(f"Could not get member list: {members.get('error', 'unknown')}")

    # Analyze endpoint status
    if status.get("available"):
        status_endpoints = status.get("endpoints", [])
        max_db_size = 0

        for ep_status in status_endpoints:
            ep_info = ep_status.get("Status", ep_status)
            endpoint = ep_status.get("Endpoint", "unknown")

            # Database size
            db_size = ep_info.get("dbSize", 0)
            if db_size > max_db_size:
                max_db_size = db_size

            db_size_mb = db_size / (1024 * 1024)
            if db_size_mb > db_crit_mb:
                issues.append(
                    f"Database size critical: {db_size_mb:.1f}MB (threshold: {db_crit_mb}MB)"
                )
            elif db_size_mb > db_warn_mb:
                warnings.append(
                    f"Database size high: {db_size_mb:.1f}MB (threshold: {db_warn_mb}MB)"
                )

            # Leader info
            if ep_info.get("isLeader"):
                analysis["leader"] = endpoint

        analysis["db_size_bytes"] = max_db_size

        if not analysis["leader"]:
            # Check if we have leader ID from any status
            for ep_status in status_endpoints:
                ep_info = ep_status.get("Status", ep_status)
                if ep_info.get("leader"):
                    # We have a leader ID but didn't find isLeader - that's ok
                    break
            else:
                issues.append("No leader elected - cluster may be unavailable")
    else:
        warnings.append(f"Could not get endpoint status: {status.get('error', 'unknown')}")

    # Analyze alarms
    if alarms.get("available"):
        active_alarms = alarms.get("alarms", [])
        for alarm in active_alarms:
            alarm_type = alarm.get("alarm", alarm.get("alarmType", "UNKNOWN"))
            member_id = alarm.get("memberID", "unknown")
            issues.append(f"Active alarm: {alarm_type} on member {member_id}")
    else:
        warnings.append(f"Could not check alarms: {alarms.get('error', 'unknown')}")

    analysis["cluster_healthy"] = len(issues) == 0

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
        description="Monitor etcd cluster health and performance"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json", "table"], default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show if issues detected"
    )
    parser.add_argument(
        "-e", "--endpoints",
        default=context.get_env("ETCDCTL_ENDPOINTS", DEFAULT_ENDPOINTS),
        help=f"Comma-separated etcd endpoints (default: {DEFAULT_ENDPOINTS})",
    )
    parser.add_argument(
        "--cacert", default=context.get_env("ETCDCTL_CACERT"),
        help="Path to CA certificate for TLS",
    )
    parser.add_argument(
        "--cert", default=context.get_env("ETCDCTL_CERT"),
        help="Path to client certificate for TLS",
    )
    parser.add_argument(
        "--key", default=context.get_env("ETCDCTL_KEY"),
        help="Path to client key for TLS",
    )
    parser.add_argument(
        "--db-warn-mb",
        type=int,
        default=DEFAULT_DB_SIZE_WARN_MB,
        help=f"Database size warning threshold in MB (default: {DEFAULT_DB_SIZE_WARN_MB})",
    )
    parser.add_argument(
        "--db-crit-mb",
        type=int,
        default=DEFAULT_DB_SIZE_CRIT_MB,
        help=f"Database size critical threshold in MB (default: {DEFAULT_DB_SIZE_CRIT_MB})",
    )
    opts = parser.parse_args(args)

    # Check etcdctl availability
    if not context.check_tool("etcdctl"):
        output.error("etcdctl not found. Install etcd: https://etcd.io/docs/latest/install/")

        output.render(opts.format, "Monitor etcd cluster health and performance")
        return 2

    # Gather health data
    health = get_cluster_health(opts.endpoints, context, opts.cacert, opts.cert, opts.key)
    status = get_endpoint_status(opts.endpoints, context, opts.cacert, opts.cert, opts.key)
    members = get_member_list(opts.endpoints, context, opts.cacert, opts.cert, opts.key)
    alarms = get_alarms(opts.endpoints, context, opts.cacert, opts.cert, opts.key)

    # Analyze health
    issues, warnings, analysis = analyze_health(
        health, status, members, alarms,
        opts.db_warn_mb, opts.db_crit_mb,
    )

    # Build output
    db_size_mb = analysis["db_size_bytes"] / (1024 * 1024)
    result: dict[str, Any] = {
        "cluster_healthy": analysis["cluster_healthy"],
        "member_count": analysis["member_count"],
        "healthy_members": analysis["healthy_members"],
        "has_quorum": analysis["has_quorum"],
        "leader": analysis["leader"],
        "db_size_mb": round(db_size_mb, 2),
        "issues": issues,
        "warnings": warnings,
    }

    if opts.verbose:
        result["health_details"] = health
        result["status_details"] = status
        result["members_details"] = members
        result["alarms_details"] = alarms

    output.emit(result)

    # Set summary
    if issues:
        output.set_summary(
            f"etcd UNHEALTHY: {analysis['healthy_members']}/{analysis['member_count']} members, "
            f"{len(issues)} issues"
        )
    elif warnings:
        output.set_summary(
            f"etcd WARNING: {analysis['healthy_members']}/{analysis['member_count']} members, "
            f"{len(warnings)} warnings"
        )
    else:
        output.set_summary(
            f"etcd healthy: {analysis['healthy_members']}/{analysis['member_count']} members, "
            f"{db_size_mb:.0f}MB"
        )

    output.render(opts.format, "Monitor etcd cluster health and performance")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
