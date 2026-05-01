#!/usr/bin/env python3
# boxctl:
#   category: k8s/helm
#   tags: [helm, kubernetes, releases, deployment, health]
#   requires: [helm]
#   brief: Monitor Helm release health and deployment status
#   privilege: user
#   related: [gitops_sync, deployment_status]

"""
Monitor Helm release health and deployment status in Kubernetes clusters.

This script provides visibility into Helm releases, including:
- Release status (deployed, failed, pending-install, pending-upgrade, etc.)
- Chart versions and app versions
- Release age and last deployment time
- Detection of failed or stalled releases
- Namespace-based filtering

Exit codes:
    0 - All Helm releases healthy (deployed status)
    1 - One or more releases in failed or problematic state
    2 - Usage error or helm not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_timestamp(timestamp_str: str | None) -> datetime | None:
    """Parse Helm timestamp string to datetime object."""
    if not timestamp_str:
        return None
    try:
        # Helm uses RFC3339 format: 2024-01-15T10:30:00.123456789Z
        # Python's fromisoformat doesn't handle nanoseconds, so truncate
        if "." in timestamp_str:
            base, frac = timestamp_str.rsplit(".", 1)
            # Keep only microseconds (6 digits)
            frac = frac.rstrip("Z")[:6]
            timestamp_str = f"{base}.{frac}+00:00"
        else:
            timestamp_str = timestamp_str.replace("Z", "+00:00")
        return datetime.fromisoformat(timestamp_str)
    except (ValueError, AttributeError):
        return None


def calculate_age(timestamp: datetime | None) -> str:
    """Calculate human-readable age from timestamp."""
    if not timestamp:
        return "unknown"

    now = datetime.now(timezone.utc)
    delta = now - timestamp

    days = delta.days
    hours = delta.seconds // 3600
    minutes = (delta.seconds % 3600) // 60

    if days > 0:
        return f"{days}d{hours}h"
    elif hours > 0:
        return f"{hours}h{minutes}m"
    else:
        return f"{minutes}m"


def check_release_status(release: dict) -> dict:
    """Check release status and return health info."""
    status = release.get("status", "unknown")
    name = release.get("name", "unknown")
    namespace = release.get("namespace", "default")
    chart = release.get("chart", "unknown")
    app_version = release.get("app_version", "unknown")
    revision = release.get("revision", 0)
    updated = release.get("updated", "")

    # Parse timestamp
    timestamp = parse_timestamp(updated)
    age = calculate_age(timestamp)

    # Determine health
    healthy_statuses = ["deployed"]
    warning_statuses = [
        "pending-install",
        "pending-upgrade",
        "pending-rollback",
        "uninstalling",
    ]
    failed_statuses = ["failed", "superseded"]

    is_healthy = status.lower() in healthy_statuses
    is_warning = status.lower() in warning_statuses
    is_failed = status.lower() in failed_statuses

    issues = []
    if is_failed:
        issues.append(f"Release in {status} state")
    elif is_warning:
        issues.append(f"Release in {status} state (operation in progress)")

    return {
        "name": name,
        "namespace": namespace,
        "status": status,
        "chart": chart,
        "app_version": app_version,
        "revision": revision,
        "updated": updated,
        "age": age,
        "healthy": is_healthy,
        "issues": issues,
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all OK, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Helm release health and deployment status"
    )
    parser.add_argument(
        "--namespace",
        "-n",
        help="Namespace to check (default: all namespaces)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show releases with issues",
    )
    opts = parser.parse_args(args)

    # Check for helm
    if not context.check_tool("helm"):
        output.error("helm not found in PATH")
        return 2

    # Get Helm releases
    try:
        helm_args = ["helm", "list", "-o", "json"]
        if opts.namespace:
            helm_args.extend(["-n", opts.namespace])
        else:
            helm_args.append("--all-namespaces")

        result = context.run(helm_args)
        if result.returncode != 0:
            output.error(f"helm failed: {result.stderr}")
            return 2

        if not result.stdout.strip():
            releases = []
        else:
            releases = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get helm releases: {e}")
        return 2

    has_issues = False

    # Process all releases
    processed = []
    for release in releases:
        info = check_release_status(release)
        if info["issues"]:
            has_issues = True
        if not opts.warn_only or info["issues"]:
            processed.append(info)

    if opts.format == "json":
        print(json.dumps(processed, indent=2))

    elif opts.format == "table":
        if not processed:
            print("No Helm releases found")
        else:
            # Print header
            print(
                f"{'STATUS':<12} {'NAMESPACE':<20} {'NAME':<30} {'CHART':<35} {'APP VERSION':<15} {'AGE':<10}"
            )
            print("-" * 122)

            for info in processed:
                status_marker = "" if info["healthy"] else "[!] "
                print(
                    f"{status_marker}{info['status']:<12} {info['namespace']:<20} {info['name']:<30} "
                    f"{info['chart']:<35} {info['app_version']:<15} {info['age']:<10}"
                )

                for issue in info["issues"]:
                    print(f"    WARNING: {issue}")

    else:  # plain format
        healthy_count = 0
        unhealthy_count = 0

        for info in processed:
            if info["healthy"]:
                healthy_count += 1
            else:
                unhealthy_count += 1

            status_marker = "[OK]" if info["healthy"] else "[!!]"
            print(f"{status_marker} {info['namespace']}/{info['name']}")
            print(f"    Status: {info['status']}")
            print(f"    Chart: {info['chart']}")
            print(f"    App Version: {info['app_version']}")
            print(f"    Revision: {info['revision']}")
            print(f"    Age: {info['age']}")

            for issue in info["issues"]:
                print(f"    WARNING: {issue}")

            print()

        # Print summary
        total = healthy_count + unhealthy_count
        if total > 0:
            print(
                f"Summary: {healthy_count}/{total} releases healthy, {unhealthy_count} with issues"
            )
        else:
            print("No Helm releases found")

    output.set_summary(
        f"releases={len(processed)}, healthy={sum(1 for r in processed if r['healthy'])}, "
        f"unhealthy={sum(1 for r in processed if not r['healthy'])}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
