#!/usr/bin/env python3
# boxctl:
#   category: k8s/storage
#   tags: [backup, kubernetes, velero, snapshot, disaster-recovery]
#   requires: [kubectl]
#   privilege: user
#   brief: Monitor Kubernetes backup health including Velero, VolumeSnapshots, and CronJobs
#   related: [volume_attachment, pvc_stuck]

"""
Kubernetes Backup Health Monitor - Monitor backup systems in Kubernetes.

Provides comprehensive backup health monitoring for Kubernetes clusters,
checking backup schedules, recent backup completion status, snapshot health,
and backup-related CronJob execution. Essential for disaster recovery compliance.

Monitors:
- Velero backups and schedules
- VolumeSnapshots and their status
- Backup-related CronJobs

Exit codes:
    0 - All backups healthy (recent successful backups exist)
    1 - Backup issues detected (stale, failed, or missing backups)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_k8s_timestamp(timestamp_str: str | None) -> datetime | None:
    """Parse Kubernetes timestamp to datetime."""
    if not timestamp_str:
        return None
    try:
        # Handle both formats: with and without microseconds
        if "." in timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        else:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def get_age_hours(timestamp: datetime | None) -> float:
    """Get age in hours from timestamp."""
    if not timestamp:
        return float("inf")
    now = datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    delta = now - timestamp
    return delta.total_seconds() / 3600


def format_age(hours: float) -> str:
    """Format age in human-readable form."""
    if hours == float("inf"):
        return "unknown"
    if hours < 1:
        return f"{int(hours * 60)}m"
    if hours < 24:
        return f"{hours:.1f}h"
    days = hours / 24
    return f"{days:.1f}d"


def check_velero_backups(
    context: Context, namespace: str | None, max_age_hours: int
) -> tuple[list | None, list]:
    """Check Velero backup health."""
    issues = []
    backups = []

    # Check if Velero CRDs exist
    result = context.run(
        ["kubectl", "api-resources", "--api-group=velero.io", "-o", "name"]
    )
    if result.returncode != 0 or "backups" not in result.stdout:
        return None, []  # Velero not installed

    # Get backup schedules
    result = context.run(
        ["kubectl", "get", "schedules.velero.io", "-A", "-o", "json"]
    )
    schedules = []
    if result.returncode == 0:
        try:
            data = json.loads(result.stdout)
            schedules = data.get("items", [])
        except json.JSONDecodeError:
            pass

    # Get recent backups
    result = context.run(["kubectl", "get", "backups.velero.io", "-A", "-o", "json"])
    if result.returncode != 0:
        issues.append("Unable to query Velero backups")
        return issues, backups

    try:
        data = json.loads(result.stdout)
        backup_items = data.get("items", [])
    except json.JSONDecodeError:
        issues.append("Failed to parse Velero backup data")
        return issues, backups

    if not backup_items and schedules:
        issues.append("No Velero backups found but schedules exist")

    # Analyze backups
    for backup in backup_items:
        name = backup["metadata"]["name"]
        ns = backup["metadata"].get("namespace", "velero")
        status = backup.get("status", {})
        phase = status.get("phase", "Unknown")
        completion_time = parse_k8s_timestamp(status.get("completionTimestamp"))
        start_time = parse_k8s_timestamp(status.get("startTimestamp"))

        backup_info = {
            "name": name,
            "namespace": ns,
            "phase": phase,
            "type": "velero",
            "completion_time": status.get("completionTimestamp"),
            "age_hours": get_age_hours(completion_time or start_time),
            "issues": [],
        }

        # Check for issues
        if phase == "Failed":
            backup_info["issues"].append(
                f"Backup failed: {status.get('failureReason', 'unknown')}"
            )
        elif phase == "PartiallyFailed":
            backup_info["issues"].append("Backup partially failed")
        elif phase not in ["Completed", "InProgress", "New"]:
            backup_info["issues"].append(f"Unexpected phase: {phase}")

        backups.append(backup_info)

    # Check for stale backups (no recent successful backup)
    successful_backups = [b for b in backups if b["phase"] == "Completed"]
    if successful_backups:
        most_recent = min(successful_backups, key=lambda x: x["age_hours"])
        if most_recent["age_hours"] > max_age_hours:
            issues.append(
                f"Most recent successful Velero backup is {format_age(most_recent['age_hours'])} old "
                f"(threshold: {max_age_hours}h)"
            )

    return issues, backups


def check_volume_snapshots(
    context: Context, namespace: str | None, max_age_hours: int
) -> tuple[list | None, list]:
    """Check VolumeSnapshot health."""
    issues = []
    snapshots = []

    # Check if VolumeSnapshot CRDs exist
    result = context.run(
        ["kubectl", "api-resources", "--api-group=snapshot.storage.k8s.io", "-o", "name"]
    )
    if result.returncode != 0 or "volumesnapshots" not in result.stdout:
        return None, []  # VolumeSnapshots not available

    # Get VolumeSnapshots
    cmd = ["kubectl", "get", "volumesnapshots", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("-A")

    result = context.run(cmd)
    if result.returncode != 0:
        issues.append("Unable to query VolumeSnapshots")
        return issues, snapshots

    try:
        data = json.loads(result.stdout)
        snapshot_items = data.get("items", [])
    except json.JSONDecodeError:
        issues.append("Failed to parse VolumeSnapshot data")
        return issues, snapshots

    for snap in snapshot_items:
        name = snap["metadata"]["name"]
        ns = snap["metadata"].get("namespace", "default")
        status = snap.get("status", {})
        ready = status.get("readyToUse", False)
        creation_time = parse_k8s_timestamp(snap["metadata"].get("creationTimestamp"))
        restore_size = status.get("restoreSize", "Unknown")

        snapshot_info = {
            "name": name,
            "namespace": ns,
            "ready": ready,
            "type": "volumesnapshot",
            "creation_time": snap["metadata"].get("creationTimestamp"),
            "age_hours": get_age_hours(creation_time),
            "restore_size": restore_size,
            "issues": [],
        }

        # Check for issues
        if not ready:
            error = status.get("error", {})
            if error:
                snapshot_info["issues"].append(
                    f"Not ready: {error.get('message', 'unknown error')}"
                )
            else:
                snapshot_info["issues"].append("Snapshot not ready")

        snapshots.append(snapshot_info)

    # Check for stale snapshots
    ready_snapshots = [s for s in snapshots if s["ready"]]
    if ready_snapshots:
        most_recent = min(ready_snapshots, key=lambda x: x["age_hours"])
        if most_recent["age_hours"] > max_age_hours:
            issues.append(
                f"Most recent ready VolumeSnapshot is {format_age(most_recent['age_hours'])} old "
                f"(threshold: {max_age_hours}h)"
            )

    return issues, snapshots


def check_backup_cronjobs(
    context: Context, namespace: str | None, max_age_hours: int
) -> tuple[list | None, list]:
    """Check backup-related CronJobs and their recent job status."""
    issues = []
    cronjobs = []

    # Common backup CronJob patterns
    backup_patterns = ["backup", "etcd", "snapshot", "dump", "archive"]

    cmd = ["kubectl", "get", "cronjobs", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("-A")

    result = context.run(cmd)
    if result.returncode != 0:
        return None, []

    try:
        data = json.loads(result.stdout)
        cronjob_items = data.get("items", [])
    except json.JSONDecodeError:
        issues.append("Failed to parse CronJob data")
        return issues, cronjobs

    for cj in cronjob_items:
        name = cj["metadata"]["name"]
        ns = cj["metadata"].get("namespace", "default")

        # Check if this looks like a backup CronJob
        is_backup_related = any(pattern in name.lower() for pattern in backup_patterns)
        if not is_backup_related:
            continue

        spec = cj.get("spec", {})
        status = cj.get("status", {})
        schedule = spec.get("schedule", "Unknown")
        suspended = spec.get("suspend", False)
        last_schedule = parse_k8s_timestamp(status.get("lastScheduleTime"))
        last_successful = parse_k8s_timestamp(status.get("lastSuccessfulTime"))

        cronjob_info = {
            "name": name,
            "namespace": ns,
            "schedule": schedule,
            "suspended": suspended,
            "type": "cronjob",
            "last_schedule": status.get("lastScheduleTime"),
            "last_successful": status.get("lastSuccessfulTime"),
            "age_hours": get_age_hours(last_successful or last_schedule),
            "issues": [],
        }

        # Check for issues
        if suspended:
            cronjob_info["issues"].append("CronJob is suspended")

        if last_successful:
            age = get_age_hours(last_successful)
            if age > max_age_hours:
                cronjob_info["issues"].append(
                    f"Last successful run was {format_age(age)} ago"
                )
        elif last_schedule:
            # Has scheduled but never succeeded
            cronjob_info["issues"].append("CronJob has never completed successfully")
        else:
            cronjob_info["issues"].append("CronJob has never run")

        cronjobs.append(cronjob_info)

    return issues, cronjobs


def format_plain(
    velero_issues: list | None,
    velero_backups: list,
    snapshot_issues: list | None,
    snapshots: list,
    cronjob_issues: list | None,
    cronjobs: list,
    warn_only: bool,
    verbose: bool,
) -> tuple[str, bool]:
    """Format output as plain text and return (output, has_issues)."""
    lines = []
    all_issues = []

    if velero_issues:
        all_issues.extend(velero_issues)
    if snapshot_issues:
        all_issues.extend(snapshot_issues)
    if cronjob_issues:
        all_issues.extend(cronjob_issues)

    # Add item-level issues
    for item in velero_backups + snapshots + cronjobs:
        all_issues.extend(item.get("issues", []))

    has_issues = bool(all_issues)

    if velero_issues is not None:
        lines.append("=== Velero Backups ===")
        if velero_backups:
            for backup in velero_backups:
                if warn_only and not backup.get("issues"):
                    continue
                status_icon = "!" if backup.get("issues") else "+"
                lines.append(f"  [{status_icon}] {backup['namespace']}/{backup['name']}")
                lines.append(
                    f"      Phase: {backup['phase']} | Age: {format_age(backup['age_hours'])}"
                )
                for issue in backup.get("issues", []):
                    lines.append(f"      WARNING: {issue}")
        else:
            lines.append("  No Velero backups found")
        if velero_issues:
            for issue in velero_issues:
                lines.append(f"  ISSUE: {issue}")
        lines.append("")

    if snapshot_issues is not None:
        lines.append("=== VolumeSnapshots ===")
        if snapshots:
            for snap in snapshots:
                if warn_only and not snap.get("issues"):
                    continue
                status_icon = "!" if snap.get("issues") else "+"
                ready_str = "ready" if snap["ready"] else "not ready"
                lines.append(f"  [{status_icon}] {snap['namespace']}/{snap['name']}")
                lines.append(
                    f"      Status: {ready_str} | Age: {format_age(snap['age_hours'])} | Size: {snap['restore_size']}"
                )
                for issue in snap.get("issues", []):
                    lines.append(f"      WARNING: {issue}")
        else:
            lines.append("  No VolumeSnapshots found")
        if snapshot_issues:
            for issue in snapshot_issues:
                lines.append(f"  ISSUE: {issue}")
        lines.append("")

    if cronjob_issues is not None:
        lines.append("=== Backup CronJobs ===")
        if cronjobs:
            for cj in cronjobs:
                if warn_only and not cj.get("issues"):
                    continue
                status_icon = "!" if cj.get("issues") else "+"
                suspended_str = " (SUSPENDED)" if cj["suspended"] else ""
                lines.append(
                    f"  [{status_icon}] {cj['namespace']}/{cj['name']}{suspended_str}"
                )
                lines.append(
                    f"      Schedule: {cj['schedule']} | Last success: {format_age(cj['age_hours'])} ago"
                )
                for issue in cj.get("issues", []):
                    lines.append(f"      WARNING: {issue}")
        else:
            lines.append("  No backup-related CronJobs found")
        if cronjob_issues:
            for issue in cronjob_issues:
                lines.append(f"  ISSUE: {issue}")
        lines.append("")

    # Summary
    available_systems = []
    if velero_issues is not None:
        available_systems.append(f"{len(velero_backups)} Velero backups")
    if snapshot_issues is not None:
        available_systems.append(f"{len(snapshots)} VolumeSnapshots")
    if cronjob_issues is not None:
        available_systems.append(f"{len(cronjobs)} backup CronJobs")

    if not available_systems:
        lines.append(
            "No backup systems detected (Velero, VolumeSnapshots, or backup CronJobs)"
        )
    else:
        status = "HEALTHY" if not has_issues else f"ISSUES DETECTED ({len(all_issues)})"
        lines.append(f"Summary: {status}")
        lines.append(f"  Found: {', '.join(available_systems)}")

    return "\n".join(lines), has_issues


def format_json(
    velero_issues: list | None,
    velero_backups: list,
    snapshot_issues: list | None,
    snapshots: list,
    cronjob_issues: list | None,
    cronjobs: list,
    verbose: bool,
    warn_only: bool,
) -> tuple[str, bool]:
    """Format output as JSON and return (output, has_issues)."""
    all_issues = []
    if velero_issues:
        all_issues.extend(velero_issues)
    if snapshot_issues:
        all_issues.extend(snapshot_issues)
    if cronjob_issues:
        all_issues.extend(cronjob_issues)

    for item in velero_backups + snapshots + cronjobs:
        all_issues.extend(item.get("issues", []))

    has_issues = bool(all_issues)

    output = {
        "velero": {
            "available": velero_issues is not None,
            "issues": velero_issues or [],
            "backups": (
                velero_backups
                if verbose or not warn_only
                else [b for b in velero_backups if b.get("issues")]
            ),
        },
        "volumesnapshots": {
            "available": snapshot_issues is not None,
            "issues": snapshot_issues or [],
            "snapshots": (
                snapshots
                if verbose or not warn_only
                else [s for s in snapshots if s.get("issues")]
            ),
        },
        "cronjobs": {
            "available": cronjob_issues is not None,
            "issues": cronjob_issues or [],
            "cronjobs": (
                cronjobs
                if verbose or not warn_only
                else [c for c in cronjobs if c.get("issues")]
            ),
        },
        "summary": {
            "healthy": not has_issues,
            "total_issues": len(all_issues),
            "velero_backup_count": len(velero_backups),
            "snapshot_count": len(snapshots),
            "backup_cronjob_count": len(cronjobs),
        },
    }
    return json.dumps(output, indent=2), has_issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes backup health (Velero, VolumeSnapshots, CronJobs)"
    )
    parser.add_argument(
        "--namespace",
        "-n",
        help="Namespace to check (default: all namespaces)",
    )
    parser.add_argument(
        "--max-age",
        "-a",
        type=int,
        default=24,
        help="Maximum age in hours for backups before warning (default: 24)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show items with warnings or issues",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed information",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Check all backup systems
    velero_issues, velero_backups = check_velero_backups(
        context, opts.namespace, opts.max_age
    )
    snapshot_issues, snapshots = check_volume_snapshots(
        context, opts.namespace, opts.max_age
    )
    cronjob_issues, cronjobs = check_backup_cronjobs(
        context, opts.namespace, opts.max_age
    )

    # Format output
    if opts.format == "json":
        result, has_issues = format_json(
            velero_issues,
            velero_backups,
            snapshot_issues,
            snapshots,
            cronjob_issues,
            cronjobs,
            opts.verbose,
            opts.warn_only,
        )
    else:
        result, has_issues = format_plain(
            velero_issues,
            velero_backups,
            snapshot_issues,
            snapshots,
            cronjob_issues,
            cronjobs,
            opts.warn_only,
            opts.verbose,
        )

    print(result)

    output.set_summary(
        f"velero={len(velero_backups)}, snapshots={len(snapshots)}, cronjobs={len(cronjobs)}, healthy={not has_issues}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
