#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [age, stale, restarts, freshness, compliance, kubernetes]
#   requires: [kubectl]
#   privilege: user
#   brief: Analyze workload restart age across Kubernetes clusters
#   related: [container_restart_analyzer, workload_ownership]

"""
Analyze workload restart age across Kubernetes clusters.

Identifies pods based on how long they've been running without restart, helping
detect both stability issues (frequent restarts) and stale deployments (pods
running for extended periods without updates).

Use cases:
- Identify stale workloads that haven't been updated/redeployed
- Detect stability patterns across namespaces
- Find pods that survived multiple deployments (stuck/orphaned)
- Audit deployment freshness for security compliance
- Capacity planning based on workload age distribution

Exit codes:
    0 - All workloads within acceptable age bounds
    1 - Workloads found outside age thresholds (too old)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_k8s_timestamp(timestamp_str: str | None) -> datetime | None:
    """Parse Kubernetes timestamp to datetime object."""
    if not timestamp_str:
        return None
    try:
        if "." in timestamp_str:
            return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=timezone.utc
            )
        return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 0:
        return "unknown"

    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)

    if days > 0:
        return f"{days}d{hours}h"
    elif hours > 0:
        return f"{hours}h{minutes}m"
    else:
        return f"{minutes}m"


def analyze_pod_age(pod: dict, now: datetime) -> dict:
    """
    Analyze a pod's age and restart patterns.

    Returns dict with:
    - name: pod name
    - namespace: pod namespace
    - age_seconds: time since pod creation
    - last_restart_seconds: time since last container restart (if any)
    - restart_count: total restart count across containers
    - owner_kind: deployment, statefulset, daemonset, etc.
    - status: Running, Pending, etc.
    """
    metadata = pod.get("metadata", {})
    spec = pod.get("spec", {})
    status = pod.get("status", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    creation_time = parse_k8s_timestamp(metadata.get("creationTimestamp"))
    age_seconds = (now - creation_time).total_seconds() if creation_time else -1

    container_statuses = status.get("containerStatuses", [])
    total_restarts = 0
    last_restart_time = None

    for cs in container_statuses:
        total_restarts += cs.get("restartCount", 0)

        last_state = cs.get("lastState", {})
        if "terminated" in last_state:
            finished = parse_k8s_timestamp(last_state["terminated"].get("finishedAt"))
            if finished and (not last_restart_time or finished > last_restart_time):
                last_restart_time = finished

    last_restart_seconds = -1
    if last_restart_time:
        last_restart_seconds = (now - last_restart_time).total_seconds()

    owner_refs = metadata.get("ownerReferences", [])
    owner_kind = owner_refs[0].get("kind", "None") if owner_refs else "None"

    phase = status.get("phase", "Unknown")

    return {
        "name": name,
        "namespace": namespace,
        "age_seconds": age_seconds,
        "age_human": format_duration(age_seconds),
        "last_restart_seconds": last_restart_seconds,
        "last_restart_human": (
            format_duration(last_restart_seconds) if last_restart_seconds >= 0 else "never"
        ),
        "restart_count": total_restarts,
        "owner_kind": owner_kind,
        "phase": phase,
        "creation_time": metadata.get("creationTimestamp", "unknown"),
    }


def categorize_by_age(
    pods_analysis: list[dict], stale_days: int = 30, fresh_hours: int = 1
) -> dict[str, list]:
    """
    Categorize pods by age.

    Returns dict with:
    - stale: pods older than stale_days
    - normal: pods in healthy age range
    - fresh: pods younger than fresh_hours (recently deployed/restarted)
    """
    stale_seconds = stale_days * 86400
    fresh_seconds = fresh_hours * 3600

    categories = {"stale": [], "normal": [], "fresh": []}

    for pod in pods_analysis:
        age = pod["age_seconds"]
        if age < 0:
            continue

        if age > stale_seconds:
            categories["stale"].append(pod)
        elif age < fresh_seconds:
            categories["fresh"].append(pod)
        else:
            categories["normal"].append(pod)

    return categories


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all OK, 1 = stale workloads found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze workload restart age in Kubernetes clusters"
    )

    parser.add_argument(
        "-n",
        "--namespace",
        help="Kubernetes namespace to analyze (default: all namespaces)",
    )

    parser.add_argument(
        "--stale-days",
        type=int,
        default=30,
        help="Days after which a workload is considered stale (default: 30)",
    )

    parser.add_argument(
        "--fresh-hours",
        type=int,
        default=1,
        help="Hours within which a workload is considered fresh (default: 1)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show stale workloads",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information for all workloads",
    )

    parser.add_argument(
        "--exclude-namespace",
        action="append",
        default=[],
        help="Namespaces to exclude (can be specified multiple times)",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get current time
    now = datetime.now(timezone.utc)

    # Get pods
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if opts.namespace:
        cmd.extend(["-n", opts.namespace])
    else:
        cmd.append("--all-namespaces")

    try:
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods = json.loads(result.stdout).get("items", [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not pods:
        if opts.format == "json":
            print(
                json.dumps({"summary": {"total": 0}, "categories": {}, "all_pods": []})
            )
        else:
            print("No pods found")
        return 0

    # Analyze each pod
    pods_analysis = []
    for pod in pods:
        analysis = analyze_pod_age(pod, now)

        if analysis["namespace"] in opts.exclude_namespace:
            continue

        if analysis["phase"] not in ["Running", "Succeeded"]:
            continue

        pods_analysis.append(analysis)

    if not pods_analysis:
        if opts.format == "json":
            print(
                json.dumps({"summary": {"total": 0}, "categories": {}, "all_pods": []})
            )
        else:
            print("No running pods found")
        return 0

    # Categorize by age
    categories = categorize_by_age(
        pods_analysis, stale_days=opts.stale_days, fresh_hours=opts.fresh_hours
    )

    # Output results
    if opts.format == "json":
        result_data = {
            "summary": {
                "total": len(pods_analysis),
                "stale": len(categories["stale"]),
                "normal": len(categories["normal"]),
                "fresh": len(categories["fresh"]),
            },
            "categories": {
                "stale": categories["stale"],
                "normal": categories["normal"],
                "fresh": categories["fresh"],
            },
            "all_pods": pods_analysis,
        }
        print(json.dumps(result_data, indent=2, default=str))

    elif opts.format == "table":
        if opts.warn_only:
            pods_to_show = categories["stale"]
        else:
            pods_to_show = sorted(pods_analysis, key=lambda x: -x["age_seconds"])

        print(
            f"{'NAMESPACE':<20} {'POD':<40} {'AGE':<10} {'RESTARTS':<10} "
            f"{'OWNER':<15} {'STATUS':<10}"
        )
        print("-" * 115)

        for pod in pods_to_show:
            if pod in categories["stale"]:
                status = "STALE"
            elif pod in categories["fresh"]:
                status = "FRESH"
            else:
                status = "OK"

            name = (
                pod["name"][:38] + ".." if len(pod["name"]) > 40 else pod["name"]
            )
            ns = (
                pod["namespace"][:18] + ".."
                if len(pod["namespace"]) > 20
                else pod["namespace"]
            )
            print(
                f"{ns:<20} {name:<40} {pod['age_human']:<10} "
                f"{pod['restart_count']:<10} {pod['owner_kind']:<15} {status:<10}"
            )

        print()
        print(
            f"Total: {len(pods_analysis)} | Stale: {len(categories['stale'])} | "
            f"Fresh: {len(categories['fresh'])}"
        )

    else:  # plain
        total = len(pods_analysis)
        stale_count = len(categories["stale"])
        fresh_count = len(categories["fresh"])
        normal_count = len(categories["normal"])

        if not opts.warn_only:
            print("Workload Restart Age Analysis")
            print(f"Total pods analyzed: {total}")
            print(f"  Stale (old): {stale_count}")
            print(f"  Normal: {normal_count}")
            print(f"  Fresh (recent): {fresh_count}")
            print()

        if categories["stale"]:
            print(f"Stale Workloads ({stale_count}):")
            print("-" * 80)
            for pod in sorted(categories["stale"], key=lambda x: -x["age_seconds"]):
                restarts = (
                    f"restarts={pod['restart_count']}"
                    if pod["restart_count"] > 0
                    else "no restarts"
                )
                print(f"  {pod['namespace']}/{pod['name']}")
                print(
                    f"    Age: {pod['age_human']}, Owner: {pod['owner_kind']}, "
                    f"{restarts}"
                )
            print()

        if categories["fresh"] and opts.verbose:
            print(f"Fresh Workloads ({fresh_count}):")
            print("-" * 80)
            for pod in sorted(categories["fresh"], key=lambda x: x["age_seconds"]):
                restarts = (
                    f"restarts={pod['restart_count']}"
                    if pod["restart_count"] > 0
                    else "no restarts"
                )
                print(f"  {pod['namespace']}/{pod['name']}")
                print(
                    f"    Age: {pod['age_human']}, Owner: {pod['owner_kind']}, "
                    f"{restarts}"
                )
            print()

        if opts.verbose and not opts.warn_only:
            print("All Workloads by Age:")
            print("-" * 80)
            for pod in sorted(pods_analysis, key=lambda x: -x["age_seconds"]):
                status_marker = ""
                if pod in categories["stale"]:
                    status_marker = "[STALE] "
                elif pod in categories["fresh"]:
                    status_marker = "[FRESH] "
                print(
                    f"  {status_marker}{pod['namespace']}/{pod['name']}: "
                    f"{pod['age_human']}"
                )

        if not categories["stale"] and opts.warn_only:
            print("All workloads within acceptable age bounds")

    has_stale = len(categories["stale"]) > 0
    output.set_summary(
        f"pods={len(pods_analysis)}, stale={len(categories['stale'])}, "
        f"fresh={len(categories['fresh'])}"
    )

    return 1 if has_stale else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
