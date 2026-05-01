#!/usr/bin/env python3
# boxctl:
#   category: k8s/troubleshooting
#   tags: [finalizer, kubernetes, troubleshooting, deletion, stuck]
#   requires: [kubectl]
#   brief: Find resources stuck due to finalizers
#   privilege: user
#   related: [namespace_resource_analyzer, restart_monitor]

"""
Kubernetes finalizer analyzer - Find resources stuck due to finalizers.

Identifies resources in Terminating state that cannot be deleted because
finalizers are blocking deletion. Common in large-scale environments where
namespace deletions hang, or custom controllers fail to clean up properly.

Exit codes:
    0 - No stuck resources found
    1 - Stuck resources detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def calculate_age(timestamp_str: str | None) -> str:
    """Calculate age from ISO timestamp string."""
    if not timestamp_str:
        return "Unknown"

    try:
        # Parse ISO format timestamp
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        deletion_time = datetime.fromisoformat(timestamp_str)
        now = datetime.now(timezone.utc)
        delta = now - deletion_time

        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)

        if days > 0:
            return f"{days}d{hours}h"
        elif hours > 0:
            return f"{hours}h{minutes}m"
        else:
            return f"{minutes}m"
    except (ValueError, TypeError):
        return "Unknown"


def get_terminating_namespaces(context: Context) -> list:
    """Get namespaces stuck in Terminating state."""
    result = context.run(["kubectl", "get", "namespaces", "-o", "json"])
    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    terminating = []
    for ns in data.get("items", []):
        metadata = ns.get("metadata", {})
        status = ns.get("status", {})
        phase = status.get("phase", "")

        if phase == "Terminating":
            deletion_timestamp = metadata.get("deletionTimestamp")
            finalizers = metadata.get("finalizers", [])

            terminating.append(
                {
                    "name": metadata.get("name"),
                    "finalizers": finalizers,
                    "deletion_timestamp": deletion_timestamp,
                    "conditions": status.get("conditions", []),
                    "age_since_deletion": calculate_age(deletion_timestamp),
                }
            )

    return terminating


def get_resources_with_finalizers(
    context: Context, namespace: str | None = None, resource_type: str = "all"
) -> list:
    """Get resources with finalizers that are in Terminating state."""
    # Resource types to check
    if resource_type == "all":
        resource_types = [
            "pods",
            "services",
            "deployments",
            "statefulsets",
            "daemonsets",
            "replicasets",
            "jobs",
            "cronjobs",
            "configmaps",
            "secrets",
            "persistentvolumeclaims",
            "serviceaccounts",
            "roles",
            "rolebindings",
            "networkpolicies",
            "ingresses",
        ]
    else:
        resource_types = [resource_type]

    stuck_resources = []

    for res_type in resource_types:
        cmd = ["kubectl", "get", res_type, "-o", "json"]
        if namespace:
            cmd.extend(["-n", namespace])
        else:
            cmd.append("--all-namespaces")

        result = context.run(cmd)
        if result.returncode != 0:
            continue

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            continue

        for item in data.get("items", []):
            metadata = item.get("metadata", {})
            deletion_timestamp = metadata.get("deletionTimestamp")
            finalizers = metadata.get("finalizers", [])

            # Resource is terminating if it has a deletionTimestamp
            if deletion_timestamp and finalizers:
                stuck_resources.append(
                    {
                        "kind": item.get("kind", res_type),
                        "name": metadata.get("name"),
                        "namespace": metadata.get("namespace", ""),
                        "finalizers": finalizers,
                        "deletion_timestamp": deletion_timestamp,
                        "age_since_deletion": calculate_age(deletion_timestamp),
                    }
                )

    return stuck_resources


def get_terminating_pvs(context: Context) -> list:
    """Get PersistentVolumes stuck in Terminating state."""
    result = context.run(["kubectl", "get", "pv", "-o", "json"])
    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    stuck = []
    for pv in data.get("items", []):
        metadata = pv.get("metadata", {})
        deletion_timestamp = metadata.get("deletionTimestamp")
        finalizers = metadata.get("finalizers", [])

        if deletion_timestamp and finalizers:
            stuck.append(
                {
                    "kind": "PersistentVolume",
                    "name": metadata.get("name"),
                    "namespace": "",
                    "finalizers": finalizers,
                    "deletion_timestamp": deletion_timestamp,
                    "age_since_deletion": calculate_age(deletion_timestamp),
                    "status": pv.get("status", {}).get("phase", "Unknown"),
                }
            )

    return stuck


def is_stuck_long(item: dict) -> bool:
    """Check if item has been stuck for more than 5 minutes."""
    age = item.get("age_since_deletion", "")
    if "d" in age or "h" in age:
        return True
    if "m" in age:
        try:
            minutes = int(age.replace("m", ""))
            return minutes >= 5
        except ValueError:
            return True
    return True


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no stuck resources, 1 = stuck resources found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Find Kubernetes resources stuck due to finalizers"
    )
    parser.add_argument(
        "-n",
        "--namespace",
        help="Check specific namespace only",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--namespaces-only",
        action="store_true",
        help="Only check for terminating namespaces",
    )
    parser.add_argument(
        "--resource-type",
        default="all",
        help="Specific resource type to check (default: all)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information including conditions",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show resources stuck for more than 5 minutes",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Gather data
    terminating_namespaces = []
    stuck_resources = []
    stuck_pvs = []

    # Always check namespaces unless checking specific namespace
    if not opts.namespace:
        terminating_namespaces = get_terminating_namespaces(context)

    # Check resources unless namespaces-only
    if not opts.namespaces_only:
        stuck_resources = get_resources_with_finalizers(
            context, namespace=opts.namespace, resource_type=opts.resource_type
        )

        # Check cluster-scoped PVs
        if not opts.namespace:
            stuck_pvs = get_terminating_pvs(context)

    # Filter if warn-only (stuck for > 5 minutes)
    if opts.warn_only:
        stuck_resources = [r for r in stuck_resources if is_stuck_long(r)]
        stuck_pvs = [p for p in stuck_pvs if is_stuck_long(p)]

    has_issues = bool(terminating_namespaces or stuck_resources or stuck_pvs)

    if opts.format == "json":
        result_data = {
            "terminating_namespaces": terminating_namespaces,
            "stuck_resources": stuck_resources,
            "stuck_persistent_volumes": stuck_pvs,
            "summary": {
                "total_terminating_namespaces": len(terminating_namespaces),
                "total_stuck_resources": len(stuck_resources),
                "total_stuck_pvs": len(stuck_pvs),
            },
        }
        print(json.dumps(result_data, indent=2))

    elif opts.format == "table":
        if terminating_namespaces or stuck_resources or stuck_pvs:
            print(
                f"{'TYPE':<25} {'NAMESPACE':<20} {'NAME':<40} {'AGE':<10} {'FINALIZERS':<30}"
            )
            print("-" * 125)

            for ns in terminating_namespaces:
                finalizers_str = ", ".join(ns["finalizers"][:2])
                if len(ns["finalizers"]) > 2:
                    finalizers_str += f" (+{len(ns['finalizers'])-2} more)"
                age = ns.get("age_since_deletion", "Unknown")
                print(
                    f"{'Namespace':<25} {'-':<20} {ns['name']:<40} {age:<10} {finalizers_str:<30}"
                )

            for res in stuck_resources:
                finalizers_str = ", ".join(res["finalizers"][:2])
                if len(res["finalizers"]) > 2:
                    finalizers_str += f" (+{len(res['finalizers'])-2} more)"
                ns = res["namespace"] or "-"
                print(
                    f"{res['kind']:<25} {ns:<20} {res['name']:<40} {res['age_since_deletion']:<10} {finalizers_str:<30}"
                )

            for pv in stuck_pvs:
                finalizers_str = ", ".join(pv["finalizers"][:2])
                if len(pv["finalizers"]) > 2:
                    finalizers_str += f" (+{len(pv['finalizers'])-2} more)"
                print(
                    f"{'PersistentVolume':<25} {'-':<20} {pv['name']:<40} {pv['age_since_deletion']:<10} {finalizers_str:<30}"
                )
        else:
            print("No resources stuck due to finalizers.")

    else:  # plain
        lines = []

        if terminating_namespaces:
            lines.append("=== Terminating Namespaces ===")
            for ns in terminating_namespaces:
                lines.append(f"\nNamespace: {ns['name']}")
                lines.append(f"  Deletion requested: {ns['deletion_timestamp']}")
                lines.append(f"  Age: {ns['age_since_deletion']}")
                lines.append("  Finalizers blocking deletion:")
                for f in ns["finalizers"]:
                    lines.append(f"    - {f}")

                if opts.verbose and ns["conditions"]:
                    lines.append("  Conditions:")
                    for cond in ns["conditions"]:
                        lines.append(
                            f"    - {cond.get('type')}: {cond.get('message', 'N/A')}"
                        )
            lines.append("")

        if stuck_resources:
            lines.append("=== Resources Stuck in Terminating State ===")

            # Group by namespace
            by_namespace = {}
            for res in stuck_resources:
                ns = res["namespace"] or "(cluster-scoped)"
                if ns not in by_namespace:
                    by_namespace[ns] = []
                by_namespace[ns].append(res)

            for ns, items in sorted(by_namespace.items()):
                lines.append(f"\nNamespace: {ns}")
                for item in items:
                    lines.append(
                        f"  {item['kind']}/{item['name']} (stuck for {item['age_since_deletion']})"
                    )
                    lines.append("    Finalizers:")
                    for f in item["finalizers"]:
                        lines.append(f"      - {f}")
            lines.append("")

        if stuck_pvs:
            lines.append("=== PersistentVolumes Stuck in Terminating State ===")
            for pv in stuck_pvs:
                lines.append(
                    f"\n  {pv['name']} (stuck for {pv['age_since_deletion']})"
                )
                lines.append(f"    Status: {pv.get('status', 'Unknown')}")
                lines.append("    Finalizers:")
                for f in pv["finalizers"]:
                    lines.append(f"      - {f}")
            lines.append("")

        if not has_issues:
            lines.append("No resources stuck due to finalizers.")

        print("\n".join(lines))

    output.set_summary(
        f"namespaces={len(terminating_namespaces)}, "
        f"resources={len(stuck_resources)}, "
        f"pvs={len(stuck_pvs)}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
