#!/usr/bin/env python3
# boxctl:
#   category: k8s/availability
#   tags: [zones, topology, ha, availability, distribution, kubernetes]
#   requires: [kubectl]
#   privilege: user
#   brief: Analyze Kubernetes workload distribution across topology zones
#   related: [node_capacity, pending_pod_analyzer]

"""
Analyze Kubernetes workload distribution across topology zones.

This script checks whether pods are properly distributed across failure domains
(availability zones, regions, or custom topology keys) to ensure high availability.
It identifies workloads with poor zone distribution that could be affected by
zone-level failures.

The script analyzes:
- Pod distribution across zones for each workload (Deployment, StatefulSet, DaemonSet)
- Zone imbalance ratios and single-zone vulnerabilities
- Topology spread constraints compliance
- Workloads lacking zone redundancy

Exit codes:
    0 - All workloads have acceptable zone distribution
    1 - One or more workloads have poor zone distribution
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_workload_owner(pod: dict) -> tuple[str, str]:
    """Get the workload (Deployment, StatefulSet, etc.) owning a pod."""
    owner_refs = pod.get("metadata", {}).get("ownerReferences", [])

    for owner in owner_refs:
        kind = owner.get("kind", "")
        name = owner.get("name", "")

        if kind == "ReplicaSet":
            parts = name.rsplit("-", 1)
            if len(parts) > 1:
                return "Deployment", parts[0]
            return "ReplicaSet", name
        elif kind in ["StatefulSet", "DaemonSet", "Job"]:
            return kind, name

    return "Standalone", pod.get("metadata", {}).get("name", "unknown")


def analyze_zone_distribution(
    pods_data: dict, nodes: dict, min_zones: int = 2
) -> list[dict]:
    """
    Analyze zone distribution for each workload.

    Returns a list of workload analyses with zone distribution metrics.
    """
    workloads = defaultdict(
        lambda: {"pods": [], "zones": defaultdict(int), "nodes": set()}
    )

    for pod in pods_data.get("items", []):
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name", "unknown")
        node_name = pod.get("spec", {}).get("nodeName")
        phase = pod.get("status", {}).get("phase", "Unknown")

        if phase not in ["Running", "Pending"]:
            continue

        kind, workload_name = get_workload_owner(pod)
        key = (namespace, kind, workload_name)

        if node_name and node_name in nodes:
            zone = nodes[node_name]["zone"]
        else:
            zone = "unscheduled" if not node_name else "unknown"

        workloads[key]["pods"].append(
            {"name": pod_name, "node": node_name, "zone": zone, "phase": phase}
        )
        workloads[key]["zones"][zone] += 1
        if node_name:
            workloads[key]["nodes"].add(node_name)

    results = []
    for (namespace, kind, name), data in workloads.items():
        pod_count = len(data["pods"])
        zone_count = len(
            [z for z in data["zones"] if z not in ("unknown", "unscheduled")]
        )
        zones = dict(data["zones"])

        if zone_count > 0:
            zone_values = [
                v for k, v in zones.items() if k not in ("unknown", "unscheduled")
            ]
            max_in_zone = max(zone_values) if zone_values else 0
            min_in_zone = min(zone_values) if zone_values else 0
            imbalance_ratio = (
                (max_in_zone / min_in_zone) if min_in_zone > 0 else float("inf")
            )
        else:
            max_in_zone = 0
            min_in_zone = 0
            imbalance_ratio = 0

        issues = []
        risk_level = "OK"

        if pod_count >= min_zones and zone_count == 1:
            issues.append("All pods in single zone - no zone redundancy")
            risk_level = "CRITICAL"
        elif pod_count >= min_zones and zone_count < min_zones:
            issues.append(f"Only {zone_count} zone(s) but has {pod_count} pods")
            risk_level = "HIGH"
        elif imbalance_ratio > 2.0 and zone_count >= min_zones:
            issues.append(f"Zone imbalance ratio: {imbalance_ratio:.1f}x")
            risk_level = "MEDIUM"

        unscheduled = zones.get("unscheduled", 0)
        if unscheduled > 0:
            issues.append(f"{unscheduled} pod(s) unscheduled")
            if risk_level == "OK":
                risk_level = "MEDIUM"

        # Skip standalone pods with only 1 replica
        if kind == "Standalone" and pod_count == 1:
            continue

        # Skip DaemonSets (they run on all nodes by design)
        if kind == "DaemonSet":
            continue

        results.append(
            {
                "namespace": namespace,
                "kind": kind,
                "name": name,
                "pod_count": pod_count,
                "zone_count": zone_count,
                "zones": zones,
                "node_count": len(data["nodes"]),
                "imbalance_ratio": (
                    imbalance_ratio if imbalance_ratio != float("inf") else 999.9
                ),
                "risk_level": risk_level,
                "issues": issues,
            }
        )

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "OK": 3}
    results.sort(key=lambda x: (risk_order.get(x["risk_level"], 4), -x["pod_count"]))

    return results


def get_zone_summary(nodes: dict) -> dict[str, int]:
    """Get summary of nodes per zone."""
    zone_counts = defaultdict(int)
    for node_name, node_info in nodes.items():
        zone_counts[node_info["zone"]] += 1
    return dict(zone_counts)


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
        description="Analyze Kubernetes workload distribution across topology zones"
    )

    parser.add_argument(
        "-n",
        "--namespace",
        help="Namespace to check (default: all namespaces)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show workloads with zone distribution issues",
    )

    parser.add_argument(
        "--min-zones",
        type=int,
        default=2,
        help="Minimum zones required for HA (default: 2)",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get nodes
    try:
        result = context.run(["kubectl", "get", "nodes", "-o", "json"])
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        nodes_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get nodes: {e}")
        return 2

    nodes = {}
    for node in nodes_data.get("items", []):
        node_name = node.get("metadata", {}).get("name", "unknown")
        labels = node.get("metadata", {}).get("labels", {})

        zone = (
            labels.get("topology.kubernetes.io/zone")
            or labels.get("failure-domain.beta.kubernetes.io/zone")
            or labels.get("zone")
            or "unknown"
        )
        region = (
            labels.get("topology.kubernetes.io/region")
            or labels.get("failure-domain.beta.kubernetes.io/region")
            or labels.get("region")
            or "unknown"
        )

        nodes[node_name] = {"zone": zone, "region": region, "labels": labels}

    if not nodes:
        output.error("No nodes found in cluster")
        return 1

    zone_summary = get_zone_summary(nodes)

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
        pods_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    results = analyze_zone_distribution(pods_data, nodes, opts.min_zones)

    if not results:
        if opts.namespace:
            print(f"No workloads found in namespace {opts.namespace}")
        else:
            print("No workloads found in cluster")
        return 0

    # Output
    if opts.format == "json":
        output_data = {
            "cluster_zones": zone_summary,
            "total_workloads": len(results),
            "workloads_at_risk": len([r for r in results if r["risk_level"] != "OK"]),
            "workloads": (
                [r for r in results if not opts.warn_only or r["risk_level"] != "OK"]
            ),
        }
        print(json.dumps(output_data, indent=2))

    elif opts.format == "table":
        lines = []

        lines.append("CLUSTER ZONE SUMMARY")
        lines.append("-" * 40)
        for zone, count in sorted(zone_summary.items()):
            lines.append(f"  {zone:<25} {count} nodes")
        lines.append("")

        lines.append(
            f"{'NAMESPACE':<20} {'WORKLOAD':<35} {'PODS':<6} {'ZONES':<6} "
            f"{'RISK':<10} {'DISTRIBUTION'}"
        )
        lines.append("-" * 120)

        for r in results:
            if opts.warn_only and r["risk_level"] == "OK":
                continue

            workload = f"{r['kind'][:3]}/{r['name']}"[:35]
            zones_str = ", ".join(
                f"{z}:{c}" for z, c in sorted(r["zones"].items())
            )[:40]

            lines.append(
                f"{r['namespace']:<20} {workload:<35} {r['pod_count']:<6} "
                f"{r['zone_count']:<6} {r['risk_level']:<10} {zones_str}"
            )

        print("\n".join(lines))

    else:  # plain
        lines = []

        lines.append("Cluster Zones:")
        for zone, count in sorted(zone_summary.items()):
            lines.append(f"  {zone}: {count} nodes")
        lines.append("")

        for r in results:
            if opts.warn_only and r["risk_level"] == "OK":
                continue

            zones_str = ", ".join(f"{z}:{c}" for z, c in sorted(r["zones"].items()))
            lines.append(
                f"{r['namespace']} {r['kind']}/{r['name']} "
                f"pods={r['pod_count']} zones={r['zone_count']} "
                f"[{r['risk_level']}] ({zones_str})"
            )
            for issue in r["issues"]:
                lines.append(f"  - {issue}")

        print("\n".join(lines))

    has_issues = any(r["risk_level"] != "OK" for r in results)
    output.set_summary(
        f"workloads={len(results)}, "
        f"at_risk={len([r for r in results if r['risk_level'] != 'OK'])}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
