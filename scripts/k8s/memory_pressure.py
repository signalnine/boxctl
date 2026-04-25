#!/usr/bin/env python3
# boxctl:
#   category: k8s/resources
#   tags: [memory, pressure, kubernetes, nodes, pods, resources]
#   requires: [kubectl]
#   brief: Analyze memory pressure on nodes and identify high-memory pods
#   privilege: user
#   related: [node_pressure, pod_resource_audit, node_capacity]

"""
Kubernetes memory pressure analyzer for nodes and pods.

This script detects memory pressure on nodes and identifies pods contributing
to memory contention in a Kubernetes cluster. Essential for baremetal and
large-scale environments where memory constraints can impact stability.

Features:
- Detect nodes with memory pressure conditions
- Identify pods with high memory usage relative to requests/limits
- Analyze memory fragmentation and allocatable vs used memory
- Support for filtering by namespace or node
- Sort pods by memory usage to identify top consumers
- Cluster-wide memory health summary

Exit codes:
    0 - No memory pressure detected / healthy memory state
    1 - Memory pressure detected on nodes or pods / evictions possible
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_memory_value(mem_str: str | None) -> int:
    """Convert memory string (e.g., '512Mi', '1Gi') to bytes."""
    if not mem_str:
        return 0

    mem_str = str(mem_str).strip()
    units = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
    }

    for unit, multiplier in units.items():
        if mem_str.endswith(unit):
            try:
                return int(float(mem_str[: -len(unit)]) * multiplier)
            except ValueError:
                return 0

    try:
        return int(mem_str)
    except ValueError:
        return 0


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable memory size."""
    for unit in ["B", "Ki", "Mi", "Gi", "Ti"]:
        if bytes_val < 1024:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f}Ti"


def check_node_memory_pressure(nodes_data: dict) -> tuple[list, dict]:
    """Check for memory pressure on nodes."""
    nodes_with_pressure = []
    nodes_summary = defaultdict(
        lambda: {
            "allocatable": 0,
            "used": 0,
            "requested": 0,
            "pressure": False,
            "conditions": {},
        }
    )

    if not nodes_data or "items" not in nodes_data:
        return nodes_with_pressure, nodes_summary

    for node in nodes_data["items"]:
        node_name = node["metadata"]["name"]

        # Get allocatable memory
        if "status" in node and "allocatable" in node["status"]:
            allocatable = parse_memory_value(node["status"]["allocatable"].get("memory", "0"))
            nodes_summary[node_name]["allocatable"] = allocatable

        # Check node conditions
        has_memory_pressure = False
        if "status" in node and "conditions" in node["status"]:
            for condition in node["status"]["conditions"]:
                cond_type = condition.get("type")
                cond_status = condition.get("status")
                nodes_summary[node_name]["conditions"][cond_type] = cond_status

                if cond_type == "MemoryPressure" and cond_status == "True":
                    has_memory_pressure = True
                    nodes_with_pressure.append(
                        {
                            "node": node_name,
                            "reason": condition.get("reason", "Unknown"),
                            "message": condition.get("message", ""),
                        }
                    )

        nodes_summary[node_name]["pressure"] = has_memory_pressure

    return nodes_with_pressure, dict(nodes_summary)


def check_pod_memory_usage(pods_data: dict) -> tuple[list, dict]:
    """Analyze pod memory usage and identify high consumers."""
    high_memory_pods = []
    memory_stats = {
        "total_requested": 0,
        "total_limits": 0,
        "pod_count": 0,
        "pods_without_limits": 0,
        "namespace_usage": defaultdict(lambda: {"requested": 0, "limits": 0, "count": 0}),
    }

    if not pods_data or "items" not in pods_data:
        return high_memory_pods, memory_stats

    pod_memory_list = []

    for pod in pods_data["items"]:
        namespace = pod["metadata"].get("namespace", "default")
        pod_name = pod["metadata"]["name"]
        memory_stats["pod_count"] += 1

        # Get memory requests and limits
        total_requested = 0
        total_limits = 0
        has_limits = False

        if "spec" in pod and "containers" in pod["spec"]:
            for container in pod["spec"]["containers"]:
                resources = container.get("resources", {})
                requests = resources.get("requests", {})
                limits = resources.get("limits", {})

                total_requested += parse_memory_value(requests.get("memory", "0"))
                total_limits += parse_memory_value(limits.get("memory", "0"))

                if limits.get("memory"):
                    has_limits = True

        if not has_limits:
            memory_stats["pods_without_limits"] += 1

        memory_stats["total_requested"] += total_requested
        memory_stats["total_limits"] += total_limits
        memory_stats["namespace_usage"][namespace]["requested"] += total_requested
        memory_stats["namespace_usage"][namespace]["limits"] += total_limits
        memory_stats["namespace_usage"][namespace]["count"] += 1

        pod_memory_list.append(
            {
                "namespace": namespace,
                "pod": pod_name,
                "requested": total_requested,
                "limits": total_limits,
            }
        )

    # Find high memory consumers
    # High = requesting >512Mi or any limits
    high_memory_pods = [p for p in pod_memory_list if p["limits"] > 0 or p["requested"] > 512 * 1024**2]

    # Sort by limits, then by requested
    high_memory_pods.sort(key=lambda x: (x["limits"] or x["requested"]), reverse=True)

    # Convert namespace_usage to regular dict
    memory_stats["namespace_usage"] = dict(memory_stats["namespace_usage"])

    return high_memory_pods, memory_stats


def format_node_summary(nodes_with_pressure: list, nodes_summary: dict) -> list[str]:
    """Format node memory pressure summary."""
    lines = []
    lines.append("\n=== Node Memory Status ===")
    lines.append(f"Total nodes checked: {len(nodes_summary)}")
    lines.append(f"Nodes with memory pressure: {len(nodes_with_pressure)}")

    if nodes_with_pressure:
        lines.append("\nNodes with MemoryPressure condition:")
        for item in nodes_with_pressure:
            lines.append(f"  - {item['node']}: {item['reason']}")
            if item["message"]:
                lines.append(f"    {item['message']}")

    # Show node with highest allocated memory
    if nodes_summary:
        lines.append("\nNode allocatable memory:")
        sorted_nodes = sorted(nodes_summary.items(), key=lambda x: x[1]["allocatable"], reverse=True)
        for node, info in sorted_nodes[:5]:
            allocatable = format_bytes(info["allocatable"])
            pressure_status = "PRESSURE" if info["pressure"] else "OK"
            lines.append(f"  - {node}: {allocatable} [{pressure_status}]")

    return lines


def format_pod_summary(high_memory_pods: list, memory_stats: dict) -> list[str]:
    """Format pod memory usage summary."""
    lines = []
    lines.append("\n=== Pod Memory Summary ===")
    lines.append(f"Total pods: {memory_stats['pod_count']}")
    lines.append(f"Pods without memory limits: {memory_stats['pods_without_limits']}")
    lines.append(f"Total memory requested: {format_bytes(memory_stats['total_requested'])}")
    lines.append(f"Total memory limits: {format_bytes(memory_stats['total_limits'])}")

    if high_memory_pods:
        lines.append("\nTop memory consumers (first 10):")
        for pod in high_memory_pods[:10]:
            requested = format_bytes(pod["requested"])
            limits = format_bytes(pod["limits"]) if pod["limits"] > 0 else "None"
            lines.append(f"  - {pod['namespace']}/{pod['pod']}: requested={requested}, limits={limits}")

    if memory_stats["namespace_usage"]:
        lines.append("\nMemory usage by namespace (top 5):")
        sorted_ns = sorted(
            memory_stats["namespace_usage"].items(),
            key=lambda x: x[1]["requested"],
            reverse=True,
        )
        for ns, info in sorted_ns[:5]:
            requested = format_bytes(info["requested"])
            limits = format_bytes(info["limits"]) if info["limits"] > 0 else "None"
            lines.append(f"  - {ns}: {info['count']} pods, requested={requested}, limits={limits}")

    return lines


def format_json_output(
    nodes_with_pressure: list,
    nodes_summary: dict,
    high_memory_pods: list,
    memory_stats: dict,
) -> str:
    """Format output as JSON."""
    output = {
        "nodes": {
            "total": len(nodes_summary),
            "with_pressure": len(nodes_with_pressure),
            "pressure_details": nodes_with_pressure,
            "summary": nodes_summary,
        },
        "pods": {
            "total": memory_stats["pod_count"],
            "without_limits": memory_stats["pods_without_limits"],
            "total_requested_bytes": memory_stats["total_requested"],
            "total_limits_bytes": memory_stats["total_limits"],
            "top_consumers": high_memory_pods[:20],
            "by_namespace": memory_stats["namespace_usage"],
        },
    }
    return json.dumps(output, indent=2)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = pressure/issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes memory pressure on nodes and pods"
    )

    parser.add_argument(
        "-n",
        "--namespace",
        help="Kubernetes namespace to analyze (default: all namespaces)",
    )

    parser.add_argument(
        "--nodes-only",
        action="store_true",
        help="Only show node memory pressure information",
    )

    parser.add_argument(
        "--pods-only",
        action="store_true",
        help="Only show pod memory usage information",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show issues (nodes with pressure, pods without limits)",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        output.render(opts.format)
        return 2

    exit_code = 0
    nodes_with_pressure = []
    nodes_summary = {}
    high_memory_pods = []
    memory_stats = {
        "pod_count": 0,
        "pods_without_limits": 0,
        "total_requested": 0,
        "total_limits": 0,
        "namespace_usage": {},
    }

    # Get nodes data
    if not opts.pods_only:
        try:
            result = context.run(["kubectl", "get", "nodes", "-o", "json"])
            if result.returncode != 0:
                output.error(f"kubectl failed: {result.stderr}")
                output.render(opts.format)
                return 2
            nodes_data = json.loads(result.stdout)
        except Exception as e:
            output.error(f"Failed to get nodes: {e}")
            output.render(opts.format)
            return 2

        nodes_with_pressure, nodes_summary = check_node_memory_pressure(nodes_data)
        if nodes_with_pressure:
            exit_code = 1

    # Get pods data
    if not opts.nodes_only:
        try:
            cmd = ["kubectl", "get", "pods", "-o", "json"]
            if opts.namespace:
                cmd.extend(["-n", opts.namespace])
            else:
                cmd.append("--all-namespaces")

            result = context.run(cmd)
            if result.returncode != 0:
                output.error(f"kubectl failed: {result.stderr}")
                output.render(opts.format)
                return 2
            pods_data = json.loads(result.stdout)
        except Exception as e:
            output.error(f"Failed to get pods: {e}")
            output.render(opts.format)
            return 2

        high_memory_pods, memory_stats = check_pod_memory_usage(pods_data)
        if memory_stats["pods_without_limits"] > 0:
            exit_code = 1

    # Format and print output
    if opts.format == "json":
        print(format_json_output(nodes_with_pressure, nodes_summary, high_memory_pods, memory_stats))
    else:
        lines = []
        if not opts.pods_only:
            lines.extend(format_node_summary(nodes_with_pressure, nodes_summary))
        if not opts.nodes_only:
            lines.extend(format_pod_summary(high_memory_pods, memory_stats))
        print("\n".join(lines))

    # Set summary
    pressure_count = len(nodes_with_pressure)
    no_limits = memory_stats["pods_without_limits"]
    output.set_summary(f"nodes_with_pressure={pressure_count}, pods_without_limits={no_limits}")

    return exit_code


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
