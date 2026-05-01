#!/usr/bin/env python3
# boxctl:
#   category: k8s/network
#   tags: [cni, kubernetes, network, calico, cilium, flannel]
#   requires: [kubectl]
#   privilege: user
#   brief: Monitor Kubernetes CNI (Container Network Interface) health
#   related: [node_health, cni_health]

"""
Kubernetes CNI Health Monitor - Monitor Container Network Interface health.

Monitors the health of Container Network Interface (CNI) components:
- CNI plugin pods (Calico, Cilium, Flannel, Weave, etc.)
- IPAM allocation status and IP exhaustion risks
- Node network readiness conditions
- Pod networking issues (pending pods with network errors)
- CNI configuration presence on nodes

Exit codes:
    0 - All CNI components healthy
    1 - CNI issues detected (warnings or errors)
    2 - Usage error or missing dependencies
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# Common CNI plugin identifiers
CNI_PLUGINS = {
    "calico": {
        "labels": ["k8s-app=calico-node", "k8s-app=calico-kube-controllers"],
        "daemonset": "calico-node",
        "namespace": "kube-system",
    },
    "cilium": {
        "labels": ["k8s-app=cilium", "app.kubernetes.io/name=cilium-agent"],
        "daemonset": "cilium",
        "namespace": "kube-system",
    },
    "flannel": {
        "labels": ["app=flannel", "k8s-app=flannel"],
        "daemonset": "kube-flannel-ds",
        "namespace": "kube-flannel",
    },
    "weave": {
        "labels": ["name=weave-net"],
        "daemonset": "weave-net",
        "namespace": "kube-system",
    },
    "aws-vpc-cni": {
        "labels": ["k8s-app=aws-node"],
        "daemonset": "aws-node",
        "namespace": "kube-system",
    },
    "azure-cni": {
        "labels": ["k8s-app=azure-cni"],
        "daemonset": "azure-cni",
        "namespace": "kube-system",
    },
}


def detect_cni_plugin(context: Context) -> list:
    """Detect which CNI plugin is installed in the cluster."""
    detected = []

    for plugin_name, plugin_info in CNI_PLUGINS.items():
        namespace = plugin_info["namespace"]
        for label in plugin_info["labels"]:
            result = context.run(
                [
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    namespace,
                    "-l",
                    label,
                    "-o",
                    "json",
                    "--ignore-not-found",
                ]
            )
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    if data.get("items"):
                        detected.append(
                            {
                                "name": plugin_name,
                                "namespace": namespace,
                                "label": label,
                                "pod_count": len(data["items"]),
                            }
                        )
                        break
                except json.JSONDecodeError:
                    continue

    return detected


def get_cni_daemonset_status(
    context: Context, plugin_name: str, namespace: str = "kube-system"
) -> dict | None:
    """Get DaemonSet status for CNI plugin."""
    plugin_info = CNI_PLUGINS.get(plugin_name, {})
    ds_name = plugin_info.get("daemonset", plugin_name)

    result = context.run(
        ["kubectl", "get", "daemonset", ds_name, "-n", namespace, "-o", "json"]
    )

    if result.returncode != 0:
        return None

    try:
        data = json.loads(result.stdout)
        status = data.get("status", {})
        return {
            "name": ds_name,
            "desired": status.get("desiredNumberScheduled", 0),
            "current": status.get("currentNumberScheduled", 0),
            "ready": status.get("numberReady", 0),
            "available": status.get("numberAvailable", 0),
            "unavailable": status.get("numberUnavailable", 0),
            "misscheduled": status.get("numberMisscheduled", 0),
        }
    except json.JSONDecodeError:
        return None


def get_cni_pods(
    context: Context, plugin_name: str, namespace: str = "kube-system"
) -> list:
    """Get CNI plugin pods and their status."""
    plugin_info = CNI_PLUGINS.get(plugin_name, {})
    if not plugin_info:
        return []

    pods = []
    for label in plugin_info["labels"]:
        result = context.run(
            ["kubectl", "get", "pods", "-n", namespace, "-l", label, "-o", "json"]
        )
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                if data.get("items"):
                    pods.extend(data["items"])
                    break
            except json.JSONDecodeError:
                continue

    return pods


def get_node_network_conditions(context: Context) -> list:
    """Get network-related conditions from all nodes."""
    result = context.run(["kubectl", "get", "nodes", "-o", "json"])
    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    nodes = []
    for node in data.get("items", []):
        node_name = node.get("metadata", {}).get("name", "unknown")
        conditions = node.get("status", {}).get("conditions", [])

        network_conditions = {}
        for cond in conditions:
            cond_type = cond.get("type", "")
            # Look for network-related conditions
            if cond_type in ["NetworkUnavailable", "Ready"]:
                network_conditions[cond_type] = {
                    "status": cond.get("status"),
                    "reason": cond.get("reason", ""),
                    "message": cond.get("message", ""),
                }

        # Check pod CIDR allocation
        pod_cidr = node.get("spec", {}).get("podCIDR", "")
        pod_cidrs = node.get("spec", {}).get("podCIDRs", [])

        nodes.append(
            {
                "name": node_name,
                "conditions": network_conditions,
                "pod_cidr": pod_cidr,
                "pod_cidrs": pod_cidrs,
            }
        )

    return nodes


def get_pods_with_network_issues(context: Context) -> list:
    """Find pods that are failing due to network issues."""
    result = context.run(["kubectl", "get", "pods", "--all-namespaces", "-o", "json"])
    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    network_issues = []
    network_error_keywords = [
        "network",
        "cni",
        "ip address",
        "ipam",
        "sandbox",
        "networkplugin",
        "failed to set up",
        "failed to allocate",
    ]

    for pod in data.get("items", []):
        metadata = pod.get("metadata", {})
        status = pod.get("status", {})
        phase = status.get("phase", "")

        # Skip running pods
        if phase == "Running":
            continue

        # Check for network-related issues in container statuses
        container_statuses = status.get("containerStatuses", [])
        init_container_statuses = status.get("initContainerStatuses", [])

        for container in container_statuses + init_container_statuses:
            waiting = container.get("waiting", {})
            reason = waiting.get("reason", "").lower()
            message = waiting.get("message", "").lower()

            for keyword in network_error_keywords:
                if keyword in reason or keyword in message:
                    network_issues.append(
                        {
                            "namespace": metadata.get("namespace", ""),
                            "name": metadata.get("name", ""),
                            "reason": waiting.get("reason", ""),
                            "message": waiting.get("message", "")[:200],
                        }
                    )
                    break

        # Check pod conditions for network issues
        conditions = status.get("conditions", [])
        for cond in conditions:
            if cond.get("status") == "False":
                message = cond.get("message", "").lower()
                for keyword in network_error_keywords:
                    if keyword in message:
                        network_issues.append(
                            {
                                "namespace": metadata.get("namespace", ""),
                                "name": metadata.get("name", ""),
                                "reason": cond.get("reason", ""),
                                "message": cond.get("message", "")[:200],
                            }
                        )
                        break

    # Deduplicate
    seen = set()
    unique_issues = []
    for issue in network_issues:
        key = (issue["namespace"], issue["name"])
        if key not in seen:
            seen.add(key)
            unique_issues.append(issue)

    return unique_issues


def analyze_cni_health(
    detected_plugins: list,
    daemonset_status: dict | None,
    pods: list,
    nodes: list,
    network_issues: list,
) -> tuple[list, list]:
    """Analyze CNI health and return issues and warnings."""
    issues = []
    warnings = []

    # Check if any CNI plugin is detected
    if not detected_plugins:
        issues.append("No recognized CNI plugin detected in the cluster")
        return issues, warnings

    # Check DaemonSet status
    if daemonset_status:
        ds = daemonset_status
        if ds["unavailable"] and ds["unavailable"] > 0:
            issues.append(
                f"CNI DaemonSet '{ds['name']}' has {ds['unavailable']} unavailable pods"
            )
        if ds["ready"] < ds["desired"]:
            warnings.append(
                f"CNI DaemonSet '{ds['name']}' has {ds['ready']}/{ds['desired']} ready pods"
            )
        if ds["misscheduled"] > 0:
            warnings.append(
                f"CNI DaemonSet '{ds['name']}' has {ds['misscheduled']} misscheduled pods"
            )

    # Check individual CNI pods
    if pods:
        not_ready_pods = []
        high_restart_pods = []

        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            status = pod.get("status", {})
            phase = status.get("phase", "Unknown")

            if phase != "Running":
                not_ready_pods.append(f"{pod_name} ({phase})")
                continue

            container_statuses = status.get("containerStatuses", [])
            for container in container_statuses:
                if not container.get("ready", False):
                    not_ready_pods.append(f"{pod_name}/{container.get('name')}")

                restart_count = container.get("restartCount", 0)
                if restart_count > 10:
                    high_restart_pods.append(f"{pod_name} ({restart_count} restarts)")

        if not_ready_pods:
            issues.append(f"CNI pods not ready: {', '.join(not_ready_pods[:5])}")
            if len(not_ready_pods) > 5:
                issues[-1] += f" (and {len(not_ready_pods) - 5} more)"

        if high_restart_pods:
            warnings.append(
                f"CNI pods with high restarts: {', '.join(high_restart_pods[:3])}"
            )

    # Check node network conditions
    nodes_with_network_issues = []
    nodes_without_cidr = []

    for node in nodes:
        node_name = node["name"]
        conditions = node.get("conditions", {})

        # Check NetworkUnavailable condition
        network_unavail = conditions.get("NetworkUnavailable", {})
        if network_unavail.get("status") == "True":
            nodes_with_network_issues.append(node_name)

        # Check if node has pod CIDR assigned
        if not node.get("pod_cidr") and not node.get("pod_cidrs"):
            nodes_without_cidr.append(node_name)

    if nodes_with_network_issues:
        issues.append(
            f"Nodes with NetworkUnavailable condition: {', '.join(nodes_with_network_issues[:5])}"
        )
        if len(nodes_with_network_issues) > 5:
            issues[-1] += f" (and {len(nodes_with_network_issues) - 5} more)"

    if nodes_without_cidr:
        warnings.append(f"Nodes without pod CIDR: {', '.join(nodes_without_cidr[:5])}")

    # Check pods with network issues
    if network_issues:
        issue_count = len(network_issues)
        sample = network_issues[:3]
        sample_names = [f"{p['namespace']}/{p['name']}" for p in sample]
        warnings.append(
            f"{issue_count} pod(s) with network issues: {', '.join(sample_names)}"
        )
        if issue_count > 3:
            warnings[-1] += f" (and {issue_count - 3} more)"

    return issues, warnings


def format_plain(
    detected_plugins: list,
    daemonset_status: dict | None,
    pods: list,
    nodes: list,
    network_issues: list,
    issues: list,
    warnings: list,
    verbose: bool = False,
) -> str:
    """Format output in plain text."""
    lines = []
    lines.append("Kubernetes CNI Health Monitor")
    lines.append("=" * 50)
    lines.append("")

    # Detected CNI
    lines.append("Detected CNI Plugin(s):")
    if detected_plugins:
        for plugin in detected_plugins:
            lines.append(
                f"  - {plugin['name']} ({plugin['pod_count']} pods in {plugin['namespace']})"
            )
    else:
        lines.append("  No recognized CNI plugin detected")
    lines.append("")

    # DaemonSet status
    if daemonset_status:
        ds = daemonset_status
        lines.append("CNI DaemonSet Status:")
        lines.append(f"  Name: {ds['name']}")
        lines.append(f"  Desired: {ds['desired']}")
        lines.append(f"  Ready: {ds['ready']}")
        lines.append(f"  Available: {ds['available']}")
        if ds["unavailable"]:
            lines.append(f"  Unavailable: {ds['unavailable']}")
        lines.append("")

    # Node network status
    if verbose and nodes:
        lines.append("Node Network Status:")
        for node in nodes[:10]:
            cidr = node.get("pod_cidr", "none")
            network_cond = node["conditions"].get("NetworkUnavailable", {})
            network_status = network_cond.get("status", "Unknown")
            symbol = "OK" if network_status == "False" else "ISSUE"
            lines.append(f"  {node['name']}: {symbol}, CIDR: {cidr}")
        if len(nodes) > 10:
            lines.append(f"  ... and {len(nodes) - 10} more nodes")
        lines.append("")

    # Pods with network issues
    if network_issues:
        lines.append("Pods with Network Issues:")
        for pod in network_issues[:5]:
            lines.append(f"  {pod['namespace']}/{pod['name']}: {pod['reason']}")
            if verbose:
                lines.append(f"    {pod['message'][:100]}")
        if len(network_issues) > 5:
            lines.append(f"  ... and {len(network_issues) - 5} more")
        lines.append("")

    # Issues and warnings
    if issues:
        lines.append("ISSUES:")
        for issue in issues:
            lines.append(f"  X {issue}")
        lines.append("")

    if warnings:
        lines.append("WARNINGS:")
        for warning in warnings:
            lines.append(f"  ! {warning}")
        lines.append("")

    if not issues and not warnings:
        lines.append("OK All CNI health checks passed")

    return "\n".join(lines)


def format_json(
    detected_plugins: list,
    daemonset_status: dict | None,
    pods: list,
    nodes: list,
    network_issues: list,
    issues: list,
    warnings: list,
) -> str:
    """Format output as JSON."""
    pod_summary = []
    if pods:
        for pod in pods:
            container_statuses = pod.get("status", {}).get("containerStatuses", [])
            pod_summary.append(
                {
                    "name": pod.get("metadata", {}).get("name"),
                    "namespace": pod.get("metadata", {}).get("namespace"),
                    "phase": pod.get("status", {}).get("phase"),
                    "ready": all(c.get("ready", False) for c in container_statuses),
                    "restarts": sum(
                        c.get("restartCount", 0) for c in container_statuses
                    ),
                }
            )

    node_summary = []
    for node in nodes:
        network_cond = node["conditions"].get("NetworkUnavailable", {})
        node_summary.append(
            {
                "name": node["name"],
                "network_available": network_cond.get("status") != "True",
                "pod_cidr": node.get("pod_cidr", ""),
            }
        )

    return json.dumps(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detected_plugins": detected_plugins,
            "daemonset_status": daemonset_status,
            "pods": pod_summary,
            "nodes": node_summary,
            "pods_with_network_issues": network_issues,
            "issues": issues,
            "warnings": warnings,
            "healthy": len(issues) == 0,
        },
        indent=2,
    )


def format_table(
    detected_plugins: list,
    daemonset_status: dict | None,
    issues: list,
    warnings: list,
) -> str:
    """Format output as a table."""
    lines = []

    # Header
    lines.append("+" + "-" * 78 + "+")
    lines.append("| Kubernetes CNI Health Monitor" + " " * 48 + "|")
    lines.append("+" + "-" * 78 + "+")

    # Detected CNI
    lines.append("| Detected CNI" + " " * 65 + "|")
    lines.append("+" + "-" * 78 + "+")
    if detected_plugins:
        for plugin in detected_plugins:
            plugin_text = (
                f"{plugin['name']} - {plugin['pod_count']} pods in {plugin['namespace']}"
            )
            lines.append(f"| {plugin_text:<76} |")
    else:
        lines.append("| No recognized CNI plugin detected" + " " * 43 + "|")
    lines.append("+" + "-" * 78 + "+")

    # DaemonSet status
    if daemonset_status:
        ds = daemonset_status
        lines.append("| CNI DaemonSet Status" + " " * 57 + "|")
        lines.append("+" + "-" * 78 + "+")
        lines.append(
            f"| {'Name':<20} | {'Desired':<10} | {'Ready':<10} | {'Available':<10} | {'Unavail':<10} |"
        )
        lines.append("+" + "-" * 78 + "+")
        lines.append(
            f"| {ds['name']:<20} | {ds['desired']:<10} | {ds['ready']:<10} | "
            f"{ds['available']:<10} | {ds.get('unavailable', 0):<10} |"
        )
        lines.append("+" + "-" * 78 + "+")

    # Issues and warnings
    if issues or warnings:
        lines.append("| Issues & Warnings" + " " * 60 + "|")
        lines.append("+" + "-" * 78 + "+")
        for issue in issues:
            issue_text = f"ISSUE: {issue}"[:76]
            lines.append(f"| {issue_text:<76} |")
        for warning in warnings:
            warning_text = f"WARN: {warning}"[:76]
            lines.append(f"| {warning_text:<76} |")
        lines.append("+" + "-" * 78 + "+")
    else:
        lines.append("| Status: All CNI checks passed" + " " * 47 + "|")
        lines.append("+" + "-" * 78 + "+")

    return "\n".join(lines)


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
        description="Monitor Kubernetes CNI (Container Network Interface) health"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show output if issues or warnings are detected",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information including per-node status",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Gather CNI health data
    detected_plugins = detect_cni_plugin(context)

    # Get DaemonSet status for primary detected plugin
    daemonset_status = None
    pods = []
    if detected_plugins:
        primary_plugin = detected_plugins[0]
        plugin_info = CNI_PLUGINS.get(primary_plugin["name"], {})
        namespace = plugin_info.get("namespace", "kube-system")
        daemonset_status = get_cni_daemonset_status(
            context, primary_plugin["name"], namespace
        )
        pods = get_cni_pods(context, primary_plugin["name"], namespace)

    nodes = get_node_network_conditions(context)
    network_issues = get_pods_with_network_issues(context)

    # Analyze health
    issues, warnings = analyze_cni_health(
        detected_plugins, daemonset_status, pods, nodes, network_issues
    )

    # Format output
    if opts.format == "json":
        result = format_json(
            detected_plugins,
            daemonset_status,
            pods,
            nodes,
            network_issues,
            issues,
            warnings,
        )
    elif opts.format == "table":
        result = format_table(detected_plugins, daemonset_status, issues, warnings)
    else:
        result = format_plain(
            detected_plugins,
            daemonset_status,
            pods,
            nodes,
            network_issues,
            issues,
            warnings,
            verbose=opts.verbose,
        )

    # Print output (respecting --warn-only)
    if not opts.warn_only or issues or warnings:
        print(result)

    output.set_summary(
        f"plugins={len(detected_plugins)}, issues={len(issues)}, warnings={len(warnings)}"
    )

    # Return appropriate exit code
    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
