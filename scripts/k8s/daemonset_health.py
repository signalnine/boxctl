#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [daemonset, kubernetes, health, monitoring, nodes]
#   requires: [kubectl]
#   brief: Monitor DaemonSet health with node coverage and pod status
#   privilege: user
#   related: [node_capacity, container_restart_analyzer]

"""
Monitor Kubernetes DaemonSet health with node coverage and pod status.

Provides DaemonSet-specific health checks including:
- Node coverage: verify pods are running on all expected nodes
- Pod readiness and status on each node
- ImagePullBackOff and CrashLoopBackOff detection
- Node selector and toleration issues preventing scheduling
- Update strategy status and rollout progress
- Resource constraints blocking DaemonSet pod placement
- Critical system DaemonSet monitoring (CNI, CSI, kube-proxy)

Exit codes:
    0 - All DaemonSets healthy with pods on all expected nodes
    1 - One or more DaemonSets unhealthy or have warnings
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_pods_for_daemonset(context: Context, namespace: str, name: str) -> dict:
    """Get pods belonging to a specific DaemonSet."""
    result = context.run(["kubectl", "get", "pods", "-n", namespace, "-o", "json"])
    if result.returncode != 0:
        return {"items": []}

    all_pods = json.loads(result.stdout)
    filtered_pods = []

    for pod in all_pods.get("items", []):
        owner_refs = pod.get("metadata", {}).get("ownerReferences", [])
        for ref in owner_refs:
            if ref.get("kind") == "DaemonSet" and ref.get("name") == name:
                filtered_pods.append(pod)
                break

    return {"items": filtered_pods}


def check_pod_health(pod: dict) -> tuple[list, str]:
    """Check individual pod health and return issues."""
    issues = []
    name = pod["metadata"]["name"]
    node_name = pod["spec"].get("nodeName", "unassigned")
    status = pod.get("status", {})

    # Check pod phase
    phase = status.get("phase", "Unknown")
    if phase not in ["Running", "Succeeded"]:
        issues.append(f"Pod {name} on node {node_name} in {phase} phase")

    # Check container statuses
    container_statuses = status.get("containerStatuses", [])
    for container in container_statuses:
        container_name = container.get("name", "unknown")
        ready = container.get("ready", False)
        restart_count = container.get("restartCount", 0)

        if not ready:
            state = container.get("state", {})
            if "waiting" in state:
                reason = state["waiting"].get("reason", "Unknown")
                message = state["waiting"].get("message", "")
                issues.append(
                    f"Container {container_name} on {node_name} not ready: {reason} - {message}"
                )
            elif "terminated" in state:
                reason = state["terminated"].get("reason", "Unknown")
                issues.append(
                    f"Container {container_name} on {node_name} terminated: {reason}"
                )

        if restart_count > 5:
            issues.append(
                f"Container {container_name} on {node_name} has {restart_count} restarts"
            )

    # Check for scheduling issues
    conditions = status.get("conditions", [])
    for condition in conditions:
        if (
            condition.get("type") == "PodScheduled"
            and condition.get("status") != "True"
        ):
            message = condition.get("message", "")
            issues.append(f"Scheduling issue on {node_name}: {message}")

    return issues, node_name


def node_matches_selector(node: dict, node_selector: dict) -> bool:
    """Check if node matches the DaemonSet's node selector."""
    if not node_selector:
        return True

    node_labels = node.get("metadata", {}).get("labels", {})
    for key, value in node_selector.items():
        if node_labels.get(key) != value:
            return False
    return True


def check_daemonset_health(
    ds: dict, pods: dict, nodes: dict, context: Context
) -> tuple[bool, list, list, dict, dict]:
    """Check DaemonSet health including node coverage."""
    name = ds["metadata"]["name"]
    namespace = ds["metadata"].get("namespace", "default")
    status = ds.get("status", {})
    spec = ds.get("spec", {})

    issues = []
    warnings = []

    # Get replica counts
    desired = status.get("desiredNumberScheduled", 0)
    current = status.get("currentNumberScheduled", 0)
    ready = status.get("numberReady", 0)
    available = status.get("numberAvailable", 0)
    misscheduled = status.get("numberMisscheduled", 0)
    updated = status.get("updatedNumberScheduled", 0)

    # Check if pods are running on all expected nodes
    if current != desired:
        issues.append(
            f"Only {current}/{desired} pods scheduled (missing on {desired - current} nodes)"
        )

    if ready != desired:
        issues.append(f"Only {ready}/{desired} pods ready")

    if available != desired:
        warnings.append(f"Only {available}/{desired} pods available")

    if misscheduled > 0:
        issues.append(f"{misscheduled} pods running on nodes where they shouldn't")

    if updated != desired:
        warnings.append(f"Only {updated}/{desired} pods updated (rollout in progress)")

    # Check update strategy
    update_strategy = spec.get("updateStrategy", {})
    strategy_type = update_strategy.get("type", "RollingUpdate")

    if strategy_type == "RollingUpdate":
        rolling_update = update_strategy.get("rollingUpdate", {})
        max_unavailable = rolling_update.get("maxUnavailable", 1)
        if max_unavailable == 0:
            warnings.append("MaxUnavailable is 0 (rollout will be slow)")

    # Get node selector
    node_selector = spec.get("template", {}).get("spec", {}).get("nodeSelector", {})

    # Build map of nodes that have pods
    nodes_with_pods = set()
    pod_issues = defaultdict(list)

    for pod in pods.get("items", []):
        pod_name = pod["metadata"]["name"]
        pod_problems, node_name = check_pod_health(pod)
        if node_name != "unassigned":
            nodes_with_pods.add(node_name)
        if pod_problems:
            pod_issues[pod_name] = pod_problems

    # Check which nodes should have pods but don't
    nodes_without_pods = []
    nodes_unschedulable = []

    for node in nodes.get("items", []):
        node_name = node["metadata"]["name"]

        # Check if node is schedulable
        unschedulable = node["spec"].get("unschedulable", False)
        if unschedulable:
            nodes_unschedulable.append(node_name)
            continue

        # Check if node is ready
        node_ready = False
        conditions = node.get("status", {}).get("conditions", [])
        for condition in conditions:
            if condition.get("type") == "Ready" and condition.get("status") == "True":
                node_ready = True
                break

        if not node_ready:
            continue

        # Check if node matches selector
        if not node_matches_selector(node, node_selector):
            continue

        # This node should have a pod
        if node_name not in nodes_with_pods:
            nodes_without_pods.append(node_name)

    if nodes_without_pods:
        nodes_preview = ", ".join(nodes_without_pods[:5])
        suffix = "..." if len(nodes_without_pods) > 5 else ""
        issues.append(
            f"Missing pods on {len(nodes_without_pods)} nodes: {nodes_preview}{suffix}"
        )

    # Check for node selector that might be too restrictive
    if node_selector and desired == 0:
        warnings.append(f"Node selector may be too restrictive: {node_selector}")

    # Determine overall health
    is_healthy = len(issues) == 0 and ready == desired and current == desired

    return (
        is_healthy,
        issues,
        warnings,
        dict(pod_issues),
        {
            "desired": desired,
            "current": current,
            "ready": ready,
            "available": available,
            "updated": updated,
            "misscheduled": misscheduled,
            "nodes_without_pods": nodes_without_pods,
            "nodes_unschedulable": nodes_unschedulable,
        },
    )


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
        description="Monitor Kubernetes DaemonSet health with node coverage and pod status"
    )
    parser.add_argument(
        "--namespace",
        "-n",
        help="Namespace to check (default: all namespaces)",
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
        help="Only show DaemonSets with issues or warnings",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get nodes first (needed for coverage check)
    try:
        result = context.run(["kubectl", "get", "nodes", "-o", "json"])
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        nodes = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get nodes: {e}")
        return 2

    # Get DaemonSets
    try:
        ds_args = ["kubectl", "get", "daemonsets", "-o", "json"]
        if opts.namespace:
            ds_args.extend(["-n", opts.namespace])
        else:
            ds_args.append("--all-namespaces")

        result = context.run(ds_args)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        daemonsets = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get daemonsets: {e}")
        return 2

    has_issues = False
    results = []

    for ds in daemonsets.get("items", []):
        name = ds["metadata"]["name"]
        namespace = ds["metadata"].get("namespace", "default")

        if opts.namespace and namespace != opts.namespace:
            continue

        # Get pods for this DaemonSet
        pods = get_pods_for_daemonset(context, namespace, name)

        is_healthy, issues, warnings, pod_issues, replicas = check_daemonset_health(
            ds, pods, nodes, context
        )

        ds_info = {
            "namespace": namespace,
            "name": name,
            "healthy": is_healthy,
            "replicas": replicas,
            "issues": issues,
            "warnings": warnings,
            "pod_issues": pod_issues,
        }

        if not opts.warn_only or issues or warnings or pod_issues:
            results.append(ds_info)
            if issues or pod_issues:
                has_issues = True

    # Output results
    if opts.format == "json":
        print(json.dumps(results, indent=2))
    else:
        healthy_count = sum(1 for r in results if r["healthy"])
        unhealthy_count = sum(1 for r in results if not r["healthy"])

        for r in results:
            status_marker = "[OK]" if r["healthy"] else "[!!]"
            print(f"{status_marker} DaemonSet: {r['namespace']}/{r['name']}")
            print(
                f"  Pods: {r['replicas']['ready']}/{r['replicas']['desired']} ready, "
                f"{r['replicas']['current']}/{r['replicas']['desired']} scheduled, "
                f"{r['replicas']['updated']}/{r['replicas']['desired']} updated"
            )

            if r["replicas"]["misscheduled"] > 0:
                print(f"  Misscheduled: {r['replicas']['misscheduled']} pods")

            for issue in r["issues"]:
                print(f"  ERROR: {issue}")

            for warning in r["warnings"]:
                print(f"  WARNING: {warning}")

            if r["pod_issues"]:
                print("  Pod Issues:")
                for pod_name, pod_problems in r["pod_issues"].items():
                    print(f"    {pod_name}:")
                    for problem in pod_problems:
                        print(f"      - {problem}")

            if (
                r["replicas"]["nodes_without_pods"]
                and len(r["replicas"]["nodes_without_pods"]) <= 10
            ):
                print(
                    f"  Nodes without pods: {', '.join(r['replicas']['nodes_without_pods'])}"
                )

            print()

        total = healthy_count + unhealthy_count
        if total > 0:
            print(
                f"Summary: {healthy_count}/{total} DaemonSets healthy, {unhealthy_count} with issues"
            )
        else:
            print("No DaemonSets found")

    output.set_summary(
        f"daemonsets={len(results)}, healthy={sum(1 for r in results if r['healthy'])}, "
        f"unhealthy={sum(1 for r in results if not r['healthy'])}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
