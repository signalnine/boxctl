#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [statefulset, pods, pvc, storage, kubernetes]
#   requires: [kubectl]
#   privilege: user
#   brief: Monitor Kubernetes StatefulSet health with detailed pod and PVC status
#   related: [pv_health, container_restart_analyzer, deployment_status]

"""
Monitor Kubernetes StatefulSet health with detailed pod and PVC status.

This script provides StatefulSet-specific health checks including:
- Pod readiness and ordering (StatefulSets maintain stable pod identities)
- PersistentVolumeClaim binding status for each pod
- Partition rollout status (for staged rollouts)
- Pod restart counts and readiness
- Volume attachment issues
- StatefulSet update strategy validation

Exit codes:
    0 - All StatefulSets healthy with all pods ready
    1 - One or more StatefulSets unhealthy or have warnings
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_pods_for_statefulset(
    context: Context, namespace: str, name: str
) -> dict:
    """Get pods belonging to a specific StatefulSet."""
    # Try with standard label first
    cmd = [
        "kubectl",
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        f"app.kubernetes.io/name={name}",
        "-o",
        "json",
    ]
    result = context.run(cmd)
    pods_data = json.loads(result.stdout)

    # If no pods found with standard label, try owner reference approach
    if not pods_data.get("items"):
        cmd = ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
        result = context.run(cmd)
        all_pods = json.loads(result.stdout)

        filtered_pods = []
        for pod in all_pods.get("items", []):
            owner_refs = pod.get("metadata", {}).get("ownerReferences", [])
            for ref in owner_refs:
                if ref.get("kind") == "StatefulSet" and ref.get("name") == name:
                    filtered_pods.append(pod)
                    break

        pods_data["items"] = filtered_pods

    return pods_data


def get_pvcs_for_namespace(context: Context, namespace: str) -> dict:
    """Get all PVCs in a namespace."""
    cmd = ["kubectl", "get", "pvc", "-n", namespace, "-o", "json"]
    result = context.run(cmd)
    return json.loads(result.stdout)


def check_pod_health(pod: dict) -> list[str]:
    """Check individual pod health and return issues."""
    issues = []
    name = pod["metadata"]["name"]
    status = pod.get("status", {})

    # Check pod phase
    phase = status.get("phase", "Unknown")
    if phase not in ["Running", "Succeeded"]:
        issues.append(f"Pod {name} in {phase} phase")

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
                    f"Container {container_name} not ready: {reason} - {message}"
                )
            elif "terminated" in state:
                reason = state["terminated"].get("reason", "Unknown")
                issues.append(f"Container {container_name} terminated: {reason}")

        if restart_count > 5:
            issues.append(f"Container {container_name} has {restart_count} restarts")

    # Check for unbound volumes
    conditions = status.get("conditions", [])
    for condition in conditions:
        if (
            condition.get("type") == "PodScheduled"
            and condition.get("status") != "True"
        ):
            reason = condition.get("reason", "")
            message = condition.get("message", "")
            if "volume" in message.lower() or "pvc" in message.lower():
                issues.append(f"Volume binding issue: {message}")

    return issues


def check_statefulset_health(
    sts: dict, pods: dict, pvcs: dict
) -> tuple[bool, list, list, dict, dict]:
    """Check StatefulSet health including pods and PVCs."""
    name = sts["metadata"]["name"]
    namespace = sts["metadata"].get("namespace", "default")
    status = sts.get("status", {})
    spec = sts.get("spec", {})

    issues = []
    warnings = []

    # Check replica counts
    desired = spec.get("replicas", 0)
    ready = status.get("readyReplicas", 0)
    current = status.get("currentReplicas", 0)
    updated = status.get("updatedReplicas", 0)

    if ready != desired:
        issues.append(f"Only {ready}/{desired} replicas ready")

    if current != desired:
        warnings.append(f"Current replicas: {current}/{desired}")

    if updated != desired:
        warnings.append(f"Updated replicas: {updated}/{desired}")

    # Check update strategy
    update_strategy = spec.get("updateStrategy", {})
    strategy_type = update_strategy.get("type", "RollingUpdate")

    if strategy_type == "RollingUpdate":
        rolling_update = update_strategy.get("rollingUpdate", {})
        partition = rolling_update.get("partition", 0)

        if partition > 0:
            warnings.append(
                f"Partition set to {partition} (staged rollout in progress)"
            )

    # Check for stalled rollout
    observed_generation = status.get("observedGeneration", 0)
    generation = sts["metadata"].get("generation", 0)

    if observed_generation < generation:
        issues.append("StatefulSet generation not yet observed (update pending)")

    # Check individual pods
    pod_issues = defaultdict(list)
    for pod in pods.get("items", []):
        pod_name = pod["metadata"]["name"]
        pod_problems = check_pod_health(pod)
        if pod_problems:
            pod_issues[pod_name] = pod_problems

    # Check PVC status for volumeClaimTemplates
    volume_claim_templates = spec.get("volumeClaimTemplates", [])
    if volume_claim_templates:
        pvc_map = {}
        for pvc in pvcs.get("items", []):
            pvc_name = pvc["metadata"]["name"]
            pvc_map[pvc_name] = pvc

        # Check if all expected PVCs exist and are bound
        for i in range(desired):
            for template in volume_claim_templates:
                template_name = template["metadata"]["name"]
                expected_pvc_name = f"{template_name}-{name}-{i}"

                if expected_pvc_name not in pvc_map:
                    issues.append(f"Missing PVC: {expected_pvc_name}")
                else:
                    pvc = pvc_map[expected_pvc_name]
                    pvc_phase = pvc.get("status", {}).get("phase", "Unknown")
                    if pvc_phase != "Bound":
                        issues.append(
                            f"PVC {expected_pvc_name} not bound (phase: {pvc_phase})"
                        )

    # Determine overall health
    is_healthy = len(issues) == 0 and ready == desired

    return (
        is_healthy,
        issues,
        warnings,
        dict(pod_issues),
        {
            "desired": desired,
            "ready": ready,
            "current": current,
            "updated": updated,
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
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes StatefulSet health with detailed pod and PVC status"
    )

    parser.add_argument(
        "-n",
        "--namespace",
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
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show StatefulSets with issues or warnings",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get StatefulSets
    cmd = ["kubectl", "get", "statefulsets", "-o", "json"]
    if opts.namespace:
        cmd.extend(["-n", opts.namespace])
    else:
        cmd.append("--all-namespaces")

    try:
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        statefulsets_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get statefulsets: {e}")
        return 2

    statefulsets = statefulsets_data.get("items", [])
    has_issues = False
    healthy_count = 0
    unhealthy_count = 0

    if opts.format == "json":
        output_list = []

        for sts in statefulsets:
            name = sts["metadata"]["name"]
            namespace = sts["metadata"].get("namespace", "default")

            if opts.namespace and namespace != opts.namespace:
                continue

            pods = get_pods_for_statefulset(context, namespace, name)
            pvcs = get_pvcs_for_namespace(context, namespace)

            is_healthy, issues, warnings, pod_issues, replicas = (
                check_statefulset_health(sts, pods, pvcs)
            )

            sts_info = {
                "namespace": namespace,
                "name": name,
                "healthy": is_healthy,
                "replicas": replicas,
                "issues": issues,
                "warnings": warnings,
                "pod_issues": pod_issues,
            }

            if not opts.warn_only or issues or warnings or pod_issues:
                output_list.append(sts_info)
                if issues or pod_issues:
                    has_issues = True

        print(json.dumps(output_list, indent=2))

    else:  # plain format
        for sts in statefulsets:
            name = sts["metadata"]["name"]
            namespace = sts["metadata"].get("namespace", "default")

            if opts.namespace and namespace != opts.namespace:
                continue

            pods = get_pods_for_statefulset(context, namespace, name)
            pvcs = get_pvcs_for_namespace(context, namespace)

            is_healthy, issues, warnings, pod_issues, replicas = (
                check_statefulset_health(sts, pods, pvcs)
            )

            if is_healthy:
                healthy_count += 1
            else:
                unhealthy_count += 1
                has_issues = True

            # Skip healthy if warn_only
            if opts.warn_only and is_healthy and not warnings and not pod_issues:
                continue

            # Print StatefulSet info
            status_marker = "[OK]" if is_healthy else "[WARN]"
            print(f"{status_marker} StatefulSet: {namespace}/{name}")
            print(
                f"  Replicas: {replicas['ready']}/{replicas['desired']} ready, "
                f"{replicas['updated']}/{replicas['desired']} updated, "
                f"{replicas['current']}/{replicas['desired']} current"
            )

            if issues:
                for issue in issues:
                    print(f"  ERROR: {issue}")

            if warnings:
                for warning in warnings:
                    print(f"  WARNING: {warning}")

            if pod_issues:
                print("  Pod Issues:")
                for pod_name, pod_problems in pod_issues.items():
                    print(f"    {pod_name}:")
                    for problem in pod_problems:
                        print(f"      - {problem}")

            print()

        total = healthy_count + unhealthy_count
        if total > 0:
            print(
                f"Summary: {healthy_count}/{total} StatefulSets healthy, "
                f"{unhealthy_count} with issues"
            )
        else:
            print("No StatefulSets found")

    output.set_summary(f"healthy={healthy_count}, unhealthy={unhealthy_count}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
