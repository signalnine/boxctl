#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [deployment, statefulset, health, rollout]
#   requires: [kubectl]
#   privilege: user
#   related: [replicaset_health]
#   brief: Monitor Deployment and StatefulSet health status

"""
Monitor Kubernetes Deployments and StatefulSets status and replica availability.

Checks for:
- Replica availability (desired, ready, updated, available)
- Deployment/StatefulSet conditions (Progressing, Available)
- Rollout status and stalled rollouts
- Generation observation status

Exit codes:
    0 - All deployments/statefulsets healthy and fully rolled out
    1 - One or more deployments/statefulsets not ready or unhealthy
    2 - Usage error or kubectl not available
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_deployments(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get all deployments in JSON format."""
    cmd = ["kubectl", "get", "deployments", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout)


def get_statefulsets(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get all statefulsets in JSON format."""
    cmd = ["kubectl", "get", "statefulsets", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout)


def check_deployment_status(deployment: dict[str, Any]) -> tuple[bool, list[str], dict[str, int]]:
    """Check deployment status and return health info."""
    status = deployment.get("status", {})
    spec = deployment.get("spec", {})

    desired = spec.get("replicas", 0)
    ready = status.get("readyReplicas", 0)
    updated = status.get("updatedReplicas", 0)
    available = status.get("availableReplicas", 0)
    observed_generation = status.get("observedGeneration", 0)

    metadata = deployment.get("metadata", {})
    generation = metadata.get("generation", 0)

    issues = []
    is_healthy = True

    # Check if deployment is fully rolled out
    if ready != desired or updated != desired or available != desired:
        issues.append(
            f"Not fully rolled out: {ready}/{desired} ready, "
            f"{updated}/{desired} updated, {available}/{desired} available"
        )
        is_healthy = False

    # Check if generation is observed
    if observed_generation < generation:
        issues.append("Rollout in progress (generation not yet observed)")
        is_healthy = False

    # Check conditions
    conditions = status.get("conditions", [])
    for condition in conditions:
        condition_type = condition.get("type", "")
        cond_status = condition.get("status", "Unknown")
        reason = condition.get("reason", "")
        message = condition.get("message", "")

        if condition_type == "Progressing" and cond_status != "True":
            issues.append(f"Progressing={cond_status}: {reason} - {message}")
            is_healthy = False

        if condition_type == "Available" and cond_status != "True":
            issues.append(f"Available={cond_status}: {reason}")
            is_healthy = False

    return is_healthy, issues, {
        "desired": desired,
        "ready": ready,
        "updated": updated,
        "available": available
    }


def check_statefulset_status(statefulset: dict[str, Any]) -> tuple[bool, list[str], dict[str, int]]:
    """Check statefulset status and return health info."""
    status = statefulset.get("status", {})
    spec = statefulset.get("spec", {})

    desired = spec.get("replicas", 0)
    ready = status.get("readyReplicas", 0)
    updated = status.get("updatedReplicas", 0)
    current = status.get("currentReplicas", 0)
    observed_generation = status.get("observedGeneration", 0)

    metadata = statefulset.get("metadata", {})
    generation = metadata.get("generation", 0)

    issues = []
    is_healthy = True

    # Check if statefulset is fully rolled out
    if ready != desired or updated != desired or current != desired:
        issues.append(
            f"Not fully rolled out: {ready}/{desired} ready, "
            f"{updated}/{desired} updated, {current}/{desired} current"
        )
        is_healthy = False

    # Check if generation is observed
    if observed_generation < generation:
        issues.append("Rollout in progress (generation not yet observed)")
        is_healthy = False

    return is_healthy, issues, {
        "desired": desired,
        "ready": ready,
        "updated": updated,
        "current": current
    }


def get_images(resource: dict[str, Any]) -> list[str]:
    """Extract image versions from resource."""
    containers = resource.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    return [container.get("image", "unknown") for container in containers]


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
        description="Monitor Kubernetes Deployments and StatefulSets status"
    )
    parser.add_argument("-n", "--namespace", help="Namespace to check (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl to use this script.")
        return 2

    try:
        deployments = get_deployments(context, opts.namespace)
        statefulsets = get_statefulsets(context, opts.namespace)
    except Exception as e:
        output.error(f"Failed to get resources: {e}")
        return 2

    results = []
    has_issues = False
    healthy_count = 0
    unhealthy_count = 0

    # Process deployments
    for dep in deployments.get("items", []):
        name = dep["metadata"]["name"]
        ns = dep["metadata"].get("namespace", "default")

        is_healthy, issues, replicas = check_deployment_status(dep)
        images = get_images(dep)

        if is_healthy:
            healthy_count += 1
        else:
            unhealthy_count += 1
            has_issues = True

        if opts.warn_only and is_healthy:
            continue

        result_item = {
            "type": "Deployment",
            "namespace": ns,
            "name": name,
            "healthy": is_healthy,
            "replicas": replicas,
            "issues": issues,
        }

        if opts.verbose:
            result_item["images"] = images

        results.append(result_item)

    # Process statefulsets
    for sts in statefulsets.get("items", []):
        name = sts["metadata"]["name"]
        ns = sts["metadata"].get("namespace", "default")

        is_healthy, issues, replicas = check_statefulset_status(sts)
        images = get_images(sts)

        if is_healthy:
            healthy_count += 1
        else:
            unhealthy_count += 1
            has_issues = True

        if opts.warn_only and is_healthy:
            continue

        result_item = {
            "type": "StatefulSet",
            "namespace": ns,
            "name": name,
            "healthy": is_healthy,
            "replicas": replicas,
            "issues": issues,
        }

        if opts.verbose:
            result_item["images"] = images

        results.append(result_item)

    output.emit({
        "resources": results,
        "summary": {
            "healthy": healthy_count,
            "unhealthy": unhealthy_count,
            "total": healthy_count + unhealthy_count,
        }
    })

    output.set_summary(f"{healthy_count} healthy, {unhealthy_count} with issues")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
