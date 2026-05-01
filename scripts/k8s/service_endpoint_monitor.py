#!/usr/bin/env python3
# boxctl:
#   category: k8s/networking
#   tags: [service, endpoint, health, connectivity]
#   requires: [kubectl]
#   privilege: user
#   related: [ingress_health]
#   brief: Monitor Kubernetes Service endpoint health

"""
Kubernetes Service Endpoint Health Monitor

Monitors Kubernetes Services to detect those without healthy endpoints,
which indicates broken application connectivity.

Checks for:
- Services with no endpoints (selector mismatch or no pods)
- Services with endpoints but all NotReady
- LoadBalancer services without external IPs
- Partial endpoint readiness

Exit codes:
    0 - All services have healthy endpoints
    1 - One or more services have endpoint issues
    2 - Usage error or kubectl not found
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_services(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get services in JSON format."""
    cmd = ["kubectl", "get", "services", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout)


def get_endpoints(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get endpoints in JSON format."""
    cmd = ["kubectl", "get", "endpoints", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout)


def get_pods(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get pods in JSON format."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout)


def is_pod_ready(pod: dict[str, Any]) -> bool:
    """Check if pod is ready."""
    conditions = pod.get("status", {}).get("conditions", [])
    for condition in conditions:
        if condition["type"] == "Ready":
            return condition["status"] == "True"
    return False


def analyze_service_endpoints(
    services: dict[str, Any],
    endpoints: dict[str, Any],
    pods: dict[str, Any]
) -> list[dict[str, Any]]:
    """Analyze services for endpoint health issues."""
    issues = []

    # Build endpoint map: namespace/name -> endpoint object
    endpoint_map = {}
    for ep in endpoints.get("items", []):
        ns = ep["metadata"]["namespace"]
        name = ep["metadata"]["name"]
        key = f"{ns}/{name}"
        endpoint_map[key] = ep

    # Build pod map for selector matching
    pod_map = defaultdict(list)
    for pod in pods.get("items", []):
        ns = pod["metadata"]["namespace"]
        labels = pod["metadata"].get("labels", {})
        pod_map[ns].append({
            "name": pod["metadata"]["name"],
            "labels": labels,
            "ready": is_pod_ready(pod)
        })

    for svc in services.get("items", []):
        ns = svc["metadata"]["namespace"]
        name = svc["metadata"]["name"]
        svc_type = svc["spec"].get("type", "ClusterIP")
        selector = svc["spec"].get("selector", {})

        # Skip services without selectors (e.g., ExternalName, headless)
        if not selector:
            continue

        key = f"{ns}/{name}"

        # Check if service has endpoint object
        if key not in endpoint_map:
            issues.append({
                "namespace": ns,
                "service": name,
                "type": svc_type,
                "issue": "no_endpoint_object",
                "severity": "critical",
                "details": "Service has no corresponding endpoint object"
            })
            continue

        ep = endpoint_map[key]
        subsets = ep.get("subsets", [])

        # Check if endpoint has any addresses
        total_ready = 0
        total_not_ready = 0

        for subset in subsets:
            ready_addrs = subset.get("addresses", [])
            not_ready_addrs = subset.get("notReadyAddresses", [])
            total_ready += len(ready_addrs)
            total_not_ready += len(not_ready_addrs)

        if total_ready == 0 and total_not_ready == 0:
            # No endpoints at all - check if pods exist with matching labels
            matching_pods = [
                p for p in pod_map.get(ns, [])
                if all(p["labels"].get(k) == v for k, v in selector.items())
            ]

            if not matching_pods:
                issues.append({
                    "namespace": ns,
                    "service": name,
                    "type": svc_type,
                    "issue": "no_matching_pods",
                    "severity": "critical",
                    "details": f"No pods match selector {selector}"
                })
            else:
                issues.append({
                    "namespace": ns,
                    "service": name,
                    "type": svc_type,
                    "issue": "pods_exist_but_no_endpoints",
                    "severity": "critical",
                    "details": f"{len(matching_pods)} matching pods but no endpoints"
                })

        elif total_ready == 0 and total_not_ready > 0:
            issues.append({
                "namespace": ns,
                "service": name,
                "type": svc_type,
                "issue": "all_endpoints_not_ready",
                "severity": "critical",
                "details": f"{total_not_ready} endpoints exist but all are NotReady"
            })

        elif total_ready > 0 and total_not_ready > 0:
            # Some ready, some not ready - warning level
            issues.append({
                "namespace": ns,
                "service": name,
                "type": svc_type,
                "issue": "partial_endpoints_not_ready",
                "severity": "warning",
                "details": f"{total_ready} ready, {total_not_ready} not ready"
            })

        # Check LoadBalancer services for external IP
        if svc_type == "LoadBalancer":
            status = svc.get("status", {})
            load_balancer = status.get("loadBalancer", {})
            ingress = load_balancer.get("ingress", [])

            if not ingress:
                issues.append({
                    "namespace": ns,
                    "service": name,
                    "type": svc_type,
                    "issue": "loadbalancer_no_external_ip",
                    "severity": "warning",
                    "details": "LoadBalancer service has no external IP assigned"
                })

    return issues


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
        description="Monitor Kubernetes Service endpoint health"
    )
    parser.add_argument("-n", "--namespace", help="Namespace to check (default: all)")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl to use this script.")
        return 2

    try:
        services = get_services(context, opts.namespace)
        endpoints = get_endpoints(context, opts.namespace)
        pods = get_pods(context, opts.namespace)
    except Exception as e:
        output.error(f"Failed to get resources: {e}")
        return 2

    issues = analyze_service_endpoints(services, endpoints, pods)

    # Filter by warn_only
    if opts.warn_only:
        issues = [i for i in issues if i["severity"] in ("critical", "warning")]

    critical_count = sum(1 for i in issues if i["severity"] == "critical")
    warning_count = sum(1 for i in issues if i["severity"] == "warning")

    output.emit({
        "issues": issues,
        "summary": {
            "total_issues": len(issues),
            "critical": critical_count,
            "warnings": warning_count,
        }
    })

    if not issues:
        output.set_summary("All services have healthy endpoints")
    else:
        output.set_summary(f"{critical_count} critical, {warning_count} warnings")

    has_critical = critical_count > 0
    return 1 if has_critical or issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
