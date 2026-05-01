#!/usr/bin/env python3
# boxctl:
#   category: k8s/autoscaling
#   tags: [hpa, kubernetes, autoscaling, health, monitoring]
#   requires: [kubectl]
#   brief: Monitor HorizontalPodAutoscaler health and effectiveness
#   privilege: user
#   related: [hpa_thrashing, node_capacity]

"""
Monitor HorizontalPodAutoscaler (HPA) health and effectiveness.

This script analyzes HorizontalPodAutoscalers in a Kubernetes cluster to identify:
- HPA scaling issues (unable to compute metrics, at limits, flapping)
- Metrics server availability and health
- HPA misconfiguration (invalid targets, missing metrics)
- Scaling patterns and effectiveness
- HPAs at min/max replica limits with unmet targets

Exit codes:
    0 - All HPAs healthy and functioning correctly
    1 - HPA issues detected (scaling problems, metrics unavailable, misconfigurations)
    2 - kubectl not found or usage error
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_metrics_server(context: Context) -> dict:
    """Check if metrics server is available and healthy."""
    try:
        # Check if metrics-server is deployed
        result = context.run(
            [
                "kubectl",
                "get",
                "deployment",
                "-n",
                "kube-system",
                "metrics-server",
                "-o",
                "json",
            ]
        )
        if result.returncode != 0:
            return {
                "deployed": False,
                "healthy": False,
                "metrics_api_working": False,
            }

        deployment = json.loads(result.stdout)

        available = deployment.get("status", {}).get("availableReplicas", 0)
        desired = deployment.get("spec", {}).get("replicas", 1)

        # Try to query metrics API
        metrics_result = context.run(["kubectl", "top", "nodes", "--no-headers"])
        metrics_api_working = metrics_result.returncode == 0

        return {
            "deployed": True,
            "available_replicas": available,
            "desired_replicas": desired,
            "healthy": available >= desired and metrics_api_working,
            "metrics_api_working": metrics_api_working,
        }
    except Exception:
        return {
            "deployed": False,
            "healthy": False,
            "metrics_api_working": False,
        }


def analyze_hpa(hpa: dict) -> dict:
    """Analyze a single HPA for health and configuration issues."""
    metadata = hpa.get("metadata", {})
    spec = hpa.get("spec", {})
    status = hpa.get("status", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    issues = []
    warnings = []

    # Get replica information
    current_replicas = status.get("currentReplicas", 0)
    desired_replicas = status.get("desiredReplicas", 0)
    min_replicas = spec.get("minReplicas", 1)
    max_replicas = spec.get("maxReplicas", 10)

    # Check for metrics availability
    current_metrics = status.get("currentMetrics", [])
    conditions = status.get("conditions", [])

    # Analyze conditions
    for condition in conditions:
        condition_type = condition.get("type", "")
        condition_status = condition.get("status", "")
        reason = condition.get("reason", "")
        message = condition.get("message", "")

        if condition_type == "ScalingActive" and condition_status != "True":
            issues.append(f"Scaling inactive: {reason} - {message}")

        if condition_type == "AbleToScale" and condition_status != "True":
            issues.append(f"Unable to scale: {reason} - {message}")

        if condition_type == "ScalingLimited" and condition_status == "True":
            if "minimum" in message.lower():
                warnings.append(f"At minimum replica limit ({min_replicas})")
            elif "maximum" in message.lower():
                warnings.append(f"At maximum replica limit ({max_replicas})")

    # Check if metrics are available
    if not current_metrics:
        issues.append("No current metrics available")

    # Check for metric computation issues
    for metric in current_metrics:
        metric_type = metric.get("type", "")
        if metric_type == "Resource":
            resource = metric.get("resource", {})
            current = resource.get("current", {})
            if "averageUtilization" not in current and "averageValue" not in current:
                issues.append(
                    f"Resource metric '{resource.get('name')}' has no current value"
                )
        elif metric_type == "Pods":
            pods = metric.get("pods", {})
            current = pods.get("current", {})
            if "averageValue" not in current:
                issues.append("Pods metric has no current value")
        elif metric_type == "External":
            external = metric.get("external", {})
            current = external.get("current", {})
            if "value" not in current and "averageValue" not in current:
                issues.append("External metric has no current value")

    # Check for flapping (current != desired)
    if current_replicas != desired_replicas:
        warnings.append(
            f"Scaling in progress: {current_replicas} -> {desired_replicas} replicas"
        )

    # Check if at limits with unmet targets
    if current_replicas == max_replicas:
        # Check if we should scale further but can't
        for condition in conditions:
            if (
                condition.get("type") == "ScalingLimited"
                and "maximum" in condition.get("message", "").lower()
            ):
                issues.append(
                    f"At max replicas ({max_replicas}) but may need more capacity"
                )

    # Check target reference exists
    scale_target_ref = spec.get("scaleTargetRef", {})
    target_kind = scale_target_ref.get("kind", "")
    target_name = scale_target_ref.get("name", "")

    if not target_name:
        issues.append("No scale target reference configured")

    # Analyze metrics specification
    metrics_spec = spec.get("metrics", [])
    if not metrics_spec:
        issues.append("No metrics configured")

    # Check for reasonable min/max spread
    if max_replicas - min_replicas < 2:
        warnings.append(f"Small scaling range ({min_replicas}-{max_replicas})")

    return {
        "name": name,
        "namespace": namespace,
        "target": f"{target_kind}/{target_name}",
        "current_replicas": current_replicas,
        "desired_replicas": desired_replicas,
        "min_replicas": min_replicas,
        "max_replicas": max_replicas,
        "issues": issues,
        "warnings": warnings,
        "healthy": len(issues) == 0,
        "metrics_count": len(current_metrics),
        "conditions": conditions,
    }


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
        description="Monitor HorizontalPodAutoscaler health and effectiveness"
    )
    parser.add_argument(
        "-n",
        "--namespace",
        help="Namespace to check (default: all namespaces)",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show HPAs with issues or warnings",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information including conditions",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Check metrics server
    metrics_server = check_metrics_server(context)

    # Get HPAs
    try:
        hpa_args = ["kubectl", "get", "hpa", "-o", "json"]
        if opts.namespace:
            hpa_args.extend(["-n", opts.namespace])
        else:
            hpa_args.append("--all-namespaces")

        result = context.run(hpa_args)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2

        hpas = json.loads(result.stdout).get("items", [])
    except Exception as e:
        output.error(f"Failed to get HPAs: {e}")
        return 2

    results = []
    for hpa in hpas:
        result_item = analyze_hpa(hpa)
        results.append(result_item)

    # Determine exit code
    has_issues = any(not r["healthy"] for r in results)
    metrics_server_unhealthy = not metrics_server.get("healthy", False)

    if opts.format == "json":
        json_output = {
            "metrics_server": metrics_server,
            "summary": {
                "total_hpas": len(results),
                "healthy": sum(1 for r in results if r["healthy"]),
                "unhealthy": sum(1 for r in results if not r["healthy"]),
            },
            "hpas": results,
        }
        print(json.dumps(json_output, indent=2))

    elif opts.format == "table":
        print("Metrics Server Status:")
        print(
            f"  {'Status:':<20} {'HEALTHY' if metrics_server.get('healthy') else 'UNHEALTHY'}"
        )
        print(
            f"  {'Deployed:':<20} {'Yes' if metrics_server.get('deployed') else 'No'}"
        )
        print(
            f"  {'Metrics API:':<20} {'Working' if metrics_server.get('metrics_api_working') else 'FAILED'}"
        )
        print()

        if not results:
            print("No HPAs found in cluster")
        else:
            # Filter if warn-only
            display_results = [
                r for r in results if not opts.warn_only or not r["healthy"]
            ]

            if not display_results:
                print("No issues found")
            else:
                # Print header
                print(
                    f"{'NAMESPACE':<20} {'NAME':<30} {'STATUS':<10} {'REPLICAS':<12} {'ISSUES':<10}"
                )
                print("-" * 82)

                # Print rows
                for r in display_results:
                    status = "OK" if r["healthy"] else "ISSUES"
                    replicas = f"{r['current_replicas']}/{r['desired_replicas']}"
                    issue_count = len(r["issues"]) + len(r["warnings"])

                    print(
                        f"{r['namespace']:<20} {r['name']:<30} {status:<10} {replicas:<12} {issue_count:<10}"
                    )

    else:  # plain
        print("=== Metrics Server Status ===")
        if metrics_server.get("deployed"):
            status = "HEALTHY" if metrics_server.get("healthy") else "UNHEALTHY"
            print(f"Status: {status}")
            print(
                f"Replicas: {metrics_server.get('available_replicas', 0)}/{metrics_server.get('desired_replicas', 0)}"
            )
            print(
                f"Metrics API: {'Working' if metrics_server.get('metrics_api_working') else 'FAILED'}"
            )
        else:
            print("Status: NOT DEPLOYED")

        print("\n=== HPA Health Summary ===")

        total = len(results)
        healthy = sum(1 for r in results if r["healthy"])
        unhealthy = total - healthy

        print(f"Total HPAs: {total}")
        print(f"Healthy: {healthy}")
        print(f"Unhealthy: {unhealthy}")

        if not results:
            print("\nNo HPAs found in cluster")
        else:
            print("\n=== HPA Details ===")

            for r in results:
                if opts.warn_only and r["healthy"]:
                    continue

                status_icon = "[OK]" if r["healthy"] else "[!!]"
                print(f"\n{status_icon} {r['namespace']}/{r['name']}")
                print(f"  Target: {r['target']}")
                print(
                    f"  Replicas: {r['current_replicas']} (desired: {r['desired_replicas']}, min: {r['min_replicas']}, max: {r['max_replicas']})"
                )
                print(f"  Metrics: {r['metrics_count']} active")

                if r["issues"]:
                    print("  Issues:")
                    for issue in r["issues"]:
                        print(f"    - {issue}")

                if r["warnings"]:
                    print("  Warnings:")
                    for warning in r["warnings"]:
                        print(f"    - {warning}")

    output.set_summary(
        f"hpas={len(results)}, healthy={sum(1 for r in results if r['healthy'])}, "
        f"metrics_server={'healthy' if metrics_server.get('healthy') else 'unhealthy'}"
    )

    return 1 if has_issues or metrics_server_unhealthy else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
