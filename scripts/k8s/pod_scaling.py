#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [scaling, pods, hpa, replicas, kubernetes]
#   requires: [kubectl]
#   brief: Analyze pod counts and scaling configuration
#   privilege: user
#   related: [node_capacity, resource_quota_auditor]

"""
Analyze Kubernetes pod counts and scaling configuration.

This script audits pod scaling configuration across deployments and statefulsets
to identify potential issues:
- HPA (Horizontal Pod Autoscaler) without min/max replicas configured
- Deployments with 0 replicas (scaled down)
- StatefulSets with mismatched replica counts
- Namespace-level pod quotas and current usage
- Deployments with excessive replica counts

Critical for baremetal deployments where pod density directly impacts resource
utilization. Helps identify over-provisioning, under-scaling, and configuration
issues that could affect availability.

Exit codes:
    0: No scaling issues detected
    1: Scaling issues found (warnings)
    2: Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime

from boxctl.core.context import Context
from boxctl.core.output import Output


def analyze_deployment(deployment: dict, hpa_map: dict) -> tuple:
    """Analyze a deployment for scaling issues.

    Returns: (status, issues)
    status: "OK", "WARNING", or "CRITICAL"
    issues: list of issue descriptions
    """
    issues = []
    namespace = deployment['metadata']['namespace']
    name = deployment['metadata']['name']
    spec = deployment['spec']
    status = deployment['status']

    desired_replicas = spec.get('replicas', 1)
    ready_replicas = status.get('readyReplicas', 0)
    updated_replicas = status.get('updatedReplicas', 0)
    available_replicas = status.get('availableReplicas', 0)

    # Check if deployment is scaled to zero
    if desired_replicas == 0:
        issues.append("Deployment scaled to 0 replicas")

    # Check for excessive replicas in small baremetal clusters
    if desired_replicas > 50:
        issues.append(f"High replica count: {desired_replicas}")

    # Check if replicas are not ready
    if desired_replicas > 0 and ready_replicas < desired_replicas:
        issues.append(f"Not ready: {ready_replicas}/{desired_replicas}")

    # Check if updated replicas mismatch
    if desired_replicas > 0 and updated_replicas < desired_replicas:
        issues.append(f"Update in progress: {updated_replicas}/{desired_replicas}")

    # Check if available replicas mismatch
    if desired_replicas > 0 and available_replicas < desired_replicas:
        issues.append(f"Not available: {available_replicas}/{desired_replicas}")

    # Check if there's an HPA but no resources
    if desired_replicas == 1 and (namespace, name) in hpa_map:
        hpa = hpa_map[(namespace, name)]
        min_replicas = hpa['spec'].get('minReplicas', 1)
        if min_replicas > 1 and desired_replicas == 1:
            issues.append(f"HPA configured but only 1 replica (HPA min: {min_replicas})")

    # Determine severity
    if not issues:
        return "OK", []
    elif any("scaled to 0" in issue for issue in issues):
        return "CRITICAL", issues
    else:
        return "WARNING", issues


def analyze_statefulset(statefulset: dict) -> tuple:
    """Analyze a statefulset for scaling issues.

    Returns: (status, issues)
    status: "OK", "WARNING", or "CRITICAL"
    issues: list of issue descriptions
    """
    issues = []
    spec = statefulset['spec']
    status = statefulset['status']

    desired_replicas = spec.get('replicas', 1)
    ready_replicas = status.get('readyReplicas', 0)

    # Check if statefulset is scaled to zero
    if desired_replicas == 0:
        issues.append("StatefulSet scaled to 0 replicas")

    # Check for replica mismatches (statefulsets are order-dependent)
    if desired_replicas > 0 and ready_replicas < desired_replicas:
        issues.append(f"Not all ready: {ready_replicas}/{desired_replicas}")

    # StatefulSets with excessive replicas
    if desired_replicas > 50:
        issues.append(f"High replica count: {desired_replicas}")

    # Determine severity
    if not issues:
        return "OK", []
    elif any("scaled to 0" in issue for issue in issues):
        return "CRITICAL", issues
    else:
        return "WARNING", issues


def analyze_resource_quota(quota: dict) -> tuple:
    """Analyze a resource quota for pod count limits.

    Returns: (status, issues)
    """
    issues = []
    hard = quota['spec'].get('hard', {})
    used = quota['status'].get('used', {})

    if 'pods' not in hard:
        return "OK", []

    pod_hard = int(hard['pods'])
    pod_used = int(used.get('pods', '0'))

    usage_percent = (pod_used / pod_hard * 100) if pod_hard > 0 else 0

    if usage_percent > 90:
        issues.append(f"Pod quota usage {usage_percent:.1f}% ({pod_used}/{pod_hard})")
    elif usage_percent > 75:
        issues.append(f"Pod quota approaching limit {usage_percent:.1f}% ({pod_used}/{pod_hard})")

    if usage_percent > 75:
        return "WARNING", issues
    else:
        return "OK", issues


def format_status(status: str) -> str:
    """Format status with symbol."""
    if status == "OK":
        return "OK"
    elif status == "WARNING":
        return "WARNING"
    else:
        return "CRITICAL"


def print_plain_output(results: list) -> None:
    """Print output in plain (space-separated) format."""
    for item in results:
        resource_type = item['type']
        namespace = item['namespace']
        name = item['name']
        status = item['status']
        issues = ' | '.join(item['issues']) if item['issues'] else 'None'

        print(f"{resource_type} {namespace} {name} {status} {issues}")


def print_table_output(results: list) -> None:
    """Print output in table format."""
    print(f"{'Type':<15} {'Namespace':<20} {'Name':<40} {'Status':<15} {'Issues'}")
    print("-" * 130)

    for item in results:
        resource_type = item['type']
        namespace = item['namespace']
        name = item['name']
        status = item['status']
        issue_text = item['issues'][0] if item['issues'] else 'None'

        print(f"{resource_type:<15} {namespace:<20} {name:<40} {format_status(status):<15} {issue_text}")

        # Print additional issues
        for issue in item['issues'][1:]:
            print(f"{'':<15} {'':<20} {'':<40} {'':<15} {issue}")


def print_json_output(results: list) -> None:
    """Print output in JSON format."""
    output = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total': len(results),
            'ok': sum(1 for r in results if r['status'] == 'OK'),
            'warning': sum(1 for r in results if r['status'] == 'WARNING'),
            'critical': sum(1 for r in results if r['status'] == 'CRITICAL'),
        },
        'resources': results
    }
    print(json.dumps(output, indent=2))


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes pod counts and scaling configuration"
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Analyze specific namespace only"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show resources with issues"
    )
    parser.add_argument(
        "--deployments-only",
        action="store_true",
        help="Only analyze deployments"
    )
    parser.add_argument(
        "--statefulsets-only",
        action="store_true",
        help="Only analyze statefulsets"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    results = []
    has_issues = False

    # Build namespace args
    ns_args = ["-n", opts.namespace] if opts.namespace else ["-A"]

    try:
        # Get HPA map for correlation
        hpa_map = {}
        try:
            result = context.run(["kubectl", "get", "hpa"] + ns_args + ["-o", "json"])
            if result.returncode == 0:
                hpas = json.loads(result.stdout)
                for hpa in hpas.get('items', []):
                    namespace = hpa['metadata']['namespace']
                    target_name = hpa['spec']['scaleTargetRef']['name']
                    hpa_map[(namespace, target_name)] = hpa
        except Exception:
            pass

        # Analyze deployments
        if not opts.statefulsets_only:
            try:
                result = context.run(["kubectl", "get", "deployments"] + ns_args + ["-o", "json"])
                if result.returncode == 0:
                    deployments = json.loads(result.stdout)
                    for deployment in deployments.get('items', []):
                        namespace = deployment['metadata']['namespace']

                        # Skip if filtering by namespace
                        if opts.namespace and namespace != opts.namespace:
                            continue

                        name = deployment['metadata']['name']
                        status, issues = analyze_deployment(deployment, hpa_map)

                        if status != 'OK':
                            has_issues = True

                        if not opts.warn_only or status != 'OK':
                            results.append({
                                'type': 'Deployment',
                                'namespace': namespace,
                                'name': name,
                                'status': status,
                                'issues': issues,
                                'replicas': deployment['spec'].get('replicas', 1),
                                'ready': deployment['status'].get('readyReplicas', 0),
                            })
            except Exception:
                pass

        # Analyze statefulsets
        if not opts.deployments_only:
            try:
                result = context.run(["kubectl", "get", "statefulsets"] + ns_args + ["-o", "json"])
                if result.returncode == 0:
                    statefulsets = json.loads(result.stdout)
                    for statefulset in statefulsets.get('items', []):
                        namespace = statefulset['metadata']['namespace']

                        # Skip if filtering by namespace
                        if opts.namespace and namespace != opts.namespace:
                            continue

                        name = statefulset['metadata']['name']
                        status, issues = analyze_statefulset(statefulset)

                        if status != 'OK':
                            has_issues = True

                        if not opts.warn_only or status != 'OK':
                            results.append({
                                'type': 'StatefulSet',
                                'namespace': namespace,
                                'name': name,
                                'status': status,
                                'issues': issues,
                                'replicas': statefulset['spec'].get('replicas', 1),
                                'ready': statefulset['status'].get('readyReplicas', 0),
                            })
            except Exception:
                pass

        # Analyze resource quotas if not filtering by namespace
        if not opts.namespace:
            try:
                result = context.run(["kubectl", "get", "resourcequotas", "-A", "-o", "json"])
                if result.returncode == 0:
                    quotas = json.loads(result.stdout)
                    for quota in quotas.get('items', []):
                        namespace = quota['metadata']['namespace']
                        name = quota['metadata']['name']
                        status, issues = analyze_resource_quota(quota)

                        if status != 'OK':
                            has_issues = True

                        if not opts.warn_only or status != 'OK':
                            results.append({
                                'type': 'ResourceQuota',
                                'namespace': namespace,
                                'name': name,
                                'status': status,
                                'issues': issues,
                            })
            except Exception:
                pass

    except Exception as e:
        output.error(f"Error gathering pod information: {e}")
        return 2

    # Format and print output
    if opts.format == 'json':
        print_json_output(results)
    elif opts.format == 'table':
        print_table_output(results)
    else:  # plain
        print_plain_output(results)

    # Summary
    ok_count = sum(1 for r in results if r['status'] == 'OK')
    warning_count = sum(1 for r in results if r['status'] == 'WARNING')
    critical_count = sum(1 for r in results if r['status'] == 'CRITICAL')
    output.set_summary(f"total={len(results)}, ok={ok_count}, warning={warning_count}, critical={critical_count}")

    # Exit with appropriate status
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
