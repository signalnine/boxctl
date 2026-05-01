#!/usr/bin/env python3
# boxctl:
#   category: k8s/namespace
#   tags: [resources, capacity, chargeback, governance]
#   requires: [kubectl]
#   privilege: none
#   related: [namespace_resource_summary, pod_resource_audit]
#   brief: Analyze namespace resource utilization for capacity planning

"""
Analyze Kubernetes namespace resource utilization for capacity planning and chargeback.

Provides a comprehensive view of resource consumption by namespace:
- Aggregate CPU and memory requests/limits per namespace
- Pod and container counts by namespace
- Resource quota utilization percentages
- Top resource consumers identification
- Namespaces without resource quotas (governance risk)

Exit codes:
    0 - Analysis completed, no issues
    1 - Issues detected (namespaces without quotas, pods without requests/limits)
    2 - Error (kubectl unavailable)
"""

import argparse
import json
import re
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_resource_value(value: str) -> int:
    """Parse Kubernetes resource values to base units (bytes for memory, millicores for CPU)."""
    if not value:
        return 0

    value = str(value)

    # CPU parsing (to millicores)
    if value.endswith('m'):
        return int(value[:-1])
    elif value.endswith('n'):
        return int(value[:-1]) // 1000000
    elif re.match(r'^[0-9.]+$', value):
        return int(float(value) * 1000)

    # Memory parsing (to bytes)
    multipliers = {
        'Ki': 1024,
        'Mi': 1024 ** 2,
        'Gi': 1024 ** 3,
        'Ti': 1024 ** 4,
        'K': 1000,
        'M': 1000 ** 2,
        'G': 1000 ** 3,
        'T': 1000 ** 4,
    }

    for suffix, multiplier in multipliers.items():
        if value.endswith(suffix):
            return int(float(value[:-len(suffix)]) * multiplier)

    # Plain bytes
    if re.match(r'^[0-9]+$', value):
        return int(value)

    return 0


def format_cpu(millicores: int) -> str:
    """Format millicores for display."""
    if millicores >= 1000:
        return f"{millicores / 1000:.1f}"
    return f"{millicores}m"


def format_memory(bytes_val: int) -> str:
    """Format bytes for display."""
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.1f}Gi"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.1f}Mi"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f}Ki"
    return f"{bytes_val}"


def get_all_pods(context: Context) -> dict[str, Any]:
    """Get all pods across all namespaces."""
    result = context.run(['kubectl', 'get', 'pods', '--all-namespaces', '-o', 'json'])
    return json.loads(result.stdout)


def get_resource_quotas(context: Context) -> dict[str, Any]:
    """Get all resource quotas."""
    result = context.run(['kubectl', 'get', 'resourcequota', '--all-namespaces', '-o', 'json'])
    return json.loads(result.stdout)


def get_namespaces(context: Context) -> dict[str, Any]:
    """Get all namespaces."""
    result = context.run(['kubectl', 'get', 'namespaces', '-o', 'json'])
    return json.loads(result.stdout)


def analyze_namespace_resources(
    pods_data: dict[str, Any],
    quotas_data: dict[str, Any],
    namespaces_data: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Analyze resource utilization by namespace."""
    ns_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {
        'cpu_requests': 0,
        'cpu_limits': 0,
        'memory_requests': 0,
        'memory_limits': 0,
        'pod_count': 0,
        'container_count': 0,
        'running_pods': 0,
        'has_quota': False,
        'quota_cpu_used': 0,
        'quota_cpu_hard': 0,
        'quota_memory_used': 0,
        'quota_memory_hard': 0,
        'pods_without_requests': 0,
        'pods_without_limits': 0,
    })

    # Initialize all namespaces
    for ns in namespaces_data.get('items', []):
        ns_name = ns['metadata']['name']
        ns_stats[ns_name]  # Initialize entry

    # Process pods
    for pod in pods_data.get('items', []):
        namespace = pod['metadata'].get('namespace', 'default')
        phase = pod.get('status', {}).get('phase', 'Unknown')

        ns_stats[namespace]['pod_count'] += 1
        if phase == 'Running':
            ns_stats[namespace]['running_pods'] += 1

        has_requests = False
        has_limits = False

        for container in pod.get('spec', {}).get('containers', []):
            ns_stats[namespace]['container_count'] += 1

            resources = container.get('resources', {})
            requests = resources.get('requests', {})
            limits = resources.get('limits', {})

            if requests:
                has_requests = True
                ns_stats[namespace]['cpu_requests'] += parse_resource_value(requests.get('cpu', '0'))
                ns_stats[namespace]['memory_requests'] += parse_resource_value(requests.get('memory', '0'))

            if limits:
                has_limits = True
                ns_stats[namespace]['cpu_limits'] += parse_resource_value(limits.get('cpu', '0'))
                ns_stats[namespace]['memory_limits'] += parse_resource_value(limits.get('memory', '0'))

        if not has_requests:
            ns_stats[namespace]['pods_without_requests'] += 1
        if not has_limits:
            ns_stats[namespace]['pods_without_limits'] += 1

    # Process quotas
    for quota in quotas_data.get('items', []):
        namespace = quota['metadata'].get('namespace', 'default')
        ns_stats[namespace]['has_quota'] = True

        status = quota.get('status', {})
        hard = status.get('hard', {})
        used = status.get('used', {})

        # CPU quota
        for key in ['requests.cpu', 'cpu']:
            if key in hard:
                ns_stats[namespace]['quota_cpu_hard'] = parse_resource_value(hard[key])
                ns_stats[namespace]['quota_cpu_used'] = parse_resource_value(used.get(key, '0'))
                break

        # Memory quota
        for key in ['requests.memory', 'memory']:
            if key in hard:
                ns_stats[namespace]['quota_memory_hard'] = parse_resource_value(hard[key])
                ns_stats[namespace]['quota_memory_used'] = parse_resource_value(used.get(key, '0'))
                break

    return dict(ns_stats)


def calculate_cluster_totals(ns_stats: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Calculate cluster-wide totals."""
    totals = {
        'cpu_requests': 0,
        'cpu_limits': 0,
        'memory_requests': 0,
        'memory_limits': 0,
        'pod_count': 0,
        'container_count': 0,
        'running_pods': 0,
        'namespaces_with_quota': 0,
        'namespaces_without_quota': 0,
    }

    for stats in ns_stats.values():
        totals['cpu_requests'] += stats['cpu_requests']
        totals['cpu_limits'] += stats['cpu_limits']
        totals['memory_requests'] += stats['memory_requests']
        totals['memory_limits'] += stats['memory_limits']
        totals['pod_count'] += stats['pod_count']
        totals['container_count'] += stats['container_count']
        totals['running_pods'] += stats['running_pods']

        if stats['has_quota']:
            totals['namespaces_with_quota'] += 1
        elif stats['pod_count'] > 0:
            totals['namespaces_without_quota'] += 1

    return totals


def find_issues(ns_stats: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Find governance issues in namespaces."""
    issues = []

    for namespace, stats in ns_stats.items():
        if stats['pod_count'] == 0:
            continue

        if not stats['has_quota']:
            issues.append({
                'namespace': namespace,
                'type': 'no_quota',
                'message': 'Namespace has no resource quota',
            })

        if stats['pods_without_requests'] > 0:
            issues.append({
                'namespace': namespace,
                'type': 'missing_requests',
                'message': f"{stats['pods_without_requests']} pod(s) without resource requests",
            })

        if stats['pods_without_limits'] > 0:
            issues.append({
                'namespace': namespace,
                'type': 'missing_limits',
                'message': f"{stats['pods_without_limits']} pod(s) without resource limits",
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
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes namespace resource utilization'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show additional details'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show namespaces with issues'
    )
    parser.add_argument(
        '-t', '--top',
        type=int,
        metavar='N',
        help='Show only top N namespaces by CPU requests'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json'],
        default='plain'
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool('kubectl'):
        output.error('kubectl not found in PATH')
        return 2

    try:
        pods_data = get_all_pods(context)
        quotas_data = get_resource_quotas(context)
        namespaces_data = get_namespaces(context)
    except Exception as e:
        output.error(f'Failed to fetch cluster data: {e}')
        return 2

    # Analyze
    ns_stats = analyze_namespace_resources(pods_data, quotas_data, namespaces_data)
    totals = calculate_cluster_totals(ns_stats)
    issues = find_issues(ns_stats)

    # Build output data
    namespaces_output = []
    sorted_ns = sorted(
        ns_stats.items(),
        key=lambda x: x[1]['cpu_requests'],
        reverse=True
    )

    if opts.top and opts.top > 0:
        sorted_ns = sorted_ns[:opts.top]

    for namespace, stats in sorted_ns:
        if not opts.verbose and stats['pod_count'] == 0:
            continue

        ns_issues = [i for i in issues if i['namespace'] == namespace]
        if opts.warn_only and not ns_issues:
            continue

        cpu_pct = 0.0
        memory_pct = 0.0
        if totals['cpu_requests'] > 0:
            cpu_pct = (stats['cpu_requests'] / totals['cpu_requests']) * 100
        if totals['memory_requests'] > 0:
            memory_pct = (stats['memory_requests'] / totals['memory_requests']) * 100

        ns_data = {
            'namespace': namespace,
            'pod_count': stats['pod_count'],
            'running_pods': stats['running_pods'],
            'container_count': stats['container_count'],
            'cpu_requests_millicores': stats['cpu_requests'],
            'cpu_requests_display': format_cpu(stats['cpu_requests']),
            'cpu_percent': round(cpu_pct, 1),
            'memory_requests_bytes': stats['memory_requests'],
            'memory_requests_display': format_memory(stats['memory_requests']),
            'memory_percent': round(memory_pct, 1),
            'has_quota': stats['has_quota'],
            'issues': [i['message'] for i in ns_issues],
        }

        if opts.verbose:
            ns_data['cpu_limits_millicores'] = stats['cpu_limits']
            ns_data['cpu_limits_display'] = format_cpu(stats['cpu_limits'])
            ns_data['memory_limits_bytes'] = stats['memory_limits']
            ns_data['memory_limits_display'] = format_memory(stats['memory_limits'])

        if stats['has_quota']:
            if stats['quota_cpu_hard'] > 0:
                ns_data['quota_cpu_used'] = stats['quota_cpu_used']
                ns_data['quota_cpu_hard'] = stats['quota_cpu_hard']
            if stats['quota_memory_hard'] > 0:
                ns_data['quota_memory_used'] = stats['quota_memory_used']
                ns_data['quota_memory_hard'] = stats['quota_memory_hard']

        namespaces_output.append(ns_data)

    output.emit({
        'namespaces': namespaces_output,
        'cluster_totals': {
            'namespace_count': len(ns_stats),
            'pod_count': totals['pod_count'],
            'running_pods': totals['running_pods'],
            'container_count': totals['container_count'],
            'cpu_requests_millicores': totals['cpu_requests'],
            'cpu_requests_display': format_cpu(totals['cpu_requests']),
            'memory_requests_bytes': totals['memory_requests'],
            'memory_requests_display': format_memory(totals['memory_requests']),
            'namespaces_with_quota': totals['namespaces_with_quota'],
            'namespaces_without_quota': totals['namespaces_without_quota'],
        },
        'issues': issues,
    })

    # Set summary
    output.set_summary(
        f"{len(ns_stats)} namespaces, {totals['pod_count']} pods, {len(issues)} issues"
    )

    return 1 if issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
