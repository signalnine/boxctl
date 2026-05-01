#!/usr/bin/env python3
# boxctl:
#   category: k8s/namespace
#   tags: [resources, capacity, cost, efficiency]
#   requires: [kubectl]
#   privilege: none
#   related: [namespace_resource_analyzer, pod_resource_audit]
#   brief: Summarize namespace resource allocation and usage

"""
Summarize Kubernetes resource allocation and usage by namespace.

Provides a namespace-level view of resource requests, limits, and actual usage
for capacity planning, cost attribution, and identifying over/under-provisioned
namespaces in multi-tenant clusters.

Features:
- Aggregates CPU and memory requests/limits per namespace
- Calculates request-to-limit ratios
- Identifies namespaces with high overprovisioning
- Supports filtering and sorting options

Exit codes:
    0 - Summary generated successfully
    1 - Issues detected (overprovisioned namespaces)
    2 - Error (kubectl unavailable)
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_resource_value(value: str, resource_type: str) -> int:
    """
    Parse Kubernetes resource value to a normalized number.

    CPU: millicores (1000m = 1 core)
    Memory: bytes
    """
    if not value:
        return 0

    value = str(value).strip()

    if resource_type == 'cpu':
        # CPU in millicores
        if value.endswith('m'):
            return int(value[:-1])
        elif value.endswith('n'):
            # nanocores
            return int(value[:-1]) // 1000000
        else:
            # whole cores
            return int(float(value) * 1000)

    elif resource_type == 'memory':
        # Memory in bytes
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

        for suffix, mult in multipliers.items():
            if value.endswith(suffix):
                return int(float(value[:-len(suffix)]) * mult)

        # Plain bytes
        return int(value)

    return 0


def format_cpu(millicores: int) -> str:
    """Format CPU millicores for display."""
    if millicores >= 1000:
        return f"{millicores / 1000:.2f}"
    else:
        return f"{millicores}m"


def format_memory(bytes_val: int) -> str:
    """Format memory bytes for display."""
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.2f}Gi"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.2f}Mi"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.2f}Ki"
    else:
        return f"{bytes_val}B"


def get_all_pods(context: Context) -> dict[str, Any]:
    """Get all pods in JSON format."""
    result = context.run(['kubectl', 'get', 'pods', '--all-namespaces', '-o', 'json'])
    return json.loads(result.stdout)


def aggregate_namespace_resources(pods_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Aggregate resource requests, limits by namespace.

    Returns dict keyed by namespace with aggregated values.
    """
    namespaces: dict[str, dict[str, Any]] = defaultdict(lambda: {
        'pod_count': 0,
        'container_count': 0,
        'cpu_requests': 0,
        'cpu_limits': 0,
        'memory_requests': 0,
        'memory_limits': 0,
    })

    pods = pods_data.get('items', [])

    for pod in pods:
        namespace = pod['metadata'].get('namespace', 'default')
        phase = pod.get('status', {}).get('phase', '')

        # Skip completed/failed pods
        if phase in ['Succeeded', 'Failed']:
            continue

        namespaces[namespace]['pod_count'] += 1

        # Aggregate container resources
        containers = pod.get('spec', {}).get('containers', [])
        for container in containers:
            namespaces[namespace]['container_count'] += 1

            resources = container.get('resources', {})
            requests = resources.get('requests', {})
            limits = resources.get('limits', {})

            # CPU
            namespaces[namespace]['cpu_requests'] += parse_resource_value(
                requests.get('cpu', '0'), 'cpu'
            )
            namespaces[namespace]['cpu_limits'] += parse_resource_value(
                limits.get('cpu', '0'), 'cpu'
            )

            # Memory
            namespaces[namespace]['memory_requests'] += parse_resource_value(
                requests.get('memory', '0'), 'memory'
            )
            namespaces[namespace]['memory_limits'] += parse_resource_value(
                limits.get('memory', '0'), 'memory'
            )

    return dict(namespaces)


def calculate_efficiency(ns_data: dict[str, Any]) -> dict[str, float]:
    """Calculate efficiency metrics for a namespace."""
    # Request to limit ratio
    cpu_req_limit_ratio = 0.0
    if ns_data['cpu_limits'] > 0:
        cpu_req_limit_ratio = (ns_data['cpu_requests'] / ns_data['cpu_limits']) * 100

    memory_req_limit_ratio = 0.0
    if ns_data['memory_limits'] > 0:
        memory_req_limit_ratio = (ns_data['memory_requests'] / ns_data['memory_limits']) * 100

    return {
        'cpu_req_limit_ratio': round(cpu_req_limit_ratio, 1),
        'memory_req_limit_ratio': round(memory_req_limit_ratio, 1),
    }


def analyze_namespaces(
    ns_data: dict[str, dict[str, Any]],
    req_limit_threshold: float
) -> list[dict[str, Any]]:
    """
    Analyze namespaces and identify issues.

    Returns list of issues found.
    """
    issues = []

    for namespace, data in ns_data.items():
        if data['pod_count'] == 0:
            continue

        efficiency = calculate_efficiency(data)

        # Check for low request-to-limit ratio (over-requesting)
        if data['cpu_limits'] > 0 and efficiency['cpu_req_limit_ratio'] < req_limit_threshold:
            if data['cpu_requests'] > 500:  # Only flag if meaningful requests
                issues.append({
                    'namespace': namespace,
                    'type': 'cpu_overcommit_potential',
                    'message': f"CPU request/limit ratio only {efficiency['cpu_req_limit_ratio']}%",
                })

        if data['memory_limits'] > 0 and efficiency['memory_req_limit_ratio'] < req_limit_threshold:
            if data['memory_requests'] > 100 * 1024 * 1024:  # 100Mi threshold
                issues.append({
                    'namespace': namespace,
                    'type': 'memory_overcommit_potential',
                    'message': f"Memory request/limit ratio only {efficiency['memory_req_limit_ratio']}%",
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
        description='Summarize Kubernetes resource allocation by namespace'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed efficiency metrics'
    )
    parser.add_argument(
        '-a', '--all',
        action='store_true',
        dest='show_all',
        help='Include system namespaces'
    )
    parser.add_argument(
        '-s', '--sort',
        choices=['name', 'cpu', 'memory', 'pods'],
        default='cpu',
        help='Sort order (default: cpu)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if there are warnings'
    )
    parser.add_argument(
        '--req-limit-threshold',
        type=float,
        default=25.0,
        help='Request/limit ratio threshold for warnings (default: 25%%)'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json'],
        default='plain'
    )
    opts = parser.parse_args(args)

    # Validate threshold
    if opts.req_limit_threshold <= 0 or opts.req_limit_threshold > 100:
        output.error('--req-limit-threshold must be between 0 and 100')
        return 2

    # Check for kubectl
    if not context.check_tool('kubectl'):
        output.error('kubectl not found in PATH')
        return 2

    try:
        pods_data = get_all_pods(context)
    except Exception as e:
        output.error(f'Failed to fetch pod data: {e}')
        return 2

    # Aggregate by namespace
    ns_data = aggregate_namespace_resources(pods_data)

    if not ns_data:
        output.warning('No pods found in cluster')
        output.emit({'namespaces': [], 'cluster_totals': {}})
        return 0

    # Analyze for issues
    issues = analyze_namespaces(ns_data, opts.req_limit_threshold)

    # Handle warn-only mode
    if opts.warn_only and not issues:
        return 0

    # Sort namespaces
    sorted_ns = list(ns_data.items())
    if opts.sort == 'cpu':
        sorted_ns.sort(key=lambda x: x[1]['cpu_requests'], reverse=True)
    elif opts.sort == 'memory':
        sorted_ns.sort(key=lambda x: x[1]['memory_requests'], reverse=True)
    elif opts.sort == 'pods':
        sorted_ns.sort(key=lambda x: x[1]['pod_count'], reverse=True)
    else:
        sorted_ns.sort(key=lambda x: x[0])

    # Filter system namespaces if not showing all
    system_ns = {'kube-system', 'kube-public', 'kube-node-lease'}
    if not opts.show_all:
        sorted_ns = [(ns, data) for ns, data in sorted_ns if ns not in system_ns]

    # Build output
    namespaces_output = []
    for namespace, data in sorted_ns:
        if data['pod_count'] == 0:
            continue

        efficiency = calculate_efficiency(data)
        ns_issues = [i for i in issues if i['namespace'] == namespace]

        ns_output = {
            'namespace': namespace,
            'pod_count': data['pod_count'],
            'container_count': data['container_count'],
            'cpu_requests_millicores': data['cpu_requests'],
            'cpu_requests_display': format_cpu(data['cpu_requests']),
            'cpu_limits_millicores': data['cpu_limits'],
            'cpu_limits_display': format_cpu(data['cpu_limits']),
            'memory_requests_bytes': data['memory_requests'],
            'memory_requests_display': format_memory(data['memory_requests']),
            'memory_limits_bytes': data['memory_limits'],
            'memory_limits_display': format_memory(data['memory_limits']),
        }

        if opts.verbose:
            ns_output['cpu_req_limit_ratio'] = efficiency['cpu_req_limit_ratio']
            ns_output['memory_req_limit_ratio'] = efficiency['memory_req_limit_ratio']

        if ns_issues:
            ns_output['issues'] = [i['message'] for i in ns_issues]

        namespaces_output.append(ns_output)

    # Calculate totals
    total_pods = sum(d['pod_count'] for d in ns_data.values())
    total_containers = sum(d['container_count'] for d in ns_data.values())
    total_cpu_req = sum(d['cpu_requests'] for d in ns_data.values())
    total_cpu_lim = sum(d['cpu_limits'] for d in ns_data.values())
    total_mem_req = sum(d['memory_requests'] for d in ns_data.values())
    total_mem_lim = sum(d['memory_limits'] for d in ns_data.values())

    output.emit({
        'namespaces': namespaces_output,
        'cluster_totals': {
            'namespace_count': len(ns_data),
            'pod_count': total_pods,
            'container_count': total_containers,
            'cpu_requests_millicores': total_cpu_req,
            'cpu_requests_display': format_cpu(total_cpu_req),
            'cpu_limits_millicores': total_cpu_lim,
            'cpu_limits_display': format_cpu(total_cpu_lim),
            'memory_requests_bytes': total_mem_req,
            'memory_requests_display': format_memory(total_mem_req),
            'memory_limits_bytes': total_mem_lim,
            'memory_limits_display': format_memory(total_mem_lim),
        },
        'issues': issues,
    })

    output.set_summary(f"{len(ns_data)} namespaces, {total_pods} pods")

    return 1 if issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
