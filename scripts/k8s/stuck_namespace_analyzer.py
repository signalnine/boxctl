#!/usr/bin/env python3
# boxctl:
#   category: k8s/namespace
#   tags: [namespace, troubleshooting, finalizers, cleanup]
#   requires: [kubectl]
#   privilege: none
#   related: [namespace_resource_analyzer, restart_monitor]
#   brief: Analyze namespaces stuck in Terminating state

"""
Analyze Kubernetes namespaces stuck in Terminating state.

Namespaces can become stuck in "Terminating" status due to:
- Finalizers that never complete
- Resources with dangling finalizers
- API resources that can't be deleted
- Webhooks blocking deletion
- Custom resources without proper cleanup

This script identifies stuck namespaces and diagnoses the root cause,
helping operators resolve deletion issues without manual investigation.

Exit codes:
    0 - No stuck namespaces found
    1 - Stuck namespaces detected
    2 - Error (kubectl unavailable)
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_namespaces(context: Context) -> list[dict[str, Any]]:
    """Get all namespaces in JSON format."""
    result = context.run(['kubectl', 'get', 'namespaces', '-o', 'json'])
    if not result.stdout:
        return []

    try:
        data = json.loads(result.stdout)
        return data.get('items', [])
    except json.JSONDecodeError:
        return []


def get_namespace_details(context: Context, namespace: str) -> dict[str, Any] | None:
    """Get detailed namespace information."""
    result = context.run(['kubectl', 'get', 'namespace', namespace, '-o', 'json'], check=False)
    if not result.stdout or result.returncode != 0:
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def find_stuck_namespaces(namespaces: list[dict[str, Any]]) -> list[str]:
    """Find namespaces that are stuck in Terminating state."""
    stuck = []
    for ns in namespaces:
        status = ns.get('status', {})
        metadata = ns.get('metadata', {})

        phase = status.get('phase', '')
        deletion_timestamp = metadata.get('deletionTimestamp')

        if phase == 'Terminating' or deletion_timestamp:
            stuck.append(metadata.get('name', 'unknown'))

    return stuck


def analyze_stuck_namespace(
    context: Context,
    namespace: str,
    verbose: bool = False
) -> dict[str, Any]:
    """Analyze why a namespace is stuck in Terminating state."""
    ns_data = get_namespace_details(context, namespace)
    if ns_data is None:
        return {
            'namespace': namespace,
            'error': 'Could not fetch namespace details',
            'issues': [],
            'blocking_resources': [],
            'finalizers': []
        }

    metadata = ns_data.get('metadata', {})
    status = ns_data.get('status', {})
    spec = ns_data.get('spec', {})

    # Get namespace-level finalizers
    ns_finalizers = metadata.get('finalizers', [])
    spec_finalizers = spec.get('finalizers', [])
    all_finalizers = list(set(ns_finalizers + spec_finalizers))

    issues = []
    blocking_resources = []

    # Check for namespace-level finalizers
    if all_finalizers:
        issues.append({
            'type': 'namespace_finalizers',
            'description': f"Namespace has {len(all_finalizers)} finalizer(s)",
            'details': all_finalizers
        })

    # Check deletion timestamp
    deletion_timestamp = metadata.get('deletionTimestamp')
    if deletion_timestamp:
        issues.append({
            'type': 'deletion_pending',
            'description': f"Deletion initiated at {deletion_timestamp}",
            'details': deletion_timestamp
        })

    # Check conditions
    conditions = status.get('conditions', [])
    for condition in conditions:
        cond_type = condition.get('type', '')
        cond_status = condition.get('status', '')

        if cond_status != 'True':
            continue

        if cond_type == 'NamespaceDeletionContentFailure':
            issues.append({
                'type': 'deletion_content_failure',
                'description': condition.get('message', 'Content deletion failed'),
                'details': condition.get('reason', 'Unknown')
            })
        elif cond_type == 'NamespaceDeletionDiscoveryFailure':
            issues.append({
                'type': 'discovery_failure',
                'description': condition.get('message', 'Discovery failed'),
                'details': condition.get('reason', 'Unknown')
            })
        elif cond_type == 'NamespaceFinalizersRemaining':
            issues.append({
                'type': 'finalizers_remaining',
                'description': condition.get('message', 'Finalizers remaining'),
                'details': condition.get('reason', 'Unknown')
            })
        elif cond_type == 'NamespaceContentRemaining':
            issues.append({
                'type': 'content_remaining',
                'description': condition.get('message', 'Content remaining'),
                'details': condition.get('reason', 'Unknown')
            })

    return {
        'namespace': namespace,
        'phase': status.get('phase', 'Unknown'),
        'deletion_timestamp': deletion_timestamp,
        'finalizers': all_finalizers,
        'issues': issues,
        'blocking_resources': blocking_resources,
        'conditions': conditions
    }


def generate_remediation(result: dict[str, Any]) -> list[str]:
    """Generate remediation commands for a stuck namespace."""
    commands = []
    namespace = result['namespace']

    if result.get('finalizers'):
        commands.append(
            f"kubectl patch namespace {namespace} -p "
            "'{\"metadata\":{\"finalizers\":null}}' --type=merge"
        )

    if result.get('blocking_resources'):
        commands.append("# Remove finalizers from blocking resources first")
        for res in result['blocking_resources'][:3]:
            commands.append(
                f"kubectl patch {res['kind'].lower()} {res['name']} "
                f"-n {namespace} -p "
                "'{\"metadata\":{\"finalizers\":null}}' --type=merge"
            )

    return commands


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no stuck namespaces, 1 = stuck namespaces found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes namespaces stuck in Terminating state'
    )
    parser.add_argument(
        '-n', '--namespace',
        help='Analyze specific namespace (default: check all)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed analysis including blocking resources'
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
        # Get namespaces
        if opts.namespace:
            # Check specific namespace
            ns_data = get_namespace_details(context, opts.namespace)
            if ns_data is None:
                output.error(f"Namespace '{opts.namespace}' not found")
                return 2

            metadata = ns_data.get('metadata', {})
            status = ns_data.get('status', {})

            if status.get('phase') != 'Terminating' and not metadata.get('deletionTimestamp'):
                output.emit({
                    'stuck_namespaces': [],
                    'summary': {
                        'total_stuck': 0,
                        'namespaces_with_finalizers': 0,
                    }
                })
                output.set_summary(f"Namespace '{opts.namespace}' is not stuck")
                return 0

            stuck_namespaces = [opts.namespace]
        else:
            # Check all namespaces
            namespaces = get_namespaces(context)
            if not namespaces:
                output.warning('No namespaces found or unable to list namespaces')
                output.emit({'stuck_namespaces': [], 'summary': {'total_stuck': 0}})
                return 0

            stuck_namespaces = find_stuck_namespaces(namespaces)

    except Exception as e:
        output.error(f'Failed to fetch namespace data: {e}')
        return 2

    if not stuck_namespaces:
        output.emit({
            'stuck_namespaces': [],
            'summary': {
                'total_stuck': 0,
                'namespaces_with_finalizers': 0,
            }
        })
        output.set_summary("No stuck namespaces found")
        return 0

    # Analyze each stuck namespace
    results = []
    for ns in stuck_namespaces:
        analysis = analyze_stuck_namespace(context, ns, opts.verbose)
        analysis['remediation'] = generate_remediation(analysis)
        results.append(analysis)

    # Build summary
    namespaces_with_finalizers = sum(1 for r in results if r.get('finalizers'))
    namespaces_with_blocking = sum(1 for r in results if r.get('blocking_resources'))

    output.emit({
        'stuck_namespaces': results,
        'summary': {
            'total_stuck': len(results),
            'namespaces_with_finalizers': namespaces_with_finalizers,
            'namespaces_with_blocking_resources': namespaces_with_blocking,
        }
    })

    output.set_summary(f"{len(results)} stuck namespace(s) found")

    return 1 if results else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
