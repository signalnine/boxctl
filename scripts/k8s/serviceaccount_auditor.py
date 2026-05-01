#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [serviceaccount, security, audit, rbac]
#   requires: [kubectl]
#   privilege: none
#   related: [rbac_auditor, security_audit]
#   brief: Audit ServiceAccounts for security issues

"""
Audit Kubernetes ServiceAccounts for security issues.

Analyzes ServiceAccounts across the cluster to identify security
misconfigurations, risky automount settings, and unused or default accounts.

Checks performed:
- automountServiceAccountToken enabled (should be explicitly disabled when not needed)
- Default ServiceAccount usage by pods (security anti-pattern)
- ServiceAccounts with no associated pods (potentially stale)
- ServiceAccounts bound to high-privilege roles (cluster-admin, admin)
- ServiceAccounts in kube-system with broad permissions

Exit codes:
    0 - No critical issues detected
    1 - Security issues or warnings found
    2 - Error (kubectl unavailable)
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_serviceaccounts(context: Context, namespace: str | None = None) -> list[dict[str, Any]]:
    """Get all ServiceAccounts."""
    cmd = ['kubectl', 'get', 'serviceaccounts', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    result = context.run(cmd)
    data = json.loads(result.stdout) if result.stdout else {}
    return data.get('items', [])


def get_pods(context: Context, namespace: str | None = None) -> list[dict[str, Any]]:
    """Get all Pods."""
    cmd = ['kubectl', 'get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    result = context.run(cmd)
    data = json.loads(result.stdout) if result.stdout else {}
    return data.get('items', [])


def get_cluster_role_bindings(context: Context) -> list[dict[str, Any]]:
    """Get all ClusterRoleBindings."""
    result = context.run(['kubectl', 'get', 'clusterrolebindings', '-o', 'json'])
    data = json.loads(result.stdout) if result.stdout else {}
    return data.get('items', [])


def get_role_bindings(context: Context, namespace: str | None = None) -> list[dict[str, Any]]:
    """Get all RoleBindings."""
    cmd = ['kubectl', 'get', 'rolebindings', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    result = context.run(cmd)
    data = json.loads(result.stdout) if result.stdout else {}
    return data.get('items', [])


def build_sa_role_map(
    cluster_bindings: list[dict[str, Any]],
    role_bindings: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Build a map of ServiceAccount -> roles they're bound to."""
    sa_roles: dict[str, list[dict[str, Any]]] = defaultdict(list)

    # Process ClusterRoleBindings
    for binding in cluster_bindings:
        role_name = binding.get('roleRef', {}).get('name', 'unknown')
        subjects = binding.get('subjects', [])

        for subject in subjects:
            if subject.get('kind') == 'ServiceAccount':
                sa_namespace = subject.get('namespace', 'default')
                sa_name = subject.get('name', 'unknown')
                sa_key = f"{sa_namespace}/{sa_name}"
                sa_roles[sa_key].append({
                    'role': role_name,
                    'binding_type': 'ClusterRoleBinding',
                    'binding_name': binding['metadata']['name']
                })

    # Process RoleBindings
    for binding in role_bindings:
        role_name = binding.get('roleRef', {}).get('name', 'unknown')
        binding_namespace = binding['metadata'].get('namespace', 'default')
        subjects = binding.get('subjects', [])

        for subject in subjects:
            if subject.get('kind') == 'ServiceAccount':
                sa_namespace = subject.get('namespace', binding_namespace)
                sa_name = subject.get('name', 'unknown')
                sa_key = f"{sa_namespace}/{sa_name}"
                sa_roles[sa_key].append({
                    'role': role_name,
                    'binding_type': 'RoleBinding',
                    'binding_name': binding['metadata']['name'],
                    'binding_namespace': binding_namespace
                })

    return dict(sa_roles)


def build_sa_usage_map(pods: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Build a map of ServiceAccount -> pods using it."""
    sa_pods: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for pod in pods:
        namespace = pod['metadata'].get('namespace', 'default')
        pod_name = pod['metadata'].get('name', 'unknown')
        sa_name = pod['spec'].get('serviceAccountName', 'default')
        sa_key = f"{namespace}/{sa_name}"

        sa_pods[sa_key].append({
            'pod': pod_name,
            'namespace': namespace,
            'automount': pod['spec'].get('automountServiceAccountToken', None)
        })

    return dict(sa_pods)


def check_automount_issues(
    sa: dict[str, Any],
    pods_using_sa: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Check for automountServiceAccountToken security issues."""
    issues = []
    sa_name = sa['metadata']['name']
    sa_namespace = sa['metadata'].get('namespace', 'default')

    # Check SA-level automount setting
    sa_automount = sa.get('automountServiceAccountToken', True)  # Default is True

    if sa_automount is True or sa_automount is None:
        # Check if any pods have automount enabled
        pods_with_automount = [p for p in pods_using_sa if p.get('automount') is not False]

        if pods_with_automount:
            issues.append({
                'severity': 'MEDIUM',
                'type': 'automount_enabled',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"automountServiceAccountToken enabled, {len(pods_with_automount)} pod(s) may have unnecessary token access"
            })

    return issues


def check_default_sa_usage(
    sa: dict[str, Any],
    pods_using_sa: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Check if pods are using the default ServiceAccount."""
    issues = []
    sa_name = sa['metadata']['name']
    sa_namespace = sa['metadata'].get('namespace', 'default')

    if sa_name == 'default' and pods_using_sa:
        # Exclude kube-system default SA used by system pods
        non_system_pods = [p for p in pods_using_sa
                          if not p['pod'].startswith('kube-')]

        if non_system_pods:
            issues.append({
                'severity': 'LOW',
                'type': 'default_sa_usage',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"{len(non_system_pods)} non-system pod(s) using default ServiceAccount"
            })

    return issues


def check_unused_serviceaccounts(
    sa: dict[str, Any],
    pods_using_sa: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Check for ServiceAccounts with no pods using them."""
    issues = []
    sa_name = sa['metadata']['name']
    sa_namespace = sa['metadata'].get('namespace', 'default')

    # Skip built-in ServiceAccounts
    if sa_name in ('default', 'builder', 'deployer'):
        return issues

    # Skip kube-system as it has legitimate unused SAs
    if sa_namespace == 'kube-system':
        return issues

    if not pods_using_sa:
        issues.append({
            'severity': 'LOW',
            'type': 'unused_serviceaccount',
            'serviceaccount': sa_name,
            'namespace': sa_namespace,
            'detail': "ServiceAccount has no pods using it (may be stale)"
        })

    return issues


def check_privileged_bindings(
    sa: dict[str, Any],
    sa_roles: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    """Check if ServiceAccount is bound to high-privilege roles."""
    issues = []
    sa_name = sa['metadata']['name']
    sa_namespace = sa['metadata'].get('namespace', 'default')
    sa_key = f"{sa_namespace}/{sa_name}"

    roles = sa_roles.get(sa_key, [])

    for role_info in roles:
        role_name = role_info['role'].lower()

        # Check for cluster-admin (highest severity)
        if role_name == 'cluster-admin':
            issues.append({
                'severity': 'HIGH',
                'type': 'cluster_admin_binding',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"Bound to cluster-admin via {role_info['binding_type']}: {role_info['binding_name']}"
            })
        # Check for admin roles
        elif 'admin' in role_name:
            issues.append({
                'severity': 'MEDIUM',
                'type': 'admin_role_binding',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"Bound to admin role '{role_info['role']}' via {role_info['binding_type']}"
            })
        # Check for edit role
        elif role_name == 'edit':
            issues.append({
                'severity': 'LOW',
                'type': 'edit_role_binding',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"Bound to edit role via {role_info['binding_type']}"
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
        description='Audit Kubernetes ServiceAccounts for security issues'
    )
    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to audit (default: all namespaces)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )
    parser.add_argument(
        '--skip-unused',
        action='store_true',
        help='Skip checking for unused ServiceAccounts'
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
        # Gather data
        serviceaccounts = get_serviceaccounts(context, opts.namespace)
        pods = get_pods(context, opts.namespace)
        cluster_bindings = get_cluster_role_bindings(context)
        role_bindings = get_role_bindings(context, opts.namespace)

        # Build lookup maps
        sa_roles = build_sa_role_map(cluster_bindings, role_bindings)
        sa_usage = build_sa_usage_map(pods)

    except Exception as e:
        output.error(f'Failed to fetch ServiceAccount data: {e}')
        return 2

    all_issues = []

    # Audit each ServiceAccount
    for sa in serviceaccounts:
        sa_namespace = sa['metadata'].get('namespace', 'default')
        sa_name = sa['metadata']['name']
        sa_key = f"{sa_namespace}/{sa_name}"
        pods_using_sa = sa_usage.get(sa_key, [])

        # Run checks
        all_issues.extend(check_automount_issues(sa, pods_using_sa))
        all_issues.extend(check_default_sa_usage(sa, pods_using_sa))
        all_issues.extend(check_privileged_bindings(sa, sa_roles))

        if not opts.skip_unused:
            all_issues.extend(check_unused_serviceaccounts(sa, pods_using_sa))

    # Group by severity
    by_severity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for issue in all_issues:
        by_severity[issue['severity']].append(issue)

    # Build output
    output.emit({
        'summary': {
            'total_serviceaccounts': len(serviceaccounts),
            'total_issues': len(all_issues),
            'high_severity': len(by_severity.get('HIGH', [])),
            'medium_severity': len(by_severity.get('MEDIUM', [])),
            'low_severity': len(by_severity.get('LOW', [])),
        },
        'issues': all_issues,
        'by_severity': dict(by_severity),
    })

    if all_issues:
        high_count = len(by_severity.get('HIGH', []))
        medium_count = len(by_severity.get('MEDIUM', []))
        output.set_summary(f"{len(serviceaccounts)} SAs, {high_count} high, {medium_count} medium issues")
    else:
        output.set_summary(f"{len(serviceaccounts)} ServiceAccounts, no issues")

    return 1 if all_issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
