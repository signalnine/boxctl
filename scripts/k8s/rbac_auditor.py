#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [rbac, security, audit, permissions]
#   requires: [kubectl]
#   privilege: none
#   related: [serviceaccount_auditor, security_audit]
#   brief: Audit RBAC roles and bindings for security issues

"""
Audit Kubernetes RBAC roles and bindings for security issues.

Analyzes ClusterRoles, Roles, ClusterRoleBindings, and RoleBindings
to identify potentially dangerous permissions, overly permissive access, and
security policy violations.

Checks performed:
- Cluster-admin access detection
- Wildcard permissions (*, get/list/watch on all resources)
- Dangerous verbs (create, delete, deletecollection, exec, proxy)
- Service account bindings to high-privilege roles
- Anonymous user access
- Secrets and ConfigMaps access patterns

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


def get_cluster_roles(context: Context) -> list[dict[str, Any]]:
    """Get all ClusterRoles."""
    result = context.run(['kubectl', 'get', 'clusterroles', '-o', 'json'])
    data = json.loads(result.stdout) if result.stdout else {}
    return data.get('items', [])


def get_roles(context: Context, namespace: str | None = None) -> list[dict[str, Any]]:
    """Get all Roles."""
    cmd = ['kubectl', 'get', 'roles', '-o', 'json']
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


def check_dangerous_permissions(role: dict[str, Any]) -> list[dict[str, Any]]:
    """Check if a role has dangerous permissions."""
    issues = []
    role_name = role['metadata']['name']
    rules = role.get('rules', [])

    for rule in rules:
        verbs = rule.get('verbs', [])
        resources = rule.get('resources', [])
        api_groups = rule.get('apiGroups', [])

        # Check for wildcard permissions
        if '*' in verbs or '*' in resources or '*' in api_groups:
            issues.append({
                'severity': 'HIGH',
                'type': 'wildcard_permissions',
                'role': role_name,
                'detail': f"Wildcard permissions: verbs={verbs}, resources={resources}, apiGroups={api_groups}"
            })

        # Check for dangerous verbs
        dangerous_verbs = {'create', 'delete', 'deletecollection', 'exec', 'proxy', 'impersonate', 'bind', 'escalate'}
        found_dangerous = dangerous_verbs.intersection(set(verbs))
        if found_dangerous and ('*' in resources or 'pods' in resources or 'pods/exec' in resources):
            issues.append({
                'severity': 'MEDIUM',
                'type': 'dangerous_verbs',
                'role': role_name,
                'detail': f"Dangerous verbs: {list(found_dangerous)} on resources: {resources}"
            })

        # Check for secrets/configmaps access
        sensitive_resources = {'secrets', 'configmaps'}
        found_sensitive = sensitive_resources.intersection(set(resources))
        if found_sensitive and ('get' in verbs or 'list' in verbs or '*' in verbs):
            issues.append({
                'severity': 'MEDIUM',
                'type': 'sensitive_resource_access',
                'role': role_name,
                'detail': f"Access to sensitive resources: {list(found_sensitive)} with verbs: {verbs}"
            })

    return issues


def check_bindings(bindings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check RoleBindings or ClusterRoleBindings for security issues."""
    issues = []

    for binding in bindings:
        binding_name = binding['metadata']['name']
        namespace = binding['metadata'].get('namespace', 'cluster-wide')
        role_ref = binding.get('roleRef', {})
        role_name = role_ref.get('name', 'unknown')
        subjects = binding.get('subjects', [])

        # Check for cluster-admin bindings
        if role_name == 'cluster-admin':
            for subject in subjects:
                issues.append({
                    'severity': 'HIGH',
                    'type': 'cluster_admin_binding',
                    'binding': binding_name,
                    'namespace': namespace,
                    'detail': f"cluster-admin bound to {subject.get('kind', 'unknown')}: {subject.get('name', 'unknown')}"
                })

        # Check for anonymous user access
        for subject in subjects:
            if subject.get('name') == 'system:anonymous' or subject.get('name') == 'system:unauthenticated':
                issues.append({
                    'severity': 'HIGH',
                    'type': 'anonymous_access',
                    'binding': binding_name,
                    'namespace': namespace,
                    'detail': f"Anonymous/unauthenticated user bound to role: {role_name}"
                })

            # Check for service account bindings to admin roles
            if subject.get('kind') == 'ServiceAccount' and 'admin' in role_name.lower():
                issues.append({
                    'severity': 'MEDIUM',
                    'type': 'serviceaccount_admin',
                    'binding': binding_name,
                    'namespace': namespace,
                    'detail': f"ServiceAccount {subject.get('name')} bound to admin role: {role_name}"
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
        description='Audit Kubernetes RBAC roles and bindings for security issues'
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
        '--format',
        choices=['plain', 'json'],
        default='plain'
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool('kubectl'):
        output.error('kubectl not found in PATH')
        return 2

    all_issues = []

    try:
        # Audit ClusterRoles
        cluster_roles = get_cluster_roles(context)
        for role in cluster_roles:
            all_issues.extend(check_dangerous_permissions(role))

        # Audit Roles (namespace-specific or all)
        roles = get_roles(context, opts.namespace)
        for role in roles:
            all_issues.extend(check_dangerous_permissions(role))

        # Audit ClusterRoleBindings
        cluster_role_bindings = get_cluster_role_bindings(context)
        all_issues.extend(check_bindings(cluster_role_bindings))

        # Audit RoleBindings
        role_bindings = get_role_bindings(context, opts.namespace)
        all_issues.extend(check_bindings(role_bindings))

    except Exception as e:
        output.error(f'Failed to fetch RBAC data: {e}')
        return 2

    # Group by severity
    by_severity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for issue in all_issues:
        by_severity[issue['severity']].append(issue)

    # Build output
    output.emit({
        'summary': {
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
        output.set_summary(f"{high_count} high, {medium_count} medium severity issues")
    else:
        output.set_summary("No RBAC security issues detected")

    return 1 if all_issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
