#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [lifecycle, hooks, prestop, poststart, graceful, kubernetes]
#   requires: [kubectl]
#   brief: Analyze pod lifecycle hook configurations
#   privilege: user
#   related: [pdb_coverage, node_drain_readiness]

"""
Kubernetes Pod Lifecycle Hook Analyzer

Analyzes pod lifecycle hook configurations to identify issues affecting
graceful shutdown and startup behavior:
- Missing preStop hooks on stateful workloads
- preStop hook timeout vs terminationGracePeriodSeconds mismatches
- postStart hook failures blocking pod startup
- Lifecycle hook configuration issues

For large-scale Kubernetes environments, proper lifecycle hook configuration
is critical for graceful node drains, rolling updates, and data integrity.

Exit codes:
    0 - All pods have properly configured lifecycle hooks
    1 - Lifecycle hook issues detected
    2 - Usage error or kubectl not found
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


# Default thresholds
DEFAULT_THRESHOLDS = {
    'min_grace_period': 30,        # Minimum terminationGracePeriodSeconds
    'prestop_buffer': 5,           # Seconds buffer between preStop and grace period
}

# System namespaces often excluded from audits
SYSTEM_NAMESPACES = {'kube-system', 'kube-public', 'kube-node-lease'}

# Workload types that typically need preStop hooks
STATEFUL_ANNOTATIONS = [
    'statefulset.kubernetes.io/pod-name',
]

STATEFUL_LABELS = [
    'app.kubernetes.io/component',
    'statefulset.kubernetes.io/pod-name',
]


def is_stateful_workload(pod: dict) -> bool:
    """Determine if a pod is likely a stateful workload needing preStop hooks."""
    metadata = pod.get('metadata', {})
    labels = metadata.get('labels', {})
    annotations = metadata.get('annotations', {})
    owner_refs = metadata.get('ownerReferences', [])

    # Check if owned by StatefulSet
    for ref in owner_refs:
        if ref.get('kind') == 'StatefulSet':
            return True

    # Check for stateful-related labels/annotations
    for label in STATEFUL_LABELS:
        if label in labels:
            return True

    for annotation in STATEFUL_ANNOTATIONS:
        if annotation in annotations:
            return True

    # Check for PVC mounts (indicates stateful workload)
    spec = pod.get('spec', {})
    volumes = spec.get('volumes', [])
    for vol in volumes:
        if vol.get('persistentVolumeClaim'):
            return True

    return False


def analyze_lifecycle_hook(hook: dict, hook_type: str) -> list:
    """Analyze a single lifecycle hook configuration."""
    issues = []

    if not hook:
        return issues

    # Check exec hooks
    exec_hook = hook.get('exec')
    if exec_hook:
        command = exec_hook.get('command', [])
        if not command:
            issues.append({
                'severity': 'HIGH',
                'type': f'{hook_type}_empty_exec',
                'detail': f'{hook_type} exec hook has empty command',
                'recommendation': 'Specify a command for the exec hook'
            })
        elif 'sleep' in ' '.join(str(c) for c in command).lower():
            # sleep in preStop is a common pattern, but check duration
            for i, arg in enumerate(command):
                if arg == 'sleep' and i + 1 < len(command):
                    try:
                        sleep_duration = int(command[i + 1])
                        if sleep_duration > 60:
                            issues.append({
                                'severity': 'MEDIUM',
                                'type': f'{hook_type}_long_sleep',
                                'detail': f'{hook_type} has long sleep ({sleep_duration}s)',
                                'recommendation': 'Ensure sleep duration is within terminationGracePeriodSeconds'
                            })
                    except (ValueError, IndexError):
                        pass

    # Check httpGet hooks
    http_hook = hook.get('httpGet')
    if http_hook:
        if not http_hook.get('path'):
            issues.append({
                'severity': 'MEDIUM',
                'type': f'{hook_type}_no_path',
                'detail': f'{hook_type} HTTP hook has no path specified',
                'recommendation': 'Specify a path for the HTTP hook'
            })
        if not http_hook.get('port'):
            issues.append({
                'severity': 'HIGH',
                'type': f'{hook_type}_no_port',
                'detail': f'{hook_type} HTTP hook has no port specified',
                'recommendation': 'Specify a port for the HTTP hook'
            })

    # Check tcpSocket hooks
    tcp_hook = hook.get('tcpSocket')
    if tcp_hook:
        if not tcp_hook.get('port'):
            issues.append({
                'severity': 'HIGH',
                'type': f'{hook_type}_no_port',
                'detail': f'{hook_type} TCP hook has no port specified',
                'recommendation': 'Specify a port for the TCP hook'
            })

    return issues


def analyze_container_lifecycle(container: dict, pod_name: str, namespace: str,
                                  grace_period: int, is_stateful: bool) -> list:
    """Analyze lifecycle hooks for a single container."""
    issues = []
    container_name = container.get('name', 'unknown')
    lifecycle = container.get('lifecycle', {})

    pre_stop = lifecycle.get('preStop')
    post_start = lifecycle.get('postStart')

    # Check for missing preStop on stateful workloads
    if is_stateful and not pre_stop:
        issues.append({
            'severity': 'HIGH',
            'type': 'missing_prestop_stateful',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'Stateful workload missing preStop hook',
            'recommendation': 'Add preStop hook for graceful shutdown and data sync'
        })

    # Check for missing preStop with PVC mounts
    volume_mounts = container.get('volumeMounts', [])
    has_pvc_mount = any(vm.get('name', '').startswith('pvc-') or
                        'data' in vm.get('name', '').lower()
                        for vm in volume_mounts)

    if has_pvc_mount and not pre_stop:
        issues.append({
            'severity': 'MEDIUM',
            'type': 'missing_prestop_pvc',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'Container with data volume missing preStop hook',
            'recommendation': 'Add preStop hook to flush data before termination'
        })

    # Analyze preStop hook configuration
    if pre_stop:
        hook_issues = analyze_lifecycle_hook(pre_stop, 'preStop')
        for issue in hook_issues:
            issue['namespace'] = namespace
            issue['pod'] = pod_name
            issue['container'] = container_name
            issues.append(issue)

        # Check preStop vs grace period timing
        exec_hook = pre_stop.get('exec')
        if exec_hook:
            command = exec_hook.get('command', [])
            cmd_str = ' '.join(str(c) for c in command)

            # Detect potential timeout issues
            if 'sleep' in cmd_str:
                for i, arg in enumerate(command):
                    if arg == 'sleep' and i + 1 < len(command):
                        try:
                            sleep_duration = int(command[i + 1])
                            if sleep_duration >= grace_period:
                                issues.append({
                                    'severity': 'HIGH',
                                    'type': 'prestop_exceeds_grace',
                                    'namespace': namespace,
                                    'pod': pod_name,
                                    'container': container_name,
                                    'detail': f'preStop sleep ({sleep_duration}s) >= grace period ({grace_period}s)',
                                    'recommendation': 'Increase terminationGracePeriodSeconds or reduce preStop duration'
                                })
                            elif sleep_duration > grace_period - DEFAULT_THRESHOLDS['prestop_buffer']:
                                issues.append({
                                    'severity': 'MEDIUM',
                                    'type': 'prestop_near_grace',
                                    'namespace': namespace,
                                    'pod': pod_name,
                                    'container': container_name,
                                    'detail': f'preStop sleep ({sleep_duration}s) close to grace period ({grace_period}s)',
                                    'recommendation': 'Add buffer between preStop duration and terminationGracePeriodSeconds'
                                })
                        except (ValueError, IndexError):
                            pass

    # Analyze postStart hook configuration
    if post_start:
        hook_issues = analyze_lifecycle_hook(post_start, 'postStart')
        for issue in hook_issues:
            issue['namespace'] = namespace
            issue['pod'] = pod_name
            issue['container'] = container_name
            issues.append(issue)

    # Check for low terminationGracePeriodSeconds
    if grace_period < DEFAULT_THRESHOLDS['min_grace_period']:
        if is_stateful or has_pvc_mount:
            issues.append({
                'severity': 'MEDIUM',
                'type': 'low_grace_period',
                'namespace': namespace,
                'pod': pod_name,
                'container': container_name,
                'detail': f'Low terminationGracePeriodSeconds ({grace_period}s) for stateful workload',
                'recommendation': 'Increase terminationGracePeriodSeconds for proper graceful shutdown'
            })

    return issues


def analyze_pod_lifecycle(pod: dict, exclude_system: bool = True) -> list:
    """Analyze lifecycle hook configurations for a pod."""
    issues = []
    metadata = pod.get('metadata', {})
    pod_name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    spec = pod.get('spec', {})
    status = pod.get('status', {})

    # Skip system namespaces if requested
    if exclude_system and namespace in SYSTEM_NAMESPACES:
        return issues

    # Skip completed pods
    phase = status.get('phase', '')
    if phase in ('Succeeded', 'Failed'):
        return issues

    # Get termination grace period
    grace_period = spec.get('terminationGracePeriodSeconds', 30)

    # Determine if stateful
    is_stateful = is_stateful_workload(pod)

    # Analyze each container
    containers = spec.get('containers', [])
    for container in containers:
        issues.extend(analyze_container_lifecycle(
            container, pod_name, namespace, grace_period, is_stateful
        ))

    return issues


def output_plain(all_issues: list, verbose: bool = False, warn_only: bool = False) -> None:
    """Output results in plain text format."""
    if not all_issues:
        print("All pods have properly configured lifecycle hooks")
        return

    # Group by severity
    by_severity = defaultdict(list)
    for issue in all_issues:
        by_severity[issue['severity']].append(issue)

    # Summary
    if not warn_only:
        print("Kubernetes Pod Lifecycle Hook Analysis")
        print("=" * 70)
        print(f"Total issues: {len(all_issues)}")
        print(f"  HIGH: {len(by_severity['HIGH'])}")
        print(f"  MEDIUM: {len(by_severity['MEDIUM'])}")
        print(f"  LOW: {len(by_severity['LOW'])}")
        print()

    # Output by severity
    for severity in ['HIGH', 'MEDIUM', 'LOW']:
        if severity not in by_severity:
            continue

        if warn_only and severity == 'LOW':
            continue

        issues = by_severity[severity]
        print(f"{severity} SEVERITY ({len(issues)} issues):")
        print("-" * 70)

        for issue in issues:
            print(f"  [{issue['type']}] {issue['namespace']}/{issue['pod']}")
            if issue.get('container') and issue['container'] != '*':
                print(f"    Container: {issue['container']}")
            print(f"    {issue['detail']}")
            if verbose and issue.get('recommendation'):
                print(f"    Recommendation: {issue['recommendation']}")
        print()


def output_json(all_issues: list) -> None:
    """Output results in JSON format."""
    result = {
        'summary': {
            'total_issues': len(all_issues),
            'high': len([i for i in all_issues if i['severity'] == 'HIGH']),
            'medium': len([i for i in all_issues if i['severity'] == 'MEDIUM']),
            'low': len([i for i in all_issues if i['severity'] == 'LOW'])
        },
        'issues': all_issues
    }
    print(json.dumps(result, indent=2))


def output_table(all_issues: list, warn_only: bool = False) -> None:
    """Output results in table format."""
    if not all_issues:
        print("All pods have properly configured lifecycle hooks")
        return

    # Filter if warn_only
    if warn_only:
        all_issues = [i for i in all_issues if i['severity'] != 'LOW']

    if not all_issues:
        print("No high or medium severity issues found")
        return

    print(f"{'Severity':<8} {'Type':<28} {'Namespace/Pod':<35} {'Container':<15}")
    print("=" * 90)

    for issue in sorted(all_issues,
                       key=lambda x: ['HIGH', 'MEDIUM', 'LOW'].index(x['severity'])):
        pod_full = f"{issue['namespace']}/{issue['pod']}"
        if len(pod_full) > 32:
            pod_full = pod_full[:32] + "..."

        container = issue.get('container', '*')
        if len(container) > 12:
            container = container[:12] + "..."

        issue_type = issue['type']
        if len(issue_type) > 25:
            issue_type = issue_type[:25] + "..."

        print(f"{issue['severity']:<8} {issue_type:<28} {pod_full:<35} {container:<15}")


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
        description="Analyze Kubernetes pod lifecycle hook configurations"
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to analyze (default: all namespaces)"
    )
    parser.add_argument(
        "--include-system",
        action="store_true",
        help="Include system namespaces (kube-system, kube-public, etc.)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information with recommendations"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings (exclude LOW severity)"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Build namespace args
    ns_args = ["-n", opts.namespace] if opts.namespace else ["--all-namespaces"]

    # Get pods
    try:
        result = context.run(["kubectl", "get", "pods", "-o", "json"] + ns_args)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods_data = json.loads(result.stdout)
        pods = pods_data.get('items', [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    # Analyze pods
    all_issues = []
    for pod in pods:
        issues = analyze_pod_lifecycle(
            pod,
            exclude_system=not opts.include_system
        )
        all_issues.extend(issues)

    # Output results
    if opts.format == 'json':
        output_json(all_issues)
    elif opts.format == 'table':
        output_table(all_issues, opts.warn_only)
    else:
        output_plain(all_issues, opts.verbose, opts.warn_only)

    # Summary
    high = len([i for i in all_issues if i['severity'] == 'HIGH'])
    medium = len([i for i in all_issues if i['severity'] == 'MEDIUM'])
    low = len([i for i in all_issues if i['severity'] == 'LOW'])
    output.set_summary(f"issues={len(all_issues)}, high={high}, medium={medium}, low={low}")

    # Exit with appropriate code
    if all_issues:
        high_medium = [i for i in all_issues if i['severity'] in ('HIGH', 'MEDIUM')]
        return 1 if high_medium else 0

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
