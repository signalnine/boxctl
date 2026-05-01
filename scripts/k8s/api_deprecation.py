#!/usr/bin/env python3
# boxctl:
#   category: k8s/cluster
#   tags: [deprecation, kubernetes, upgrade, api, compatibility]
#   requires: [kubectl]
#   privilege: user
#   brief: Check for deprecated or removed Kubernetes API versions
#   related: [control_plane, crd_health]

"""
Kubernetes API Deprecation Checker - Scan cluster for deprecated API versions.

Scans cluster resources for deprecated or removed API versions that may
cause issues during Kubernetes upgrades. Essential for upgrade planning
and maintaining cluster compatibility.

Checks for:
- Resources using deprecated API versions
- Resources using removed API versions (critical for upgrades)
- API versions scheduled for removal in future versions
- Custom resources with deprecated apiVersions

Exit codes:
    0 - No deprecated APIs found
    1 - Deprecated or removed APIs found
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# Mapping of deprecated API versions to their replacements and removal versions
# Format: {deprecated_api: (replacement_api, removed_in_version, severity)}
DEPRECATIONS = {
    # Extensions (removed in 1.22)
    "extensions/v1beta1/Ingress": ("networking.k8s.io/v1", "1.22", "removed"),
    "extensions/v1beta1/DaemonSet": ("apps/v1", "1.16", "removed"),
    "extensions/v1beta1/Deployment": ("apps/v1", "1.16", "removed"),
    "extensions/v1beta1/ReplicaSet": ("apps/v1", "1.16", "removed"),
    "extensions/v1beta1/NetworkPolicy": ("networking.k8s.io/v1", "1.16", "removed"),
    "extensions/v1beta1/PodSecurityPolicy": ("policy/v1beta1", "1.16", "removed"),
    # Apps v1beta1/v1beta2 (removed in 1.16)
    "apps/v1beta1/Deployment": ("apps/v1", "1.16", "removed"),
    "apps/v1beta1/StatefulSet": ("apps/v1", "1.16", "removed"),
    "apps/v1beta2/DaemonSet": ("apps/v1", "1.16", "removed"),
    "apps/v1beta2/Deployment": ("apps/v1", "1.16", "removed"),
    "apps/v1beta2/ReplicaSet": ("apps/v1", "1.16", "removed"),
    "apps/v1beta2/StatefulSet": ("apps/v1", "1.16", "removed"),
    # Networking (removed in 1.22)
    "networking.k8s.io/v1beta1/Ingress": ("networking.k8s.io/v1", "1.22", "removed"),
    "networking.k8s.io/v1beta1/IngressClass": (
        "networking.k8s.io/v1",
        "1.22",
        "removed",
    ),
    # RBAC (removed in 1.22)
    "rbac.authorization.k8s.io/v1beta1/ClusterRole": (
        "rbac.authorization.k8s.io/v1",
        "1.22",
        "removed",
    ),
    "rbac.authorization.k8s.io/v1beta1/ClusterRoleBinding": (
        "rbac.authorization.k8s.io/v1",
        "1.22",
        "removed",
    ),
    "rbac.authorization.k8s.io/v1beta1/Role": (
        "rbac.authorization.k8s.io/v1",
        "1.22",
        "removed",
    ),
    "rbac.authorization.k8s.io/v1beta1/RoleBinding": (
        "rbac.authorization.k8s.io/v1",
        "1.22",
        "removed",
    ),
    # Admission (removed in 1.22)
    "admissionregistration.k8s.io/v1beta1/MutatingWebhookConfiguration": (
        "admissionregistration.k8s.io/v1",
        "1.22",
        "removed",
    ),
    "admissionregistration.k8s.io/v1beta1/ValidatingWebhookConfiguration": (
        "admissionregistration.k8s.io/v1",
        "1.22",
        "removed",
    ),
    # CRDs (removed in 1.22)
    "apiextensions.k8s.io/v1beta1/CustomResourceDefinition": (
        "apiextensions.k8s.io/v1",
        "1.22",
        "removed",
    ),
    # Batch (CronJob removed in 1.25)
    "batch/v1beta1/CronJob": ("batch/v1", "1.25", "removed"),
    # Policy (PodDisruptionBudget removed in 1.25, PodSecurityPolicy removed in 1.25)
    "policy/v1beta1/PodDisruptionBudget": ("policy/v1", "1.25", "removed"),
    "policy/v1beta1/PodSecurityPolicy": (
        "(removed, use Pod Security Standards)",
        "1.25",
        "removed",
    ),
    # Autoscaling (v2beta2 removed in 1.26)
    "autoscaling/v2beta1/HorizontalPodAutoscaler": (
        "autoscaling/v2",
        "1.25",
        "removed",
    ),
    "autoscaling/v2beta2/HorizontalPodAutoscaler": (
        "autoscaling/v2",
        "1.26",
        "removed",
    ),
    # Storage (removed in 1.22)
    "storage.k8s.io/v1beta1/CSIDriver": ("storage.k8s.io/v1", "1.22", "removed"),
    "storage.k8s.io/v1beta1/CSINode": ("storage.k8s.io/v1", "1.22", "removed"),
    "storage.k8s.io/v1beta1/StorageClass": ("storage.k8s.io/v1", "1.17", "removed"),
    "storage.k8s.io/v1beta1/VolumeAttachment": ("storage.k8s.io/v1", "1.22", "removed"),
    # Certificates (removed in 1.22)
    "certificates.k8s.io/v1beta1/CertificateSigningRequest": (
        "certificates.k8s.io/v1",
        "1.22",
        "removed",
    ),
    # Coordination (removed in 1.22)
    "coordination.k8s.io/v1beta1/Lease": ("coordination.k8s.io/v1", "1.22", "removed"),
    # Discovery (removed in 1.25)
    "discovery.k8s.io/v1beta1/EndpointSlice": (
        "discovery.k8s.io/v1",
        "1.25",
        "removed",
    ),
    # Events (removed in 1.25)
    "events.k8s.io/v1beta1/Event": ("events.k8s.io/v1", "1.25", "removed"),
    # FlowControl (v1beta1 removed in 1.26, v1beta2 removed in 1.29)
    "flowcontrol.apiserver.k8s.io/v1beta1/FlowSchema": (
        "flowcontrol.apiserver.k8s.io/v1",
        "1.26",
        "removed",
    ),
    "flowcontrol.apiserver.k8s.io/v1beta1/PriorityLevelConfiguration": (
        "flowcontrol.apiserver.k8s.io/v1",
        "1.26",
        "removed",
    ),
    "flowcontrol.apiserver.k8s.io/v1beta2/FlowSchema": (
        "flowcontrol.apiserver.k8s.io/v1",
        "1.29",
        "removed",
    ),
    "flowcontrol.apiserver.k8s.io/v1beta2/PriorityLevelConfiguration": (
        "flowcontrol.apiserver.k8s.io/v1",
        "1.29",
        "removed",
    ),
    "flowcontrol.apiserver.k8s.io/v1beta3/FlowSchema": (
        "flowcontrol.apiserver.k8s.io/v1",
        "1.32",
        "deprecated",
    ),
    "flowcontrol.apiserver.k8s.io/v1beta3/PriorityLevelConfiguration": (
        "flowcontrol.apiserver.k8s.io/v1",
        "1.32",
        "deprecated",
    ),
    # Node (removed in 1.22)
    "node.k8s.io/v1beta1/RuntimeClass": ("node.k8s.io/v1", "1.22", "removed"),
    # Scheduling (removed in 1.22)
    "scheduling.k8s.io/v1beta1/PriorityClass": (
        "scheduling.k8s.io/v1",
        "1.22",
        "removed",
    ),
}


def get_cluster_version(context: Context) -> str | None:
    """Get the current Kubernetes cluster version."""
    result = context.run(["kubectl", "version", "-o", "json"])
    if result.returncode != 0:
        return None

    try:
        data = json.loads(result.stdout)
        server_version = data.get("serverVersion", {})
        major = server_version.get("major", "0")
        minor = server_version.get("minor", "0").rstrip("+")
        return f"{major}.{minor}"
    except (json.JSONDecodeError, KeyError):
        return None


def get_all_resources(context: Context, namespace: str | None = None) -> list:
    """Get all resources from the cluster to check API versions."""
    found_issues = []

    # Resource types to check (most commonly using deprecated APIs)
    resource_types = [
        "deployments",
        "daemonsets",
        "replicasets",
        "statefulsets",
        "ingresses",
        "networkpolicies",
        "cronjobs",
        "poddisruptionbudgets",
        "horizontalpodautoscalers",
        "clusterroles",
        "clusterrolebindings",
        "roles",
        "rolebindings",
        "mutatingwebhookconfigurations",
        "validatingwebhookconfigurations",
        "customresourcedefinitions",
        "csidriver",
        "csinodes",
        "storageclasses",
        "volumeattachments",
        "certificatesigningrequests",
        "leases",
        "endpointslices",
        "flowschemas",
        "prioritylevelconfigurations",
        "runtimeclasses",
        "priorityclasses",
    ]

    for resource_type in resource_types:
        cmd = ["kubectl", "get", resource_type, "-o", "json"]
        if namespace:
            cmd.extend(["-n", namespace])
        else:
            cmd.append("--all-namespaces")

        result = context.run(cmd)
        if result.returncode != 0:
            continue

        try:
            data = json.loads(result.stdout)
            for item in data.get("items", []):
                api_version = item.get("apiVersion", "")
                kind = item.get("kind", "")
                metadata = item.get("metadata", {})
                name = metadata.get("name", "unknown")
                ns = metadata.get("namespace", "cluster-wide")

                # Build the key to check
                key = f"{api_version}/{kind}"

                if key in DEPRECATIONS:
                    replacement, removed_in, severity = DEPRECATIONS[key]
                    found_issues.append(
                        {
                            "api_version": api_version,
                            "kind": kind,
                            "name": name,
                            "namespace": ns,
                            "replacement": replacement,
                            "removed_in": removed_in,
                            "severity": severity,
                        }
                    )
        except json.JSONDecodeError:
            continue

    return found_issues


def compare_versions(v1: str, v2: str) -> int:
    """Compare two Kubernetes versions. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""

    def parse_version(v: str) -> tuple:
        parts = v.replace("v", "").split(".")
        return tuple(int(p) for p in parts[:2])

    try:
        pv1 = parse_version(v1)
        pv2 = parse_version(v2)
        if pv1 < pv2:
            return -1
        elif pv1 > pv2:
            return 1
        return 0
    except (ValueError, IndexError):
        return 0


def analyze_issues(
    issues: list, cluster_version: str | None, target_version: str | None = None
) -> tuple[list, list, list]:
    """Analyze issues and categorize by severity."""
    critical = []  # Already removed in current or target version
    warning = []  # Deprecated, will be removed
    info = []  # Deprecated but not urgent

    for issue in issues:
        removed_in = issue["removed_in"]
        severity = issue["severity"]

        # Determine actual severity based on versions
        if severity == "removed":
            if cluster_version and compare_versions(cluster_version, removed_in) >= 0:
                issue["actual_severity"] = "critical"
                issue["message"] = (
                    f"API removed in {removed_in}, current cluster is {cluster_version}"
                )
                critical.append(issue)
            elif target_version and compare_versions(target_version, removed_in) >= 0:
                issue["actual_severity"] = "critical"
                issue["message"] = (
                    f"API will be removed in {removed_in}, blocking upgrade to {target_version}"
                )
                critical.append(issue)
            else:
                issue["actual_severity"] = "warning"
                issue["message"] = f"API deprecated, will be removed in {removed_in}"
                warning.append(issue)
        else:
            issue["actual_severity"] = "info"
            issue["message"] = f"API deprecated, scheduled for removal in {removed_in}"
            info.append(issue)

    return critical, warning, info


def format_plain(
    critical: list,
    warning: list,
    info: list,
    cluster_version: str | None,
    target_version: str | None,
    warn_only: bool = False,
) -> str:
    """Format output as plain text."""
    lines = []
    lines.append("Kubernetes API Deprecation Check")
    lines.append("=" * 50)

    if cluster_version:
        lines.append(f"Current Cluster Version: {cluster_version}")
    if target_version:
        lines.append(f"Target Upgrade Version: {target_version}")
    lines.append("")

    total = len(critical) + len(warning) + len(info)

    if total == 0:
        if not warn_only:
            lines.append("[OK] No deprecated APIs found")
        return "\n".join(lines)

    if critical:
        lines.append(f"CRITICAL ({len(critical)} resources):")
        lines.append("-" * 40)
        for issue in critical:
            lines.append(f"  [!] {issue['namespace']}/{issue['name']}")
            lines.append(f"      Kind: {issue['kind']}")
            lines.append(f"      API: {issue['api_version']}")
            lines.append(f"      Replace with: {issue['replacement']}")
            lines.append(f"      {issue['message']}")
            lines.append("")

    if warning:
        lines.append(f"WARNING ({len(warning)} resources):")
        lines.append("-" * 40)
        for issue in warning:
            lines.append(f"  [*] {issue['namespace']}/{issue['name']}")
            lines.append(f"      Kind: {issue['kind']}")
            lines.append(f"      API: {issue['api_version']}")
            lines.append(f"      Replace with: {issue['replacement']}")
            lines.append(f"      {issue['message']}")
            lines.append("")

    if info and not warn_only:
        lines.append(f"INFO ({len(info)} resources):")
        lines.append("-" * 40)
        for issue in info:
            lines.append(f"  [i] {issue['namespace']}/{issue['name']}")
            lines.append(f"      Kind: {issue['kind']}")
            lines.append(f"      API: {issue['api_version']}")
            lines.append(f"      Replace with: {issue['replacement']}")
            lines.append("")

    lines.append("")
    lines.append(
        f"Summary: {len(critical)} critical, {len(warning)} warnings, {len(info)} info"
    )

    return "\n".join(lines)


def format_json(
    critical: list,
    warning: list,
    info: list,
    cluster_version: str | None,
    target_version: str | None,
) -> str:
    """Format output as JSON."""
    return json.dumps(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cluster_version": cluster_version,
            "target_version": target_version,
            "summary": {
                "critical": len(critical),
                "warning": len(warning),
                "info": len(info),
                "total": len(critical) + len(warning) + len(info),
            },
            "critical": critical,
            "warning": warning,
            "info": info,
            "healthy": len(critical) == 0 and len(warning) == 0,
        },
        indent=2,
    )


def format_table(
    critical: list,
    warning: list,
    info: list,
    cluster_version: str | None,
    target_version: str | None,
    warn_only: bool = False,
) -> str:
    """Format output as a table."""
    lines = []

    # Header
    lines.append("+" + "-" * 90 + "+")
    title = "Kubernetes API Deprecation Check"
    if cluster_version:
        title += f" (Cluster: {cluster_version})"
    if target_version:
        title += f" -> {target_version}"
    lines.append(f"| {title:<88} |")
    lines.append("+" + "-" * 90 + "+")

    all_issues = []
    for issue in critical:
        all_issues.append(("CRITICAL", issue))
    for issue in warning:
        all_issues.append(("WARNING", issue))
    if not warn_only:
        for issue in info:
            all_issues.append(("INFO", issue))

    if not all_issues:
        lines.append(f"| {'No deprecated APIs found':<88} |")
        lines.append("+" + "-" * 90 + "+")
        return "\n".join(lines)

    # Table header
    lines.append(
        f"| {'SEVERITY':<10} | {'NAMESPACE':<20} | {'NAME':<25} | {'KIND':<15} | {'REMOVED':<8} |"
    )
    lines.append("+" + "-" * 90 + "+")

    for severity, issue in all_issues:
        ns = issue["namespace"][:20]
        name = issue["name"][:25]
        kind = issue["kind"][:15]
        removed = issue["removed_in"][:8]
        lines.append(
            f"| {severity:<10} | {ns:<20} | {name:<25} | {kind:<15} | {removed:<8} |"
        )

    lines.append("+" + "-" * 90 + "+")

    # Summary
    total = len(critical) + len(warning) + len(info)
    summary = (
        f"Total: {total} ({len(critical)} critical, {len(warning)} warning, {len(info)} info)"
    )
    lines.append(f"| {summary:<88} |")
    lines.append("+" + "-" * 90 + "+")

    return "\n".join(lines)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = deprecated APIs found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Check for deprecated Kubernetes API versions in cluster resources"
    )
    parser.add_argument(
        "--namespace",
        "-n",
        help="Namespace to check (default: all namespaces)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--target-version",
        "-t",
        help="Target Kubernetes version to upgrade to (e.g., 1.28)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show critical and warning issues",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get cluster version
    cluster_version = get_cluster_version(context)
    if not cluster_version:
        output.error("Warning: Could not determine cluster version")

    # Get all resources and check for deprecated APIs
    issues = get_all_resources(context, opts.namespace)

    # Analyze issues
    critical, warning, info = analyze_issues(issues, cluster_version, opts.target_version)

    # Format output
    if opts.format == "json":
        result = format_json(
            critical, warning, info, cluster_version, opts.target_version
        )
    elif opts.format == "table":
        result = format_table(
            critical,
            warning,
            info,
            cluster_version,
            opts.target_version,
            opts.warn_only,
        )
    else:
        result = format_plain(
            critical,
            warning,
            info,
            cluster_version,
            opts.target_version,
            opts.warn_only,
        )

    # Print output
    if result.strip():
        print(result)

    output.set_summary(
        f"critical={len(critical)}, warning={len(warning)}, info={len(info)}"
    )

    # Return exit code
    return 1 if critical or warning else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
