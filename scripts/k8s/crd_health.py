#!/usr/bin/env python3
# boxctl:
#   category: k8s/cluster
#   tags: [crd, kubernetes, custom-resources, operators, health]
#   requires: [kubectl]
#   privilege: user
#   brief: Analyze Kubernetes Custom Resource Definition health and usage
#   related: [api_deprecation, control_plane]

"""
Kubernetes CRD Health Analyzer - Analyze Custom Resource Definition health.

Monitors CRDs and their associated custom resources, detecting:
- CRDs with no associated custom resources (potentially unused)
- CRDs missing conversion webhooks when multiple versions exist
- CRDs with deprecated API versions (v1beta1)
- Custom resources counts and distribution across namespaces
- CRDs without established/served status

Useful for managing clusters with many operators (Prometheus, Cert-Manager, etc.)
and ensuring CRD hygiene in large-scale Kubernetes deployments.

Exit codes:
    0 - All CRDs healthy, no issues detected
    1 - One or more CRDs have warnings or issues
    2 - Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_crds(context: Context) -> dict:
    """Get all CRDs in JSON format."""
    result = context.run(["kubectl", "get", "crds", "-o", "json"])
    if result.returncode != 0:
        return {"items": []}
    return json.loads(result.stdout)


def get_custom_resources(context: Context, plural: str, group: str) -> int:
    """Get count of custom resources for a CRD."""
    try:
        # Use the full resource name (plural.group)
        resource = f"{plural}.{group}"
        result = context.run(
            ["kubectl", "get", resource, "--all-namespaces", "-o", "json"]
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return len(data.get("items", []))
        return 0
    except Exception:
        return 0


def analyze_crd(context: Context, crd: dict, check_resources: bool = False) -> dict:
    """Analyze a single CRD and return health info."""
    metadata = crd.get("metadata", {})
    spec = crd.get("spec", {})
    status = crd.get("status", {})

    name = metadata.get("name", "unknown")
    group = spec.get("group", "")
    scope = spec.get("scope", "Namespaced")
    names = spec.get("names", {})
    plural = names.get("plural", "")
    kind = names.get("kind", "")

    # Get versions info
    versions = spec.get("versions", [])
    version_names = [v.get("name", "") for v in versions]
    served_versions = [v.get("name", "") for v in versions if v.get("served", False)]
    storage_version = next(
        (v.get("name", "") for v in versions if v.get("storage", False)), ""
    )

    # Check conditions
    conditions = status.get("conditions", [])
    established = False
    names_accepted = False

    for condition in conditions:
        cond_type = condition.get("type", "")
        cond_status = condition.get("status", "")
        if cond_type == "Established" and cond_status == "True":
            established = True
        if cond_type == "NamesAccepted" and cond_status == "True":
            names_accepted = True

    # Detect issues
    issues = []
    is_healthy = True

    # Check if CRD is established
    if not established:
        issues.append("CRD not established")
        is_healthy = False

    # Check for names conflicts
    if not names_accepted:
        issues.append("CRD names not accepted (possible conflict)")
        is_healthy = False

    # Check for multiple versions without conversion webhook
    conversion = spec.get("conversion", {})
    conversion_strategy = conversion.get("strategy", "None")

    if len(served_versions) > 1 and conversion_strategy == "None":
        issues.append(
            f"Multiple served versions ({', '.join(served_versions)}) without conversion webhook"
        )

    # Check for deprecated v1beta1 versions
    if any("v1beta1" in v for v in version_names):
        issues.append("Contains deprecated v1beta1 version")

    # Check for no storage version
    if not storage_version:
        issues.append("No storage version defined")
        is_healthy = False

    # Get resource count if requested
    resource_count = 0
    if check_resources:
        resource_count = get_custom_resources(context, plural, group)
        if resource_count == 0:
            issues.append("No custom resources exist (potentially unused CRD)")

    return {
        "name": name,
        "group": group,
        "kind": kind,
        "scope": scope,
        "versions": version_names,
        "served_versions": served_versions,
        "storage_version": storage_version,
        "conversion_strategy": conversion_strategy,
        "established": established,
        "names_accepted": names_accepted,
        "resource_count": resource_count,
        "issues": issues,
        "healthy": is_healthy and len(issues) == 0,
    }


def format_plain(
    results: list, warn_only: bool, verbose: bool
) -> tuple[str, bool]:
    """Print analysis results in plain format."""
    lines = []
    has_issues = False

    healthy_count = 0
    issue_count = 0

    for result in results:
        if result["healthy"] and not result["issues"]:
            healthy_count += 1
        else:
            issue_count += 1
            has_issues = True

        # Skip healthy if warn_only
        if warn_only and not result["issues"]:
            continue

        status_marker = "OK" if result["healthy"] and not result["issues"] else "WARN"
        lines.append(f"[{status_marker}] {result['name']}")

        if verbose or result["issues"]:
            lines.append(f"  Group: {result['group']}")
            lines.append(f"  Kind: {result['kind']}")
            lines.append(f"  Scope: {result['scope']}")
            lines.append(f"  Versions: {', '.join(result['versions'])}")
            lines.append(f"  Storage Version: {result['storage_version']}")
            lines.append(f"  Conversion: {result['conversion_strategy']}")

            if result["resource_count"] > 0 or verbose:
                lines.append(f"  Resources: {result['resource_count']}")

            if result["issues"]:
                for issue in result["issues"]:
                    lines.append(f"  WARNING: {issue}")

            lines.append("")

    # Print summary
    total = healthy_count + issue_count
    lines.append(f"Summary: {healthy_count}/{total} CRDs healthy, {issue_count} with warnings")

    return "\n".join(lines), has_issues


def format_json(results: list, warn_only: bool) -> tuple[str, bool]:
    """Format results as JSON."""
    output = []
    has_issues = False

    for result in results:
        if not warn_only or result["issues"]:
            output.append(result)
            if result["issues"]:
                has_issues = True

    return json.dumps(output, indent=2), has_issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes Custom Resource Definition (CRD) health"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show CRDs with issues",
    )
    parser.add_argument(
        "--check-resources",
        "-c",
        action="store_true",
        help="Check for unused CRDs (slower, queries each resource type)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed information for all CRDs",
    )
    parser.add_argument(
        "--group",
        "-g",
        help="Filter CRDs by API group (e.g., cert-manager.io)",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get all CRDs
    crds = get_crds(context)

    # Analyze each CRD
    results = []
    for crd in crds.get("items", []):
        # Filter by group if specified
        if opts.group:
            crd_group = crd.get("spec", {}).get("group", "")
            if opts.group not in crd_group:
                continue

        result = analyze_crd(context, crd, check_resources=opts.check_resources)
        results.append(result)

    # Sort results: issues first, then by name
    results.sort(key=lambda x: (x["healthy"] and not x["issues"], x["name"]))

    # Format output
    if opts.format == "json":
        result, has_issues = format_json(results, opts.warn_only)
    else:
        result, has_issues = format_plain(results, opts.warn_only, opts.verbose)

    print(result)

    # Summary
    healthy_count = sum(1 for r in results if r["healthy"] and not r["issues"])
    issue_count = sum(1 for r in results if r["issues"])
    output.set_summary(
        f"total={len(results)}, healthy={healthy_count}, issues={issue_count}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
