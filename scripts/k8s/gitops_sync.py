#!/usr/bin/env python3
# boxctl:
#   category: k8s/gitops
#   tags: [gitops, flux, argocd, kubernetes, sync, deployment]
#   requires: [kubectl]
#   brief: Monitor GitOps controller sync status for Flux CD and ArgoCD
#   privilege: user
#   related: [helm_releases, deployment_status]

"""
Monitor GitOps controller sync status for Flux CD and ArgoCD.

This script monitors the health and sync status of GitOps deployments:
- Flux CD: Kustomizations, HelmReleases, GitRepositories, HelmRepositories
- ArgoCD: Applications and ApplicationSets

Detects issues like:
- Failed reconciliations
- Stalled syncs (no progress for extended time)
- Source fetch failures
- Drift between desired and actual state
- Suspended resources

Exit codes:
    0 - All GitOps resources synced and healthy
    1 - One or more resources out of sync or unhealthy
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_time(time_str: str | None) -> datetime | None:
    """Parse Kubernetes timestamp to datetime."""
    if not time_str:
        return None
    try:
        # Handle format: 2024-01-15T10:30:00Z
        return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def get_condition(conditions: list | None, condition_type: str) -> dict | None:
    """Get a specific condition from conditions list."""
    if not conditions:
        return None
    for condition in conditions:
        if condition.get("type") == condition_type:
            return condition
    return None


def get_resource(
    context: Context,
    resource_type: str,
    namespace: str | None = None,
    api_group: str | None = None,
) -> dict:
    """Get Kubernetes resources in JSON format."""
    if api_group:
        full_resource = f"{resource_type}.{api_group}"
    else:
        full_resource = resource_type

    args = ["kubectl", "get", full_resource, "-o", "json"]
    if namespace:
        args.extend(["-n", namespace])
    else:
        args.append("--all-namespaces")

    result = context.run(args)
    if result.returncode != 0:
        # Resource type might not exist (no Flux/ArgoCD installed)
        return {"items": []}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"items": []}


def check_flux_kustomization(resource: dict) -> dict:
    """Check Flux Kustomization status."""
    metadata = resource.get("metadata", {})
    status = resource.get("status", {})
    spec = resource.get("spec", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    issues = []
    is_healthy = True

    # Check if suspended
    if spec.get("suspend", False):
        issues.append("Resource is suspended")
        is_healthy = False

    conditions = status.get("conditions", [])

    # Check Ready condition
    ready = get_condition(conditions, "Ready")
    if ready:
        if ready.get("status") != "True":
            reason = ready.get("reason", "Unknown")
            message = ready.get("message", "")[:100]
            issues.append(f"Not ready: {reason} - {message}")
            is_healthy = False

    # Check Reconciling condition (stalled if not progressing)
    reconciling = get_condition(conditions, "Reconciling")
    if reconciling and reconciling.get("status") == "True":
        # Still reconciling - check how long
        last_transition = parse_time(reconciling.get("lastTransitionTime"))
        if last_transition:
            age_minutes = (
                datetime.now(timezone.utc) - last_transition
            ).total_seconds() / 60
            if age_minutes > 30:
                issues.append(
                    f"Reconciling for {int(age_minutes)} minutes (may be stalled)"
                )

    # Check last applied revision
    last_applied = status.get("lastAppliedRevision", "")
    last_attempted = status.get("lastAttemptedRevision", "")

    if last_applied and last_attempted and last_applied != last_attempted:
        issues.append(
            f"Revision mismatch: applied={last_applied[:12]}, attempted={last_attempted[:12]}"
        )
        is_healthy = False

    return {
        "type": "Kustomization",
        "controller": "flux",
        "namespace": namespace,
        "name": name,
        "healthy": is_healthy,
        "suspended": spec.get("suspend", False),
        "source": spec.get("sourceRef", {}).get("name", "unknown"),
        "revision": last_applied[:12] if last_applied else "none",
        "issues": issues,
    }


def check_flux_helmrelease(resource: dict) -> dict:
    """Check Flux HelmRelease status."""
    metadata = resource.get("metadata", {})
    status = resource.get("status", {})
    spec = resource.get("spec", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    issues = []
    is_healthy = True

    # Check if suspended
    if spec.get("suspend", False):
        issues.append("Resource is suspended")
        is_healthy = False

    conditions = status.get("conditions", [])

    # Check Ready condition
    ready = get_condition(conditions, "Ready")
    if ready:
        if ready.get("status") != "True":
            reason = ready.get("reason", "Unknown")
            message = ready.get("message", "")[:100]
            issues.append(f"Not ready: {reason} - {message}")
            is_healthy = False

    # Check Released condition
    released = get_condition(conditions, "Released")
    if released and released.get("status") != "True":
        reason = released.get("reason", "Unknown")
        issues.append(f"Not released: {reason}")
        is_healthy = False

    # Check install/upgrade failures
    failures = status.get("failures", 0)
    if failures > 0:
        issues.append(f"Has {failures} recorded failure(s)")

    # Get helm chart info
    chart_ref = spec.get("chartRef", spec.get("chart", {}).get("spec", {}))
    chart_name = chart_ref.get("name", "unknown")

    return {
        "type": "HelmRelease",
        "controller": "flux",
        "namespace": namespace,
        "name": name,
        "healthy": is_healthy,
        "suspended": spec.get("suspend", False),
        "chart": chart_name,
        "version": status.get("lastAppliedRevision", "unknown"),
        "issues": issues,
    }


def check_flux_gitrepository(resource: dict) -> dict:
    """Check Flux GitRepository status."""
    metadata = resource.get("metadata", {})
    status = resource.get("status", {})
    spec = resource.get("spec", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    issues = []
    is_healthy = True

    # Check if suspended
    if spec.get("suspend", False):
        issues.append("Resource is suspended")
        is_healthy = False

    conditions = status.get("conditions", [])

    # Check Ready condition
    ready = get_condition(conditions, "Ready")
    if ready:
        if ready.get("status") != "True":
            reason = ready.get("reason", "Unknown")
            message = ready.get("message", "")[:100]
            issues.append(f"Not ready: {reason} - {message}")
            is_healthy = False

    # Check for fetch failures
    fetching = get_condition(conditions, "FetchFailed")
    if fetching and fetching.get("status") == "True":
        issues.append(f"Fetch failed: {fetching.get('message', '')[:50]}")
        is_healthy = False

    artifact = status.get("artifact", {})
    revision = artifact.get("revision", "")

    return {
        "type": "GitRepository",
        "controller": "flux",
        "namespace": namespace,
        "name": name,
        "healthy": is_healthy,
        "suspended": spec.get("suspend", False),
        "url": spec.get("url", "unknown"),
        "branch": spec.get("ref", {}).get("branch", "main"),
        "revision": revision[:12] if revision else "none",
        "issues": issues,
    }


def check_argocd_application(resource: dict) -> dict:
    """Check ArgoCD Application status."""
    metadata = resource.get("metadata", {})
    status = resource.get("status", {})
    spec = resource.get("spec", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "argocd")

    issues = []
    is_healthy = True

    # Check sync status
    sync_status = status.get("sync", {})
    sync_state = sync_status.get("status", "Unknown")

    if sync_state != "Synced":
        issues.append(f"Sync status: {sync_state}")
        is_healthy = False

    # Check health status
    health_status = status.get("health", {})
    health_state = health_status.get("status", "Unknown")

    if health_state not in ("Healthy", "Progressing"):
        issues.append(f"Health status: {health_state}")
        if health_state != "Progressing":
            is_healthy = False

    # Check operation state for failures
    operation_state = status.get("operationState", {})
    phase = operation_state.get("phase", "")

    if phase in ("Failed", "Error"):
        message = operation_state.get("message", "")[:100]
        issues.append(f"Operation {phase}: {message}")
        is_healthy = False

    # Check for sync errors
    conditions = status.get("conditions", [])
    for condition in conditions:
        if condition.get("type") in ("SyncError", "InvalidSpecError"):
            issues.append(
                f"{condition.get('type')}: {condition.get('message', '')[:50]}"
            )
            is_healthy = False

    # Get source info
    source = spec.get("source", {})
    destination = spec.get("destination", {})

    return {
        "type": "Application",
        "controller": "argocd",
        "namespace": namespace,
        "name": name,
        "healthy": is_healthy,
        "sync_status": sync_state,
        "health_status": health_state,
        "source_repo": source.get("repoURL", "unknown"),
        "target_revision": source.get("targetRevision", "HEAD"),
        "destination": destination.get("namespace", "default"),
        "issues": issues,
    }


def check_argocd_applicationset(resource: dict) -> dict:
    """Check ArgoCD ApplicationSet status."""
    metadata = resource.get("metadata", {})
    status = resource.get("status", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "argocd")

    issues = []
    is_healthy = True

    conditions = status.get("conditions", [])

    # Check for errors in conditions
    for condition in conditions:
        cond_type = condition.get("type", "")
        cond_status = condition.get("status", "Unknown")

        if cond_type == "ErrorOccurred" and cond_status == "True":
            message = condition.get("message", "")[:100]
            issues.append(f"Error: {message}")
            is_healthy = False

        if cond_type == "ResourcesUpToDate" and cond_status != "True":
            issues.append("Resources not up to date")
            is_healthy = False

    return {
        "type": "ApplicationSet",
        "controller": "argocd",
        "namespace": namespace,
        "name": name,
        "healthy": is_healthy,
        "issues": issues,
    }


def collect_gitops_status(context: Context, namespace: str | None = None) -> list:
    """Collect status from all GitOps controllers."""
    results = []

    # Flux CD resources
    # Kustomizations
    kustomizations = get_resource(
        context, "kustomizations", namespace, "kustomize.toolkit.fluxcd.io"
    )
    for resource in kustomizations.get("items", []):
        results.append(check_flux_kustomization(resource))

    # HelmReleases
    helmreleases = get_resource(
        context, "helmreleases", namespace, "helm.toolkit.fluxcd.io"
    )
    for resource in helmreleases.get("items", []):
        results.append(check_flux_helmrelease(resource))

    # GitRepositories
    gitrepos = get_resource(
        context, "gitrepositories", namespace, "source.toolkit.fluxcd.io"
    )
    for resource in gitrepos.get("items", []):
        results.append(check_flux_gitrepository(resource))

    # ArgoCD resources
    # Applications
    applications = get_resource(context, "applications", namespace, "argoproj.io")
    for resource in applications.get("items", []):
        results.append(check_argocd_application(resource))

    # ApplicationSets
    appsets = get_resource(context, "applicationsets", namespace, "argoproj.io")
    for resource in appsets.get("items", []):
        results.append(check_argocd_applicationset(resource))

    return results


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
        description="Monitor GitOps sync status for Flux CD and ArgoCD"
    )
    parser.add_argument(
        "--namespace",
        "-n",
        help="Namespace to check (default: all namespaces)",
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
        help="Only show resources with issues",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Collect GitOps status
    results = collect_gitops_status(context, opts.namespace)

    # Filter results if warn_only
    if opts.warn_only:
        results = [r for r in results if r.get("issues") or not r.get("healthy")]

    # Check for any issues
    has_issues = any(r.get("issues") or not r.get("healthy") for r in results)

    if opts.format == "json":
        print(json.dumps(results, indent=2))
    else:  # plain format
        if not results:
            print("No GitOps resources found.")
            print("Hint: Install Flux CD or ArgoCD to use GitOps deployments")
            output.set_summary("No GitOps resources found")
            return 0

        # Group by controller
        flux_resources = [r for r in results if r.get("controller") == "flux"]
        argo_resources = [r for r in results if r.get("controller") == "argocd"]

        healthy_count = sum(1 for r in results if r.get("healthy"))
        total_count = len(results)

        if flux_resources:
            print("=== Flux CD Resources ===")
            for r in flux_resources:
                status_marker = "[OK]" if r.get("healthy") else "[!!]"
                suspended = " (SUSPENDED)" if r.get("suspended") else ""

                print(
                    f"{status_marker} {r['type']}: {r['namespace']}/{r['name']}{suspended}"
                )

                # Print details based on type
                if r["type"] == "Kustomization":
                    print(
                        f"     Source: {r.get('source', 'unknown')}, Revision: {r.get('revision', 'none')}"
                    )
                elif r["type"] == "HelmRelease":
                    print(
                        f"     Chart: {r.get('chart', 'unknown')}, Version: {r.get('version', 'unknown')}"
                    )
                elif r["type"] == "GitRepository":
                    print(
                        f"     URL: {r.get('url', 'unknown')}, Branch: {r.get('branch', 'unknown')}"
                    )

                # Print issues
                for issue in r.get("issues", []):
                    print(f"     WARNING: {issue}")

            print()

        if argo_resources:
            print("=== ArgoCD Resources ===")
            for r in argo_resources:
                status_marker = "[OK]" if r.get("healthy") else "[!!]"

                print(f"{status_marker} {r['type']}: {r['namespace']}/{r['name']}")

                if r["type"] == "Application":
                    print(
                        f"     Sync: {r.get('sync_status', 'Unknown')}, Health: {r.get('health_status', 'Unknown')}"
                    )
                    print(
                        f"     Target: {r.get('destination', 'unknown')}, Revision: {r.get('target_revision', 'HEAD')}"
                    )

                # Print issues
                for issue in r.get("issues", []):
                    print(f"     WARNING: {issue}")

            print()

        # Summary
        print(f"Summary: {healthy_count}/{total_count} GitOps resources healthy")

        if has_issues:
            unhealthy = [r for r in results if not r.get("healthy")]
            names = [r["namespace"] + "/" + r["name"] for r in unhealthy[:5]]
            print(f"Issues detected in: {', '.join(names)}")
            if len(unhealthy) > 5:
                print(f"  ...and {len(unhealthy) - 5} more")

    output.set_summary(
        f"resources={len(results)}, healthy={sum(1 for r in results if r.get('healthy'))}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
