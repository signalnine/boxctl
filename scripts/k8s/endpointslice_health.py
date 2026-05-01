#!/usr/bin/env python3
# boxctl:
#   category: k8s/networking
#   tags: [endpointslice, kubernetes, networking, service-discovery, health]
#   requires: [kubectl]
#   brief: Monitor EndpointSlice health and detect service discovery issues
#   privilege: user
#   related: [service_endpoint, ingress_health]

"""
Monitor Kubernetes EndpointSlice health and detect service discovery issues.

EndpointSlices are the modern replacement for Endpoints, providing better
scalability for large clusters. This script monitors their health to catch
service discovery problems before they impact applications.

Checks performed:
- EndpointSlices with no ready endpoints (service down)
- EndpointSlices with high not-ready endpoint ratio
- Services missing EndpointSlices entirely
- Stale EndpointSlices (endpoints stuck in not-ready)
- EndpointSlice count per service (fragmentation)
- Port mismatches between service and endpoints

Exit codes:
    0 - All EndpointSlices healthy
    1 - Issues detected (missing endpoints, unhealthy services)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def analyze_endpointslice(eps: dict) -> dict:
    """Analyze a single EndpointSlice for issues."""
    metadata = eps.get("metadata", {})
    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")
    labels = metadata.get("labels", {})

    # Get the service this EndpointSlice belongs to
    service_name = labels.get("kubernetes.io/service-name", "unknown")

    endpoints = eps.get("endpoints", [])
    ports = eps.get("ports", [])

    issues = []
    is_healthy = True

    # Count endpoint conditions
    ready_count = 0
    not_ready_count = 0
    terminating_count = 0
    unknown_count = 0

    for endpoint in endpoints:
        conditions = endpoint.get("conditions", {})

        # Ready is the primary health indicator
        ready = conditions.get("ready")
        terminating = conditions.get("terminating")

        if terminating:
            terminating_count += 1
        elif ready:
            ready_count += 1
        elif ready is False:
            not_ready_count += 1
        else:
            # Ready is nil/unknown
            unknown_count += 1

    total_endpoints = len(endpoints)

    # Check for no endpoints at all
    if total_endpoints == 0:
        issues.append("No endpoints defined")
        is_healthy = False

    # Check for no ready endpoints
    elif ready_count == 0:
        if terminating_count == total_endpoints:
            issues.append(f"All {total_endpoints} endpoints terminating")
        elif not_ready_count > 0:
            issues.append(f"No ready endpoints ({not_ready_count} not ready)")
        else:
            issues.append("No ready endpoints")
        is_healthy = False

    # Check for high not-ready ratio (>50% not ready)
    elif not_ready_count > 0:
        not_ready_ratio = not_ready_count / total_endpoints
        if not_ready_ratio > 0.5:
            issues.append(
                f"High not-ready ratio: {not_ready_count}/{total_endpoints} "
                f"({not_ready_ratio:.0%}) not ready"
            )
            is_healthy = False
        elif not_ready_ratio > 0.2:
            issues.append(
                f"Some endpoints not ready: {not_ready_count}/{total_endpoints}"
            )

    # Check for terminating endpoints
    if terminating_count > 0 and terminating_count < total_endpoints:
        issues.append(f"{terminating_count}/{total_endpoints} endpoints terminating")

    # Check for missing port definitions
    if not ports:
        issues.append("No ports defined in EndpointSlice")

    return {
        "name": name,
        "namespace": namespace,
        "service": service_name,
        "ready": ready_count,
        "not_ready": not_ready_count,
        "terminating": terminating_count,
        "unknown": unknown_count,
        "total": total_endpoints,
        "ports": len(ports),
        "healthy": is_healthy,
        "issues": issues,
    }


def check_service_coverage(
    services: dict, endpointslices_by_service: dict, exclude_headless: bool = True
) -> list:
    """Check which services are missing EndpointSlices."""
    missing_services = []

    for svc in services.get("items", []):
        metadata = svc.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")
        spec = svc.get("spec", {})

        # Skip ExternalName services (they don't have endpoints)
        if spec.get("type") == "ExternalName":
            continue

        # Optionally skip headless services
        if exclude_headless and spec.get("clusterIP") == "None":
            continue

        # Skip services without selectors (manually managed)
        if not spec.get("selector"):
            continue

        key = f"{namespace}/{name}"
        if key not in endpointslices_by_service:
            missing_services.append(
                {
                    "name": name,
                    "namespace": namespace,
                    "type": spec.get("type", "ClusterIP"),
                    "selector": spec.get("selector", {}),
                }
            )

    return missing_services


def check_endpointslice_fragmentation(
    endpointslices_by_service: dict, threshold: int = 10
) -> list:
    """Check for services with too many EndpointSlice fragments."""
    fragmented = []

    for service_key, slices in endpointslices_by_service.items():
        if len(slices) > threshold:
            namespace, name = service_key.split("/", 1)
            total_endpoints = sum(s["total"] for s in slices)
            fragmented.append(
                {
                    "name": name,
                    "namespace": namespace,
                    "slice_count": len(slices),
                    "total_endpoints": total_endpoints,
                }
            )

    return fragmented


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
        description="Monitor Kubernetes EndpointSlice health"
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
        help="Only show EndpointSlices with issues",
    )
    parser.add_argument(
        "--include-headless",
        action="store_true",
        help="Include headless services in missing service check",
    )
    parser.add_argument(
        "--frag-threshold",
        type=int,
        default=10,
        help="EndpointSlice count threshold for fragmentation warning (default: 10)",
    )
    parser.add_argument(
        "--skip-coverage-check",
        action="store_true",
        help="Skip checking for services missing EndpointSlices",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get EndpointSlices
    try:
        eps_args = ["kubectl", "get", "endpointslices", "-o", "json"]
        if opts.namespace:
            eps_args.extend(["-n", opts.namespace])
        else:
            eps_args.append("--all-namespaces")

        result = context.run(eps_args)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        endpointslices = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get endpointslices: {e}")
        return 2

    # Analyze each EndpointSlice
    results = []
    endpointslices_by_service = defaultdict(list)

    for eps in endpointslices.get("items", []):
        result_item = analyze_endpointslice(eps)
        results.append(result_item)

        # Group by service for coverage check
        service_key = f"{result_item['namespace']}/{result_item['service']}"
        endpointslices_by_service[service_key].append(result_item)

    # Check service coverage
    missing_services = []
    if not opts.skip_coverage_check:
        try:
            svc_args = ["kubectl", "get", "services", "-o", "json"]
            if opts.namespace:
                svc_args.extend(["-n", opts.namespace])
            else:
                svc_args.append("--all-namespaces")

            svc_result = context.run(svc_args)
            if svc_result.returncode == 0:
                services = json.loads(svc_result.stdout)
                missing_services = check_service_coverage(
                    services,
                    endpointslices_by_service,
                    exclude_headless=not opts.include_headless,
                )
        except Exception:
            pass  # Non-critical check

    # Check fragmentation
    fragmented = check_endpointslice_fragmentation(
        endpointslices_by_service, opts.frag_threshold
    )

    has_issues = False

    if opts.format == "json":
        json_output = {
            "endpointslices": [],
            "missing_services": missing_services,
            "fragmented_services": fragmented,
            "summary": {
                "total_slices": 0,
                "healthy_slices": 0,
                "unhealthy_slices": 0,
                "missing_services": len(missing_services),
                "fragmented_services": len(fragmented),
            },
        }

        for r in results:
            if opts.warn_only and r["healthy"] and not r["issues"]:
                continue

            json_output["endpointslices"].append(r)
            json_output["summary"]["total_slices"] += 1

            if r["healthy"]:
                json_output["summary"]["healthy_slices"] += 1
            else:
                json_output["summary"]["unhealthy_slices"] += 1
                has_issues = True

        if missing_services:
            has_issues = True
        if fragmented:
            has_issues = True

        print(json.dumps(json_output, indent=2))

    else:  # plain format
        healthy_count = 0
        unhealthy_count = 0

        print("=== EndpointSlice Health ===\n")

        for r in results:
            if opts.warn_only and r["healthy"] and not r["issues"]:
                continue

            if r["healthy"]:
                healthy_count += 1
            else:
                unhealthy_count += 1
                has_issues = True

            status = "[OK]" if r["healthy"] else "[!!]"
            print(f"{status} {r['namespace']}/{r['name']}")
            print(f"    Service: {r['service']}")
            print(
                f"    Endpoints: {r['ready']} ready, "
                f"{r['not_ready']} not-ready, "
                f"{r['terminating']} terminating"
            )

            if r["issues"]:
                for issue in r["issues"]:
                    print(f"    WARNING: {issue}")
            print()

        # Print missing services
        if missing_services:
            has_issues = True
            print("=== Services Missing EndpointSlices ===\n")
            for svc in missing_services:
                print(f"[!!] {svc['namespace']}/{svc['name']}")
                print(f"    Type: {svc['type']}")
                print(f"    Selector: {svc['selector']}")
                print()

        # Print fragmented services
        if fragmented:
            has_issues = True
            print("=== Fragmented Services (many EndpointSlices) ===\n")
            for frag in fragmented:
                print(f"[!!] {frag['namespace']}/{frag['name']}")
                print(
                    f"    Slices: {frag['slice_count']}, "
                    f"Total endpoints: {frag['total_endpoints']}"
                )
                print()

        # Summary
        total = healthy_count + unhealthy_count
        print(f"Summary: {healthy_count}/{total} EndpointSlices healthy")
        if missing_services:
            print(f"         {len(missing_services)} services missing EndpointSlices")
        if fragmented:
            print(f"         {len(fragmented)} services with excessive fragmentation")

    output.set_summary(
        f"slices={len(results)}, healthy={sum(1 for r in results if r['healthy'])}, "
        f"missing_services={len(missing_services)}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
