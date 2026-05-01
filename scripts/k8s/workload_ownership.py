#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [ownership, provenance, operators, helm, argocd, kubernetes]
#   requires: [kubectl]
#   privilege: user
#   brief: Analyze Kubernetes workload ownership and generation chains
#   related: [orphaned_resources_finder, container_restart_analyzer]

"""
Analyze Kubernetes workload ownership and generation chains.

This script traces the ownership chain of pods and workloads to identify
what controller, operator, or user created them. Useful for:
- Understanding what's generating unexpected pods
- Compliance auditing (tracking workload origins)
- Troubleshooting operator-managed workloads
- Identifying orphaned resources without proper ownership

The script follows ownerReferences chains to build a complete picture
of workload provenance, from Pod -> ReplicaSet -> Deployment -> Operator.

Exit codes:
    0 - Success, no issues found
    1 - Issues found (orphaned workloads, unknown generators)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_resource(context: Context, kind: str, name: str, namespace: str) -> dict | None:
    """Get a specific resource by kind, name, and namespace."""
    cmd = ["kubectl", "get", kind.lower(), name, "-n", namespace, "-o", "json"]
    try:
        result = context.run(cmd)
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def get_owner_chain(
    context: Context, resource: dict, namespace: str, visited: set | None = None
) -> list[dict]:
    """
    Recursively trace the ownership chain of a resource.
    Returns a list of owners from immediate parent to root.
    """
    if visited is None:
        visited = set()

    chain = []
    owner_refs = resource.get("metadata", {}).get("ownerReferences", [])

    if not owner_refs:
        return chain

    for owner_ref in owner_refs:
        owner_key = f"{owner_ref['kind']}/{owner_ref['name']}"

        if owner_key in visited:
            continue
        visited.add(owner_key)

        owner_info = {
            "kind": owner_ref["kind"],
            "name": owner_ref["name"],
            "uid": owner_ref.get("uid", ""),
            "controller": owner_ref.get("controller", False),
        }

        owner_resource = get_resource(
            context, owner_ref["kind"], owner_ref["name"], namespace
        )
        if owner_resource:
            owner_info["labels"] = owner_resource.get("metadata", {}).get("labels", {})
            owner_info["annotations"] = owner_resource.get("metadata", {}).get(
                "annotations", {}
            )

            parent_chain = get_owner_chain(context, owner_resource, namespace, visited)
            chain.append(owner_info)
            chain.extend(parent_chain)
        else:
            owner_info["status"] = "not_found"
            chain.append(owner_info)

    return chain


def identify_generator(chain: list, pod: dict) -> dict:
    """
    Identify the ultimate generator/creator of a workload.
    Returns a dict with generator info.
    """
    if not chain:
        created_by = (
            pod.get("metadata", {})
            .get("annotations", {})
            .get("kubernetes.io/created-by", "")
        )

        if created_by:
            return {
                "type": "annotation",
                "generator": "unknown (from annotation)",
                "details": created_by[:100],
            }

        return {
            "type": "standalone",
            "generator": "direct_creation",
            "details": "Pod created directly without controller",
        }

    root = chain[-1]
    root_kind = root["kind"]

    operator_labels = root.get("labels", {})
    operator_annotations = root.get("annotations", {})

    generator_info = {
        "type": "controller",
        "generator": root_kind,
        "name": root["name"],
        "details": "",
    }

    if "app.kubernetes.io/managed-by" in operator_labels:
        generator_info["managed_by"] = operator_labels["app.kubernetes.io/managed-by"]

    if "helm.sh/chart" in operator_labels:
        generator_info["helm_chart"] = operator_labels["helm.sh/chart"]
        generator_info["type"] = "helm"

    if "argocd.argoproj.io/instance" in operator_labels:
        generator_info["argocd_app"] = operator_labels["argocd.argoproj.io/instance"]
        generator_info["type"] = "argocd"

    if "fluxcd.io/sync-checksum" in operator_annotations:
        generator_info["type"] = "flux"

    for label_key in operator_labels:
        if "operator" in label_key.lower():
            generator_info["operator_label"] = (
                f"{label_key}={operator_labels[label_key]}"
            )
            generator_info["type"] = "operator"
            break

    return generator_info


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
        description="Analyze Kubernetes workload ownership and generation chains"
    )

    parser.add_argument(
        "-n",
        "--namespace",
        help="Namespace to analyze (default: all namespaces)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information for all workloads",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show workloads with issues",
    )

    parser.add_argument(
        "--show-chain",
        action="store_true",
        help="Include full ownership chain in output",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get pods
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if opts.namespace:
        cmd.extend(["-n", opts.namespace])
    else:
        cmd.append("--all-namespaces")

    try:
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods = json.loads(result.stdout).get("items", [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    results = {
        "timestamp": datetime.now().isoformat(),
        "namespace_filter": opts.namespace or "all",
        "total_pods": len(pods),
        "workloads": [],
        "summary": {
            "by_generator_type": defaultdict(int),
            "by_root_kind": defaultdict(int),
            "orphaned": 0,
            "standalone": 0,
        },
    }

    for pod in pods:
        pod_name = pod["metadata"]["name"]
        pod_namespace = pod["metadata"].get("namespace", "default")

        chain = get_owner_chain(context, pod, pod_namespace)
        generator = identify_generator(chain, pod)

        workload_info = {
            "pod_name": pod_name,
            "namespace": pod_namespace,
            "generator": generator,
            "chain_length": len(chain),
        }

        if opts.show_chain or opts.verbose:
            workload_info["ownership_chain"] = [
                {"kind": o["kind"], "name": o["name"]} for o in chain
            ]

        issues = []
        if generator["type"] == "standalone":
            issues.append("no_controller")
            results["summary"]["standalone"] += 1

        if any(o.get("status") == "not_found" for o in chain):
            issues.append("orphaned_owner")
            results["summary"]["orphaned"] += 1

        if issues:
            workload_info["issues"] = issues

        results["workloads"].append(workload_info)

        results["summary"]["by_generator_type"][generator["type"]] += 1
        if chain:
            results["summary"]["by_root_kind"][chain[-1]["kind"]] += 1
        else:
            results["summary"]["by_root_kind"]["Pod (direct)"] += 1

    results["summary"]["by_generator_type"] = dict(
        results["summary"]["by_generator_type"]
    )
    results["summary"]["by_root_kind"] = dict(results["summary"]["by_root_kind"])

    # Output results
    if opts.format == "json":
        print(json.dumps(results, indent=2, default=str))

    elif opts.format == "table":
        print(
            f"{'Namespace':<20} {'Pod':<35} {'Generator':<15} "
            f"{'Root Kind':<15} {'Issues':<15}"
        )
        print("=" * 100)

        for w in results["workloads"]:
            if opts.warn_only and "issues" not in w:
                continue

            ns = w["namespace"][:19]
            pod = w["pod_name"][:34]
            gen_type = w["generator"]["type"][:14]

            if "ownership_chain" in w and w["ownership_chain"]:
                root_kind = w["ownership_chain"][-1]["kind"][:14]
            elif w["chain_length"] > 0:
                root_kind = w["generator"].get("generator", "Unknown")[:14]
            else:
                root_kind = "Pod (direct)"[:14]

            issues_str = ", ".join(w.get("issues", []))[:14] or "-"

            print(
                f"{ns:<20} {pod:<35} {gen_type:<15} {root_kind:<15} {issues_str:<15}"
            )

    else:  # plain
        if not opts.warn_only:
            print("Workload Generation Analysis")
            print(f"Namespace: {results['namespace_filter']}")
            print(f"Total Pods: {results['total_pods']}")
            print("=" * 60)
            print()

            print("Generator Summary:")
            print("-" * 40)
            for gen_type, count in sorted(
                results["summary"]["by_generator_type"].items()
            ):
                print(f"  {gen_type}: {count}")
            print()

            print("Root Controller Types:")
            print("-" * 40)
            for kind, count in sorted(results["summary"]["by_root_kind"].items()):
                print(f"  {kind}: {count}")
            print()

        issues_found = [w for w in results["workloads"] if "issues" in w]

        if issues_found:
            print("Issues Found:")
            print("-" * 60)
            for w in issues_found:
                print(f"  {w['namespace']}/{w['pod_name']}")
                print(f"    Issues: {', '.join(w['issues'])}")
                print(
                    f"    Generator: {w['generator']['type']} - "
                    f"{w['generator'].get('name', 'N/A')}"
                )
            print()
        elif not opts.warn_only:
            print("No issues found - all workloads have proper ownership")

        if opts.verbose and not opts.warn_only:
            print()
            print("All Workloads:")
            print("-" * 60)
            for w in results["workloads"]:
                gen = w["generator"]
                print(f"  {w['namespace']}/{w['pod_name']}")
                print(
                    f"    Type: {gen['type']}, Generator: {gen.get('generator', 'N/A')}"
                )
                if "ownership_chain" in w:
                    chain_str = " -> ".join(
                        f"{o['kind']}/{o['name']}" for o in w["ownership_chain"]
                    )
                    print(f"    Chain: Pod -> {chain_str}")
                print()

    has_issues = (
        results["summary"]["orphaned"] > 0 or results["summary"]["standalone"] > 0
    )
    output.set_summary(
        f"pods={results['total_pods']}, "
        f"orphaned={results['summary']['orphaned']}, "
        f"standalone={results['summary']['standalone']}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
