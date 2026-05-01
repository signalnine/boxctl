#!/usr/bin/env python3
# boxctl:
#   category: k8s/config
#   tags: [configmap, audit, best-practices, storage]
#   requires: [kubectl]
#   privilege: user
#   related: [secret_audit]
#   brief: Audit Kubernetes ConfigMaps for common issues

"""
Audit Kubernetes ConfigMaps for common issues and best practices.

Checks for:
- ConfigMaps approaching size limits (1MB)
- Unused ConfigMaps (not referenced by any pod)
- Large ConfigMaps that could cause etcd performance issues
- ConfigMaps with missing keys referenced by pods
- ConfigMaps in default namespace
- Empty ConfigMaps

Exit codes:
    0 - No issues found
    1 - Issues detected (warnings)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# ConfigMap size limit in Kubernetes (1MB)
CONFIGMAP_SIZE_LIMIT = 1024 * 1024
# Warning threshold (80% of limit)
SIZE_WARNING_THRESHOLD = 0.8 * CONFIGMAP_SIZE_LIMIT
# Large ConfigMap threshold for performance warnings (100KB)
LARGE_CONFIGMAP_THRESHOLD = 100 * 1024


def get_configmaps(context: Context, namespace: str | None = None) -> list[dict[str, Any]]:
    """Get all ConfigMaps with their data."""
    cmd = ["kubectl", "get", "configmaps", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout).get("items", [])


def get_pods(context: Context, namespace: str | None = None) -> list[dict[str, Any]]:
    """Get all pods with their specs."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout).get("items", [])


def calculate_configmap_size(configmap: dict[str, Any]) -> int:
    """Calculate the approximate size of a ConfigMap in bytes."""
    size = 0
    data = configmap.get("data", {})
    binary_data = configmap.get("binaryData", {})

    for key, value in data.items():
        size += len(key.encode("utf-8"))
        size += len(value.encode("utf-8")) if value else 0

    for key, value in binary_data.items():
        size += len(key.encode("utf-8"))
        # binaryData is base64 encoded, actual size is ~75% of encoded
        size += int(len(value) * 0.75) if value else 0

    return size


def get_configmap_references(pods: list[dict[str, Any]]) -> dict[tuple[str, str], set[str]]:
    """Extract ConfigMap references from pods."""
    references: dict[tuple[str, str], set[str]] = defaultdict(set)

    for pod in pods:
        pod_namespace = pod["metadata"]["namespace"]
        pod_name = pod["metadata"]["name"]
        spec = pod.get("spec", {})

        # Check volumes
        for volume in spec.get("volumes", []):
            if "configMap" in volume:
                cm_name = volume["configMap"].get("name")
                if cm_name:
                    references[(pod_namespace, cm_name)].add(f"pod/{pod_name} (volume)")

        # Check containers
        for container in spec.get("containers", []) + spec.get("initContainers", []):
            # Check envFrom
            for env_from in container.get("envFrom", []):
                if "configMapRef" in env_from:
                    cm_name = env_from["configMapRef"].get("name")
                    if cm_name:
                        references[(pod_namespace, cm_name)].add(
                            f"pod/{pod_name} ({container['name']} envFrom)"
                        )

            # Check env valueFrom
            for env in container.get("env", []):
                value_from = env.get("valueFrom", {})
                if "configMapKeyRef" in value_from:
                    cm_name = value_from["configMapKeyRef"].get("name")
                    if cm_name:
                        references[(pod_namespace, cm_name)].add(
                            f"pod/{pod_name} ({container['name']} env:{env['name']})"
                        )

    return references


def get_key_references(pods: list[dict[str, Any]]) -> dict[tuple[str, str], set[str]]:
    """Extract specific key references from ConfigMaps in pods."""
    key_refs: dict[tuple[str, str], set[str]] = defaultdict(set)

    for pod in pods:
        pod_namespace = pod["metadata"]["namespace"]
        spec = pod.get("spec", {})

        # Check volumes with items
        for volume in spec.get("volumes", []):
            if "configMap" in volume:
                cm_name = volume["configMap"].get("name")
                items = volume["configMap"].get("items", [])
                for item in items:
                    key = item.get("key")
                    if key:
                        key_refs[(pod_namespace, cm_name)].add(key)

        # Check containers for env valueFrom
        for container in spec.get("containers", []) + spec.get("initContainers", []):
            for env in container.get("env", []):
                value_from = env.get("valueFrom", {})
                if "configMapKeyRef" in value_from:
                    cm_ref = value_from["configMapKeyRef"]
                    cm_name = cm_ref.get("name")
                    key = cm_ref.get("key")
                    if cm_name and key:
                        key_refs[(pod_namespace, cm_name)].add(key)

    return key_refs


def audit_configmaps(
    configmaps: list[dict[str, Any]],
    pods: list[dict[str, Any]],
    verbose: bool = False
) -> dict[str, list[dict[str, Any]]]:
    """Audit ConfigMaps for issues."""
    issues: dict[str, list[dict[str, Any]]] = {
        "approaching_limit": [],
        "large_configmaps": [],
        "unused": [],
        "missing_keys": [],
        "default_namespace": [],
        "empty": []
    }

    cm_references = get_configmap_references(pods)
    key_references = get_key_references(pods)

    for cm in configmaps:
        name = cm["metadata"]["name"]
        namespace = cm["metadata"]["namespace"]
        cm_key = (namespace, name)

        # Skip system ConfigMaps
        if name.startswith("kube-") or namespace in ["kube-system", "kube-public"]:
            if not verbose:
                continue

        # Calculate size
        size = calculate_configmap_size(cm)
        size_kb = size / 1024

        # Check if approaching size limit
        if size >= SIZE_WARNING_THRESHOLD:
            issues["approaching_limit"].append({
                "namespace": namespace,
                "name": name,
                "size_bytes": size,
                "size_kb": round(size_kb, 2),
                "percent_of_limit": round((size / CONFIGMAP_SIZE_LIMIT) * 100, 1)
            })

        # Check for large ConfigMaps (performance concern)
        elif size >= LARGE_CONFIGMAP_THRESHOLD:
            issues["large_configmaps"].append({
                "namespace": namespace,
                "name": name,
                "size_bytes": size,
                "size_kb": round(size_kb, 2)
            })

        # Check if unused
        if cm_key not in cm_references:
            # Skip known system ConfigMaps
            if not (name.endswith("-lock") or
                    name.startswith("extension-apiserver-authentication") or
                    name.startswith("cluster-info") or
                    name.startswith("coredns") or
                    name.startswith("kubeadm-config") or
                    name.startswith("kubelet-config")):
                issues["unused"].append({
                    "namespace": namespace,
                    "name": name,
                    "size_bytes": size
                })

        # Check for missing keys
        if cm_key in key_references:
            cm_data = cm.get("data", {})
            cm_binary_data = cm.get("binaryData", {})
            all_keys = set(cm_data.keys()) | set(cm_binary_data.keys())

            missing = key_references[cm_key] - all_keys
            if missing:
                issues["missing_keys"].append({
                    "namespace": namespace,
                    "name": name,
                    "missing_keys": list(missing),
                    "available_keys": list(all_keys)
                })

        # Check for ConfigMaps in default namespace
        if namespace == "default" and not name.startswith("kube-"):
            issues["default_namespace"].append({
                "namespace": namespace,
                "name": name
            })

        # Check for empty ConfigMaps
        data = cm.get("data", {})
        binary_data = cm.get("binaryData", {})
        if not data and not binary_data:
            issues["empty"].append({
                "namespace": namespace,
                "name": name
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
        description="Audit Kubernetes ConfigMaps for common issues"
    )
    parser.add_argument("-n", "--namespace", help="Namespace to check (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Include system namespaces")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show warnings")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl to use this script.")
        return 2

    try:
        configmaps = get_configmaps(context, opts.namespace)
        pods = get_pods(context, opts.namespace)
    except Exception as e:
        output.error(f"Failed to get resources: {e}")
        return 2

    if not configmaps:
        output.warning("No ConfigMaps found")
        output.emit({"issues": {}})
        return 0

    issues = audit_configmaps(configmaps, pods, verbose=opts.verbose)

    # Calculate summary
    critical_issues = len(issues["approaching_limit"]) + len(issues["missing_keys"])
    info_issues = (
        len(issues["large_configmaps"]) +
        len(issues["unused"]) +
        len(issues["empty"]) +
        len(issues["default_namespace"])
    )

    output.emit({
        "issues": issues,
        "summary": {
            "approaching_limit": len(issues["approaching_limit"]),
            "large_configmaps": len(issues["large_configmaps"]),
            "unused": len(issues["unused"]),
            "missing_keys": len(issues["missing_keys"]),
            "empty": len(issues["empty"]),
            "default_namespace": len(issues["default_namespace"]),
        }
    })

    if critical_issues == 0 and info_issues == 0:
        output.set_summary("No ConfigMap issues detected")
    else:
        output.set_summary(f"{critical_issues} critical, {info_issues} info")

    return 1 if critical_issues > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
