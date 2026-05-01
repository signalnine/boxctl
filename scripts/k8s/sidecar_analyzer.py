#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [sidecars, pods, service-mesh, istio, envoy, kubernetes]
#   requires: [kubectl]
#   privilege: user
#   brief: Analyze Kubernetes sidecar container patterns and resource usage
#   related: [container_restart_analyzer, node_capacity]

"""
Analyze Kubernetes sidecar container patterns and resource usage.

Sidecar containers are commonly used for logging, service mesh proxies,
monitoring, and secrets management. This script identifies:

- Pods with sidecar containers (detected by common patterns)
- Resource overhead from sidecar containers
- Sidecar containers not in ready state
- Service mesh proxy issues (Istio, Linkerd, Consul)
- Sidecar containers with high restart counts
- Resource imbalances between main and sidecar containers

Exit codes:
    0 - No sidecar issues detected
    1 - Sidecar issues found
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


# Common sidecar container name patterns
SIDECAR_PATTERNS = {
    # Service mesh proxies
    "istio-proxy": "Istio sidecar proxy",
    "envoy": "Envoy proxy (generic)",
    "linkerd-proxy": "Linkerd sidecar proxy",
    "consul-connect-envoy": "Consul Connect Envoy proxy",
    "consul-dataplane": "Consul dataplane sidecar",
    # Logging sidecars
    "fluentd": "Fluentd logging sidecar",
    "fluent-bit": "Fluent Bit logging sidecar",
    "filebeat": "Elastic Filebeat logging sidecar",
    "promtail": "Grafana Promtail logging sidecar",
    "vector": "Vector logging sidecar",
    "logrotate": "Log rotation sidecar",
    # Secrets/config management
    "vault-agent": "HashiCorp Vault agent",
    "vault-agent-init": "Vault agent init container",
    "aws-secrets-manager": "AWS Secrets Manager sidecar",
    "secrets-store": "CSI Secrets Store sidecar",
    # Monitoring/observability
    "jaeger-agent": "Jaeger tracing agent",
    "otel-agent": "OpenTelemetry agent",
    "opentelemetry": "OpenTelemetry collector sidecar",
    "datadog-agent": "Datadog agent sidecar",
    "prometheus-exporter": "Prometheus exporter sidecar",
    # Cloud-specific
    "cloudsql-proxy": "Google Cloud SQL proxy",
    "cloud-sql-proxy": "Google Cloud SQL proxy",
    "gce-proxy": "Google Compute Engine proxy",
    # Other common patterns
    "oauth2-proxy": "OAuth2 proxy sidecar",
    "nginx-sidecar": "Nginx sidecar",
    "haproxy": "HAProxy sidecar",
}

# Known service mesh namespace annotations
MESH_ANNOTATIONS = {
    "sidecar.istio.io/inject": "istio",
    "linkerd.io/inject": "linkerd",
    "consul.hashicorp.com/connect-inject": "consul",
}


def identify_sidecar_type(container_name: str, image: str) -> tuple[bool, str, str]:
    """
    Identify if a container is a sidecar and what type.

    Returns:
        (is_sidecar, sidecar_type, description)
    """
    name_lower = container_name.lower()
    image_lower = image.lower()

    # Check against known patterns
    for pattern, desc in SIDECAR_PATTERNS.items():
        if pattern in name_lower or pattern in image_lower:
            return True, pattern, desc

    # Additional image-based detection
    if "istio/proxyv2" in image_lower:
        return True, "istio-proxy", "Istio sidecar proxy"
    if "linkerd" in image_lower and "proxy" in image_lower:
        return True, "linkerd-proxy", "Linkerd sidecar proxy"
    if "envoy" in image_lower and "envoyproxy" in image_lower:
        return True, "envoy", "Envoy proxy"
    if "gcr.io/cloudsql-docker" in image_lower:
        return True, "cloudsql-proxy", "Google Cloud SQL proxy"

    # Heuristic: container with "sidecar" in name
    if "sidecar" in name_lower:
        return True, "generic-sidecar", "Generic sidecar container"

    return False, "", ""


def parse_resource_quantity(value: str) -> int:
    """Parse Kubernetes resource quantity to millicores/bytes."""
    if not value:
        return 0

    value = value.strip()

    # CPU
    if value.endswith("m"):
        return int(value[:-1])
    elif value.endswith("n"):
        return int(value[:-1]) // 1000000

    # Memory
    suffixes = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
    }

    for suffix, multiplier in suffixes.items():
        if value.endswith(suffix):
            return int(float(value[: -len(suffix)]) * multiplier)

    # Plain number (CPU cores or bytes)
    try:
        num = float(value)
        if num < 100:  # Likely CPU cores
            return int(num * 1000)
        return int(num)
    except ValueError:
        return 0


def format_cpu(millicores: int) -> str:
    """Format millicores to human readable."""
    if millicores >= 1000:
        return f"{millicores / 1000:.1f} cores"
    return f"{millicores}m"


def format_memory(bytes_val: int) -> str:
    """Format bytes to human readable."""
    if bytes_val >= 1024**3:
        return f"{bytes_val / (1024 ** 3):.1f}Gi"
    elif bytes_val >= 1024**2:
        return f"{bytes_val / (1024 ** 2):.1f}Mi"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f}Ki"
    return f"{bytes_val}B"


def analyze_pod(pod: dict) -> dict:
    """Analyze a pod for sidecar containers and issues."""
    metadata = pod.get("metadata", {})
    spec = pod.get("spec", {})
    status = pod.get("status", {})

    pod_info = {
        "name": metadata.get("name", "unknown"),
        "namespace": metadata.get("namespace", "default"),
        "phase": status.get("phase", "Unknown"),
        "node": spec.get("nodeName", ""),
        "containers": [],
        "sidecars": [],
        "issues": [],
        "sidecar_resources": {
            "cpu_request": 0,
            "cpu_limit": 0,
            "memory_request": 0,
            "memory_limit": 0,
        },
        "main_resources": {
            "cpu_request": 0,
            "cpu_limit": 0,
            "memory_request": 0,
            "memory_limit": 0,
        },
        "mesh_enabled": None,
        "expected_mesh": None,
    }

    # Check for mesh annotations
    annotations = metadata.get("annotations", {})
    labels = metadata.get("labels", {})

    for annotation, mesh_type in MESH_ANNOTATIONS.items():
        if annotation in annotations:
            value = annotations[annotation].lower()
            if value in ["true", "enabled", "yes"]:
                pod_info["expected_mesh"] = mesh_type

    # Check for Istio-specific labels
    if labels.get("security.istio.io/tlsMode") == "istio":
        pod_info["expected_mesh"] = "istio"

    containers = spec.get("containers", [])
    container_statuses = {s["name"]: s for s in status.get("containerStatuses", [])}

    for container in containers:
        name = container.get("name", "unknown")
        image = container.get("image", "")
        resources = container.get("resources", {})

        is_sidecar, sidecar_type, sidecar_desc = identify_sidecar_type(name, image)

        container_info = {
            "name": name,
            "image": image.split("/")[-1][:50],
            "is_sidecar": is_sidecar,
            "sidecar_type": sidecar_type,
            "sidecar_desc": sidecar_desc,
            "resources": resources,
        }

        # Get container status
        c_status = container_statuses.get(name, {})
        container_info["ready"] = c_status.get("ready", False)
        container_info["restart_count"] = c_status.get("restartCount", 0)
        container_info["state"] = list(c_status.get("state", {}).keys())

        pod_info["containers"].append(container_info)

        # Parse resources
        requests = resources.get("requests", {})
        limits = resources.get("limits", {})

        cpu_req = parse_resource_quantity(requests.get("cpu", "0"))
        cpu_lim = parse_resource_quantity(limits.get("cpu", "0"))
        mem_req = parse_resource_quantity(requests.get("memory", "0"))
        mem_lim = parse_resource_quantity(limits.get("memory", "0"))

        container_info["cpu_request"] = cpu_req
        container_info["cpu_limit"] = cpu_lim
        container_info["memory_request"] = mem_req
        container_info["memory_limit"] = mem_lim

        if is_sidecar:
            pod_info["sidecars"].append(container_info)
            pod_info["sidecar_resources"]["cpu_request"] += cpu_req
            pod_info["sidecar_resources"]["cpu_limit"] += cpu_lim
            pod_info["sidecar_resources"]["memory_request"] += mem_req
            pod_info["sidecar_resources"]["memory_limit"] += mem_lim

            # Track mesh presence
            if sidecar_type in ["istio-proxy", "linkerd-proxy", "consul-connect-envoy"]:
                pod_info["mesh_enabled"] = sidecar_type.split("-")[0]
        else:
            pod_info["main_resources"]["cpu_request"] += cpu_req
            pod_info["main_resources"]["cpu_limit"] += cpu_lim
            pod_info["main_resources"]["memory_request"] += mem_req
            pod_info["main_resources"]["memory_limit"] += mem_lim

    return pod_info


def find_issues(pod_info: dict) -> list[dict]:
    """Find issues with sidecar containers in a pod."""
    issues = []

    # Check for expected mesh missing
    if pod_info["expected_mesh"] and not pod_info["mesh_enabled"]:
        issues.append(
            {
                "type": "mesh_injection_failed",
                "severity": "CRITICAL",
                "message": f"Expected {pod_info['expected_mesh']} sidecar not found",
                "detail": "Mesh injection may have failed",
            }
        )

    for sidecar in pod_info["sidecars"]:
        name = sidecar["name"]

        # Check for not ready sidecars
        if not sidecar["ready"] and pod_info["phase"] == "Running":
            issues.append(
                {
                    "type": "sidecar_not_ready",
                    "severity": "WARNING",
                    "container": name,
                    "message": f"Sidecar '{name}' is not ready",
                    "detail": sidecar.get("sidecar_desc", ""),
                }
            )

        # Check for high restart count
        if sidecar["restart_count"] >= 3:
            issues.append(
                {
                    "type": "sidecar_high_restarts",
                    "severity": "WARNING",
                    "container": name,
                    "restart_count": sidecar["restart_count"],
                    "message": (
                        f"Sidecar '{name}' has restarted "
                        f"{sidecar['restart_count']} times"
                    ),
                }
            )

        # Check for crash loop
        if "waiting" in sidecar["state"]:
            issues.append(
                {
                    "type": "sidecar_waiting",
                    "severity": "CRITICAL",
                    "container": name,
                    "message": f"Sidecar '{name}' is in waiting state",
                }
            )

        # Check for missing resource limits
        if not sidecar["cpu_limit"] and not sidecar["memory_limit"]:
            issues.append(
                {
                    "type": "sidecar_no_limits",
                    "severity": "INFO",
                    "container": name,
                    "message": f"Sidecar '{name}' has no resource limits",
                }
            )

    # Check for resource imbalance
    sidecar_cpu = pod_info["sidecar_resources"]["cpu_request"]
    main_cpu = pod_info["main_resources"]["cpu_request"]
    sidecar_mem = pod_info["sidecar_resources"]["memory_request"]
    main_mem = pod_info["main_resources"]["memory_request"]

    if sidecar_cpu > main_cpu and main_cpu > 0:
        issues.append(
            {
                "type": "sidecar_cpu_exceeds_main",
                "severity": "INFO",
                "message": (
                    f"Sidecar CPU requests ({format_cpu(sidecar_cpu)}) "
                    f"exceed main container ({format_cpu(main_cpu)})"
                ),
            }
        )

    if sidecar_mem > main_mem and main_mem > 0:
        issues.append(
            {
                "type": "sidecar_memory_exceeds_main",
                "severity": "INFO",
                "message": (
                    f"Sidecar memory requests ({format_memory(sidecar_mem)}) "
                    f"exceed main container ({format_memory(main_mem)})"
                ),
            }
        )

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
        description="Analyze Kubernetes sidecar container patterns and resource usage"
    )

    parser.add_argument(
        "-n",
        "--namespace",
        help="Check specific namespace (default: all namespaces)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show pods with issues",
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
        all_pods = json.loads(result.stdout).get("items", [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not all_pods:
        print("No pods found.")
        return 0

    # Analyze pods for sidecars
    pods_with_sidecars = []
    total_issues = 0
    by_issue_type = defaultdict(int)
    sidecar_types = defaultdict(int)
    total_resources = {
        "cpu_request": 0,
        "cpu_limit": 0,
        "memory_request": 0,
        "memory_limit": 0,
    }

    for pod in all_pods:
        pod_info = analyze_pod(pod)

        if pod_info["sidecars"]:
            issues = find_issues(pod_info)
            pod_info["issues"] = issues

            pods_with_sidecars.append(pod_info)

            for sidecar in pod_info["sidecars"]:
                sidecar_types[sidecar["sidecar_type"]] += 1

            for key in total_resources:
                total_resources[key] += pod_info["sidecar_resources"][key]

            for issue in issues:
                total_issues += 1
                by_issue_type[issue["type"]] += 1

    # Build summary
    summary = {
        "total_pods": len(all_pods),
        "pods_with_sidecars": len(pods_with_sidecars),
        "total_sidecars": sum(sidecar_types.values()),
        "pods_with_issues": len([p for p in pods_with_sidecars if p.get("issues")]),
        "total_issues": total_issues,
        "sidecar_types": dict(sidecar_types),
        "by_issue_type": dict(by_issue_type),
        "total_resources": total_resources,
    }

    # Handle warn-only with no issues
    if opts.warn_only and total_issues == 0:
        if opts.format == "json":
            print(json.dumps({"summary": summary, "pods": []}, indent=2))
        output.set_summary(
            f"sidecars={summary['total_sidecars']}, issues={total_issues}"
        )
        return 0

    # Output results
    if opts.format == "json":
        output_data = {
            "summary": summary,
            "pods": [p for p in pods_with_sidecars if p.get("issues")],
        }
        print(json.dumps(output_data, indent=2, default=str))

    elif opts.format == "table":
        print(
            f"{'NAMESPACE':<20} {'POD':<30} {'SIDECARS':<20} {'ISSUE':<30}"
        )
        print("=" * 105)

        pods_with_issues = [p for p in pods_with_sidecars if p.get("issues")]

        if not pods_with_issues:
            if not opts.warn_only:
                print("No sidecar issues found.")
        else:
            for pod in pods_with_issues:
                sidecar_str = ", ".join(
                    [s["sidecar_type"][:8] for s in pod["sidecars"]]
                )
                for i, issue in enumerate(pod["issues"]):
                    if i == 0:
                        print(
                            f"{pod['namespace']:<20} "
                            f"{pod['name'][:28]:<30} "
                            f"{sidecar_str:<20} "
                            f"[{issue['severity']}] {issue['type']}"
                        )
                    else:
                        print(
                            f"{'':20} {'':30} {'':20} "
                            f"[{issue['severity']}] {issue['type']}"
                        )

        print()
        print(
            f"Summary: {summary['pods_with_sidecars']} pods with sidecars, "
            f"{summary['pods_with_issues']} with issues"
        )

    else:  # plain
        print("Kubernetes Sidecar Container Analysis")
        print("=" * 70)

        print(f"\nTotal pods analyzed: {summary['total_pods']}")
        print(f"Pods with sidecars: {summary['pods_with_sidecars']}")
        print(f"Total sidecar containers: {summary['total_sidecars']}")
        print(f"Pods with sidecar issues: {summary['pods_with_issues']}")

        if summary["sidecar_types"]:
            print("\nSidecar Types Found:")
            for stype, count in sorted(
                summary["sidecar_types"].items(), key=lambda x: x[1], reverse=True
            ):
                print(f"  {stype}: {count}")

        if summary["total_resources"]["cpu_request"] > 0:
            print("\nTotal Sidecar Resource Usage:")
            print(
                f"  CPU Requests: "
                f"{format_cpu(summary['total_resources']['cpu_request'])}"
            )
            print(
                f"  CPU Limits:   "
                f"{format_cpu(summary['total_resources']['cpu_limit'])}"
            )
            print(
                f"  Mem Requests: "
                f"{format_memory(summary['total_resources']['memory_request'])}"
            )
            print(
                f"  Mem Limits:   "
                f"{format_memory(summary['total_resources']['memory_limit'])}"
            )

        if summary["by_issue_type"]:
            print("\nIssues by Type:")
            for issue_type, count in sorted(
                summary["by_issue_type"].items(), key=lambda x: x[1], reverse=True
            ):
                print(f"  {issue_type}: {count}")

        pods_with_issues = [p for p in pods_with_sidecars if p.get("issues")]

        if pods_with_issues:
            print("\n" + "-" * 70)
            print("PODS WITH SIDECAR ISSUES:")
            print("-" * 70)

            for pod in pods_with_issues:
                print(f"\n{pod['namespace']}/{pod['name']} ({pod['phase']})")
                print(f"  Node: {pod.get('node', 'n/a')}")

                sidecar_names = [s["name"] for s in pod["sidecars"]]
                print(f"  Sidecars: {', '.join(sidecar_names)}")

                for issue in pod["issues"]:
                    severity = issue.get("severity", "INFO")
                    print(f"  [{severity}] {issue['message']}")
                    if opts.verbose and issue.get("detail"):
                        print(f"    Detail: {issue['detail']}")

        elif not opts.warn_only and pods_with_sidecars:
            print("\n" + "-" * 70)
            print("PODS WITH SIDECARS (no issues):")
            print("-" * 70)

            for pod in pods_with_sidecars[:20]:
                sidecar_types_list = [s["sidecar_type"] for s in pod["sidecars"]]
                print(
                    f"  {pod['namespace']}/{pod['name']}: "
                    f"{', '.join(sidecar_types_list)}"
                )

            if len(pods_with_sidecars) > 20:
                print(f"  ... and {len(pods_with_sidecars) - 20} more")

        print()

    output.set_summary(f"sidecars={summary['total_sidecars']}, issues={total_issues}")

    return 1 if total_issues > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
