#!/usr/bin/env python3
# boxctl:
#   category: baremetal/services
#   tags: [health, service, dns, resolver, network]
#   requires: []
#   privilege: user
#   related: [route_health_monitor]
#   brief: Monitor DNS resolver configuration and health

"""
Monitor DNS resolver configuration and health.

Checks /etc/resolv.conf configuration, validates nameserver reachability,
tests DNS resolution, and monitors systemd-resolved status if present.
Critical for large-scale environments where DNS issues cause cascading failures.

Exit codes:
    0 - All resolvers healthy and reachable
    1 - DNS issues detected (unreachable resolvers, resolution failures)
    2 - Usage error or missing dependency
"""

import argparse
import re
import socket
import time
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


DEFAULT_TEST_DOMAINS = ["google.com", "cloudflare.com"]
DEFAULT_TIMEOUT = 2.0


def read_resolv_conf(context: Context, path: str = "/etc/resolv.conf") -> dict[str, Any]:
    """Parse /etc/resolv.conf and extract configuration."""
    config: dict[str, Any] = {
        "nameservers": [],
        "search_domains": [],
        "options": [],
        "path": path,
        "exists": False,
        "readable": False,
    }

    if not context.file_exists(path):
        return config

    config["exists"] = True

    try:
        content = context.read_file(path)
        config["readable"] = True
    except Exception:
        return config

    for line in content.split("\n"):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                config["nameservers"].append(parts[1])
        elif line.startswith("search") or line.startswith("domain"):
            parts = line.split()
            if len(parts) >= 2:
                config["search_domains"].extend(parts[1:])
        elif line.startswith("options"):
            parts = line.split()
            if len(parts) >= 2:
                config["options"].extend(parts[1:])

    return config


def check_systemd_resolved(context: Context) -> dict[str, Any] | None:
    """Check if systemd-resolved is running and get its status."""
    status: dict[str, Any] = {
        "running": False,
        "dns_servers": [],
        "current_dns": [],
        "dnssec": None,
    }

    # Check if systemd-resolved is active
    result = context.run(["systemctl", "is-active", "systemd-resolved"], check=False)
    status["running"] = result.returncode == 0 and result.stdout.strip() == "active"

    if not status["running"]:
        return status

    # Get DNS server information from resolvectl
    result = context.run(["resolvectl", "status"], check=False)
    if result.returncode == 0:
        for line in result.stdout.split("\n"):
            line = line.strip()
            if "DNS Servers:" in line or "Current DNS Server:" in line:
                match = re.search(r":\s*(.+)", line)
                if match:
                    servers = match.group(1).split()
                    if "Current" in line:
                        status["current_dns"] = servers
                    else:
                        status["dns_servers"].extend(servers)
            elif "DNSSEC" in line:
                match = re.search(r":\s*(.+)", line)
                if match:
                    status["dnssec"] = match.group(1).strip()

    return status


def test_nameserver_reachability(
    nameserver: str, timeout: float = DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """Test if a nameserver is reachable via DNS query."""
    result: dict[str, Any] = {
        "nameserver": nameserver,
        "reachable": False,
        "latency_ms": None,
        "error": None,
    }

    try:
        start_time = time.time()

        # Use socket to test UDP connectivity to port 53
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Simple DNS query for 'google.com' A record
        query = (
            b"\x12\x34"  # Transaction ID
            b"\x01\x00"  # Flags: standard query
            b"\x00\x01"  # Questions: 1
            b"\x00\x00"  # Answers: 0
            b"\x00\x00"  # Authority: 0
            b"\x00\x00"  # Additional: 0
            b"\x06google\x03com\x00"  # QNAME: google.com
            b"\x00\x01"  # QTYPE: A
            b"\x00\x01"  # QCLASS: IN
        )

        sock.sendto(query, (nameserver, 53))
        response, _ = sock.recvfrom(512)
        sock.close()

        end_time = time.time()
        result["latency_ms"] = (end_time - start_time) * 1000
        result["reachable"] = len(response) > 12

    except socket.timeout:
        result["error"] = "timeout"
    except socket.gaierror as e:
        result["error"] = f"address error: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


def test_dns_resolution(
    domain: str, timeout: float = DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """Test DNS resolution for a specific domain."""
    result: dict[str, Any] = {
        "domain": domain,
        "resolved": False,
        "addresses": [],
        "latency_ms": None,
        "error": None,
    }

    try:
        start_time = time.time()
        socket.setdefaulttimeout(timeout)
        addresses = socket.gethostbyname_ex(domain)
        end_time = time.time()

        result["resolved"] = True
        result["addresses"] = addresses[2]
        result["latency_ms"] = (end_time - start_time) * 1000

    except socket.gaierror as e:
        result["error"] = str(e)
    except socket.timeout:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_dns_health(
    resolv_conf: dict[str, Any],
    resolved_status: dict[str, Any] | None,
    nameserver_results: list[dict[str, Any]],
    resolution_tests: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Analyze overall DNS health and return issues."""
    issues: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    # Check resolv.conf exists and is readable
    if not resolv_conf["exists"]:
        issues.append({
            "severity": "critical",
            "type": "missing_resolv_conf",
            "message": "/etc/resolv.conf does not exist",
        })
    elif not resolv_conf["readable"]:
        issues.append({
            "severity": "critical",
            "type": "unreadable_resolv_conf",
            "message": "/etc/resolv.conf is not readable",
        })

    # Check for nameservers
    if resolv_conf["exists"] and not resolv_conf["nameservers"]:
        issues.append({
            "severity": "critical",
            "type": "no_nameservers",
            "message": "No nameservers configured in /etc/resolv.conf",
        })

    # Check nameserver reachability
    unreachable_count = 0
    for ns_result in nameserver_results:
        if not ns_result["reachable"]:
            unreachable_count += 1
            severity = (
                "warning"
                if unreachable_count < len(nameserver_results)
                else "critical"
            )
            issues.append({
                "severity": severity,
                "type": "nameserver_unreachable",
                "message": f"Nameserver {ns_result['nameserver']} is unreachable: {ns_result['error']}",
            })
        elif ns_result["latency_ms"] and ns_result["latency_ms"] > 500:
            warnings.append({
                "severity": "warning",
                "type": "nameserver_slow",
                "message": f"Nameserver {ns_result['nameserver']} has high latency ({ns_result['latency_ms']:.0f}ms)",
            })

    # Check if all nameservers are unreachable
    if unreachable_count == len(nameserver_results) and nameserver_results:
        for issue in issues:
            if issue["type"] == "nameserver_unreachable":
                issue["severity"] = "critical"

    # Check resolution tests
    for res_test in resolution_tests:
        if not res_test["resolved"]:
            issues.append({
                "severity": "critical",
                "type": "resolution_failure",
                "message": f"Failed to resolve {res_test['domain']}: {res_test['error']}",
            })

    # Check systemd-resolved status
    if resolved_status:
        if resolved_status["running"]:
            # Could add more checks here
            pass

    # Check for loopback-only configuration
    if resolv_conf["nameservers"]:
        all_loopback = all(
            ns.startswith("127.") or ns == "::1"
            for ns in resolv_conf["nameservers"]
        )
        if all_loopback and not (resolved_status and resolved_status["running"]):
            warnings.append({
                "severity": "warning",
                "type": "loopback_only_no_resolver",
                "message": "Only loopback nameservers configured but no local resolver running",
            })

    return issues, warnings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor DNS resolver configuration and health"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json", "table"], default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show warnings and issues"
    )
    parser.add_argument(
        "--no-reachability", action="store_true",
        help="Skip nameserver reachability tests",
    )
    parser.add_argument(
        "--no-resolution", action="store_true",
        help="Skip DNS resolution tests",
    )
    parser.add_argument(
        "--test-domain", action="append", dest="test_domains",
        metavar="DOMAIN", help="Additional domain to test resolution",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Timeout in seconds for DNS tests (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--resolv-conf", default="/etc/resolv.conf",
        help="Path to resolv.conf (default: /etc/resolv.conf)",
    )
    opts = parser.parse_args(args)

    if opts.timeout <= 0:
        output.error("Timeout must be a positive number")

        output.render(opts.format, "Monitor DNS resolver configuration and health")
        return 2

    # Read resolv.conf
    resolv_conf = read_resolv_conf(context, opts.resolv_conf)

    # Check systemd-resolved status
    resolved_status = check_systemd_resolved(context)

    # Test nameserver reachability
    nameserver_results: list[dict[str, Any]] = []
    if not opts.no_reachability and resolv_conf["nameservers"]:
        for ns in resolv_conf["nameservers"]:
            result = test_nameserver_reachability(ns, timeout=opts.timeout)
            nameserver_results.append(result)

    # Test DNS resolution
    resolution_tests: list[dict[str, Any]] = []
    if not opts.no_resolution:
        test_domains = DEFAULT_TEST_DOMAINS.copy()
        if opts.test_domains:
            test_domains.extend(opts.test_domains)

        for domain in test_domains:
            result = test_dns_resolution(domain, timeout=opts.timeout)
            resolution_tests.append(result)

    # Analyze health
    issues, warnings = analyze_dns_health(
        resolv_conf, resolved_status, nameserver_results, resolution_tests
    )

    # Build output
    result: dict[str, Any] = {
        "healthy": len([i for i in issues if i["severity"] == "critical"]) == 0,
        "nameservers": resolv_conf["nameservers"],
        "search_domains": resolv_conf["search_domains"],
        "nameserver_reachability": nameserver_results,
        "resolution_tests": resolution_tests,
        "issues": [i["message"] for i in issues],
        "warnings": [w["message"] for w in warnings],
    }

    if opts.verbose:
        result["resolv_conf"] = resolv_conf
        result["systemd_resolved"] = resolved_status

    output.emit(result)

    # Set summary
    reachable = sum(1 for r in nameserver_results if r["reachable"])
    total_ns = len(resolv_conf["nameservers"])
    critical_issues = [i for i in issues if i["severity"] == "critical"]

    if critical_issues:
        output.set_summary(f"DNS UNHEALTHY: {len(critical_issues)} critical issues")
    elif warnings or issues:
        output.set_summary(f"DNS WARNING: {reachable}/{total_ns} nameservers reachable")
    else:
        output.set_summary(f"DNS healthy: {reachable}/{total_ns} nameservers reachable")

    output.render(opts.format, "Monitor DNS resolver configuration and health")

    return 1 if critical_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
