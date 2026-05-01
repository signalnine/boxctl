#!/usr/bin/env python3
# boxctl:
#   category: baremetal/performance
#   tags: [boot, systemd, performance, startup]
#   requires: [systemd-analyze]
#   privilege: none
#   related: [systemd_service_monitor]
#   brief: Monitor system boot performance and systemd initialization times

"""
Monitor system boot performance and systemd initialization times.

Analyzes systemd boot performance using 'systemd-analyze' to identify
slow-booting systems and problematic services that delay system startup.
Useful for large-scale baremetal environments where boot time impacts
incident recovery.

Key metrics:
- Total boot time (kernel + userspace)
- Kernel initialization time
- Userspace (systemd) initialization time
- Firmware/bootloader time (if available)
- Top slow-starting services
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output

# Default thresholds (in seconds)
DEFAULT_BOOT_WARN = 120  # 2 minutes total boot time
DEFAULT_USERSPACE_WARN = 60  # 1 minute userspace time
DEFAULT_SERVICE_WARN = 10  # 10 seconds for individual service


def parse_boot_time(stdout: str) -> dict[str, float] | None:
    """Parse systemd-analyze output for boot time statistics."""
    pattern = r'Startup finished in (.+)'
    match = re.search(pattern, stdout)

    if not match:
        return None

    time_str = match.group(1)

    result = {
        'firmware': 0.0,
        'loader': 0.0,
        'kernel': 0.0,
        'userspace': 0.0,
        'total': 0.0
    }

    def convert_to_seconds(value: str, unit: str) -> float:
        val = float(value)
        if unit == 'ms':
            return val / 1000
        elif unit == 'min':
            return val * 60
        else:  # 's'
            return val

    # Parse individual components
    firmware_match = re.search(r'(\d+\.?\d*)(s|ms|min) \(firmware\)', time_str)
    loader_match = re.search(r'(\d+\.?\d*)(s|ms|min) \(loader\)', time_str)
    kernel_match = re.search(r'(\d+\.?\d*)(s|ms|min) \(kernel\)', time_str)
    userspace_match = re.search(r'(\d+\.?\d*)(s|ms|min) \(userspace\)', time_str)
    total_match = re.search(r'= (\d+\.?\d*)(s|ms|min)\s*$', time_str)

    if firmware_match:
        result['firmware'] = convert_to_seconds(firmware_match.group(1), firmware_match.group(2))
    if loader_match:
        result['loader'] = convert_to_seconds(loader_match.group(1), loader_match.group(2))
    if kernel_match:
        result['kernel'] = convert_to_seconds(kernel_match.group(1), kernel_match.group(2))
    if userspace_match:
        result['userspace'] = convert_to_seconds(userspace_match.group(1), userspace_match.group(2))
    if total_match:
        result['total'] = convert_to_seconds(total_match.group(1), total_match.group(2))

    return result


def parse_blame_output(stdout: str, top_n: int = 10) -> list[dict[str, Any]]:
    """Parse systemd-analyze blame output for slow services."""
    services = []
    lines = stdout.strip().split('\n')

    for line in lines[:top_n]:
        line = line.strip()
        if not line:
            continue

        parts = line.split(None, 1)
        if len(parts) < 2:
            continue

        time_str = parts[0]
        service_name = parts[1]

        # Convert time to seconds
        time_match = re.match(r'(\d+\.?\d*)(s|ms|min)', time_str)
        if not time_match:
            continue

        value = float(time_match.group(1))
        unit = time_match.group(2)

        if unit == 'ms':
            seconds = value / 1000
        elif unit == 'min':
            seconds = value * 60
        else:
            seconds = value

        services.append({
            'name': service_name,
            'time_sec': round(seconds, 3),
            'time_str': time_str
        })

    return services


def check_thresholds(boot_times: dict, slow_services: list,
                     boot_warn: float, userspace_warn: float,
                     service_warn: float) -> list[dict[str, str]]:
    """Check boot statistics against thresholds."""
    issues = []

    # Check total boot time
    if boot_times['total'] > boot_warn:
        issues.append({
            'severity': 'warning',
            'component': 'total_boot_time',
            'message': f"Total boot time {boot_times['total']:.1f}s exceeds threshold {boot_warn}s"
        })

    # Check userspace time
    if boot_times['userspace'] > userspace_warn:
        issues.append({
            'severity': 'warning',
            'component': 'userspace_time',
            'message': f"Userspace init time {boot_times['userspace']:.1f}s exceeds threshold {userspace_warn}s"
        })

    # Check slow services
    for service in slow_services:
        if service['time_sec'] > service_warn:
            issues.append({
                'severity': 'info',
                'component': 'slow_service',
                'message': f"Service {service['name']} took {service['time_sec']:.1f}s (threshold: {service_warn}s)"
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
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor system boot performance")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--boot-threshold", type=float, default=DEFAULT_BOOT_WARN,
                        help=f"Warning threshold for total boot time (default: {DEFAULT_BOOT_WARN}s)")
    parser.add_argument("--userspace-threshold", type=float, default=DEFAULT_USERSPACE_WARN,
                        help=f"Warning threshold for userspace time (default: {DEFAULT_USERSPACE_WARN}s)")
    parser.add_argument("--service-threshold", type=float, default=DEFAULT_SERVICE_WARN,
                        help=f"Warning threshold for service time (default: {DEFAULT_SERVICE_WARN}s)")
    opts = parser.parse_args(args)

    # Check for systemd-analyze
    if not context.check_tool("systemd-analyze"):
        output.error("systemd-analyze not found. This tool requires systemd.")

        output.render(opts.format, "Monitor system boot performance and systemd initialization times")
        return 2

    # Get overall boot time
    result = context.run(['systemd-analyze'], check=False)
    if result.returncode != 0:
        output.error(f"systemd-analyze failed: {result.stderr}")

        output.render(opts.format, "Monitor system boot performance and systemd initialization times")
        return 2

    boot_times = parse_boot_time(result.stdout)
    if not boot_times:
        output.error("Failed to parse boot time output")

        output.render(opts.format, "Monitor system boot performance and systemd initialization times")
        return 2

    # Get slow services
    result = context.run(['systemd-analyze', 'blame'], check=False)
    if result.returncode != 0:
        slow_services = []
    else:
        slow_services = parse_blame_output(result.stdout, top_n=10)

    # Check thresholds
    issues = check_thresholds(
        boot_times, slow_services,
        opts.boot_threshold, opts.userspace_threshold, opts.service_threshold
    )

    # Build result
    result_data = {
        'boot_times': {
            'total_sec': round(boot_times['total'], 2),
            'kernel_sec': round(boot_times['kernel'], 2),
            'userspace_sec': round(boot_times['userspace'], 2),
        },
        'issues': issues
    }

    # Add firmware/loader if present
    if boot_times['firmware'] > 0:
        result_data['boot_times']['firmware_sec'] = round(boot_times['firmware'], 2)
    if boot_times['loader'] > 0:
        result_data['boot_times']['loader_sec'] = round(boot_times['loader'], 2)

    # Add slow services in verbose mode
    if opts.verbose and slow_services:
        result_data['slow_services'] = slow_services

    output.emit(result_data)

    # Set summary
    has_warnings = any(i['severity'] == 'warning' for i in issues)
    if has_warnings:
        output.set_summary(f"boot time {boot_times['total']:.1f}s exceeds thresholds")
    else:
        output.set_summary(f"boot time {boot_times['total']:.1f}s")

    output.render(opts.format, "Monitor system boot performance and systemd initialization times")

    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
