#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [memory, vmalloc, kernel, resources]
#   requires: []
#   privilege: user
#   related: [memory_pressure, swap_monitor, oom_risk_analyzer]
#   brief: Monitor kernel vmalloc memory usage to detect exhaustion before failures

"""
Monitor kernel vmalloc memory usage to detect exhaustion before failures.

Vmalloc exhaustion can cause cryptic "unable to allocate memory" errors that
appear even when the system has plenty of RAM. This script monitors:
- Total vmalloc space usage
- Largest free contiguous block (for large allocations)
- Top vmalloc consumers (modules, subsystems)
- Warning thresholds for approaching exhaustion

Common causes of vmalloc exhaustion:
- Too many network interfaces/iptables rules
- Kernel modules with large allocations
- eBPF programs and maps
- Graphics drivers
- File systems (especially with many mount points)

Useful for monitoring large baremetal fleets where vmalloc exhaustion can
cause intermittent failures that are hard to diagnose.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_meminfo(context: Context) -> dict[str, int] | None:
    """Parse /proc/meminfo for vmalloc statistics."""
    try:
        content = context.read_file('/proc/meminfo')
    except (FileNotFoundError, PermissionError):
        return None

    meminfo: dict[str, int] = {}
    for line in content.split('\n'):
        parts = line.split(':')
        if len(parts) == 2:
            key = parts[0].strip()
            # Parse value (remove 'kB' suffix)
            value_str = parts[1].strip().split()[0]
            try:
                meminfo[key] = int(value_str)
            except ValueError:
                pass

    return meminfo


def parse_vmallocinfo(context: Context) -> list[dict[str, Any]] | None:
    """
    Parse /proc/vmallocinfo to get allocation details.

    Returns list of allocations with size and caller info.
    Requires root privileges.
    """
    try:
        content = context.read_file('/proc/vmallocinfo')
    except (FileNotFoundError, PermissionError):
        return None

    allocations = []
    for line in content.split('\n'):
        # Format: 0xaddr-0xaddr   size caller
        match = re.match(
            r'0x[0-9a-f]+-0x[0-9a-f]+\s+(\d+)\s+(.*)',
            line.strip()
        )
        if match:
            size = int(match.group(1))
            caller = match.group(2).strip()
            allocations.append({
                'size': size,
                'caller': caller,
            })

    return allocations


def get_vmalloc_info(context: Context) -> dict[str, Any] | None:
    """Get vmalloc information from /proc/meminfo and /proc/vmallocinfo."""
    meminfo = parse_meminfo(context)
    if meminfo is None:
        return None

    result = {
        'total_kb': meminfo.get('VmallocTotal', 0),
        'used_kb': meminfo.get('VmallocUsed', 0),
        'chunk_kb': meminfo.get('VmallocChunk', 0),
    }

    # Calculate free space and percentages
    result['free_kb'] = result['total_kb'] - result['used_kb']
    if result['total_kb'] > 0:
        result['used_pct'] = (result['used_kb'] / result['total_kb']) * 100
        result['free_pct'] = (result['free_kb'] / result['total_kb']) * 100
    else:
        result['used_pct'] = 0
        result['free_pct'] = 100

    # Try to get detailed allocations (requires root)
    allocations = parse_vmallocinfo(context)
    result['allocations'] = allocations
    result['has_details'] = allocations is not None

    return result


def analyze_top_consumers(allocations: list[dict] | None, top_n: int = 10) -> list[dict] | None:
    """Analyze vmalloc allocations to find top consumers."""
    if allocations is None:
        return None

    # Group by caller function/module
    consumers: dict[str, dict[str, int]] = {}
    for alloc in allocations:
        caller = alloc['caller']
        # Extract module name or function
        key = caller.split('+')[0].split('/')[0]
        if not key:
            key = 'unknown'

        if key not in consumers:
            consumers[key] = {'total_size': 0, 'count': 0}
        consumers[key]['total_size'] += alloc['size']
        consumers[key]['count'] += 1

    # Sort by total size
    sorted_consumers = sorted(
        consumers.items(),
        key=lambda x: x[1]['total_size'],
        reverse=True
    )

    return [
        {'name': name, **stats}
        for name, stats in sorted_consumers[:top_n]
    ]


def format_bytes(bytes_val: float) -> str:
    """Format bytes in human-readable form."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}TB"


def format_kb(kb_val: int) -> str:
    """Format KB value in human-readable form."""
    return format_bytes(kb_val * 1024)


def check_issues(
    info: dict[str, Any],
    warn_pct: float,
    crit_pct: float,
    min_chunk_mb: float
) -> tuple[str, list[dict[str, Any]]]:
    """
    Check for vmalloc issues.

    Returns:
        (status, issues) where status is 'healthy', 'warning', or 'critical'
    """
    issues: list[dict[str, Any]] = []

    # Check usage percentage
    if info['used_pct'] >= crit_pct:
        issues.append({
            'severity': 'critical',
            'message': f"Vmalloc usage at {info['used_pct']:.1f}% "
                       f"({format_kb(info['used_kb'])} of {format_kb(info['total_kb'])})"
        })
    elif info['used_pct'] >= warn_pct:
        issues.append({
            'severity': 'warning',
            'message': f"Vmalloc usage at {info['used_pct']:.1f}% "
                       f"({format_kb(info['used_kb'])} of {format_kb(info['total_kb'])})"
        })

    # Check largest contiguous block
    chunk_mb = info['chunk_kb'] / 1024
    if chunk_mb < min_chunk_mb:
        # Fragmentation issue
        issues.append({
            'severity': 'warning',
            'message': f"Largest free contiguous block only {chunk_mb:.1f}MB "
                       f"(threshold: {min_chunk_mb}MB) - may cause large allocation failures"
        })

    # Determine overall status
    if any(i['severity'] == 'critical' for i in issues):
        status = 'critical'
    elif issues:
        status = 'warning'
    else:
        status = 'healthy'

    return status, issues


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
        description='Monitor kernel vmalloc memory usage'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed statistics including top consumers')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only produce output if issues are detected')
    parser.add_argument('--warn-pct', type=float, default=80.0, metavar='PCT',
                        help='Warning threshold percentage (default: 80)')
    parser.add_argument('--crit-pct', type=float, default=95.0, metavar='PCT',
                        help='Critical threshold percentage (default: 95)')
    parser.add_argument('--min-chunk', type=float, default=32.0, metavar='MB',
                        help='Minimum acceptable contiguous block in MB (default: 32)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn_pct >= opts.crit_pct:
        output.error('--warn-pct must be less than --crit-pct')

        output.render(opts.format, "Monitor kernel vmalloc memory usage to detect exhaustion before failures")
        return 2

    # Check if /proc/meminfo exists
    if not context.file_exists('/proc/meminfo'):
        output.error('/proc/meminfo not found (not a Linux system?)')

        output.render(opts.format, "Monitor kernel vmalloc memory usage to detect exhaustion before failures")
        return 2

    # Get vmalloc info
    info = get_vmalloc_info(context)
    if info is None:
        output.error('Could not read vmalloc information')

        output.render(opts.format, "Monitor kernel vmalloc memory usage to detect exhaustion before failures")
        return 2

    # Check if VmallocTotal is available
    if info['total_kb'] == 0:
        output.error('VmallocTotal not found in /proc/meminfo')

        output.render(opts.format, "Monitor kernel vmalloc memory usage to detect exhaustion before failures")
        return 2

    # Analyze top consumers if we have detailed info
    top_consumers = None
    if info['allocations']:
        top_consumers = analyze_top_consumers(info['allocations'])

    # Check for issues
    status, issues = check_issues(
        info,
        warn_pct=opts.warn_pct,
        crit_pct=opts.crit_pct,
        min_chunk_mb=opts.min_chunk
    )

    # Prepare output data
    output_data: dict[str, Any] = {
        'status': status,
        'total_kb': info['total_kb'],
        'used_kb': info['used_kb'],
        'free_kb': info['free_kb'],
        'chunk_kb': info['chunk_kb'],
        'used_pct': round(info['used_pct'], 2),
        'free_pct': round(info['free_pct'], 2),
        'issues': issues,
        'has_details': info['has_details'],
    }

    if top_consumers:
        output_data['top_consumers'] = top_consumers

    output.emit(output_data)
    output.set_summary(
        f"Vmalloc: {info['used_pct']:.1f}% used "
        f"({format_kb(info['used_kb'])} of {format_kb(info['total_kb'])}), "
        f"{status}"
    )

    # Exit with appropriate code

    output.render(opts.format, "Monitor kernel vmalloc memory usage to detect exhaustion before failures")
    return 1 if status in ('warning', 'critical') else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
