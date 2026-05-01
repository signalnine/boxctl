#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [memory, reclaim, vmstat, pressure, performance]
#   requires: []
#   privilege: user
#   related: [memory_error_detector, memory_leak_detector, oom_kill_history]
#   brief: Monitor kernel memory reclamation activity and detect memory pressure

"""
Monitor kernel memory reclamation activity and detect memory pressure.

Analyzes /proc/vmstat to track memory reclamation metrics including:
- kswapd activity (background reclaim)
- Direct reclaim events (synchronous, blocks applications)
- Page scan rates
- Compaction activity
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_proc_vmstat(context: Context) -> dict[str, int]:
    """Read VM statistics from /proc/vmstat."""
    vmstat = {}
    try:
        content = context.read_file('/proc/vmstat')
        for line in content.split('\n'):
            parts = line.strip().split()
            if len(parts) == 2:
                vmstat[parts[0]] = int(parts[1])
    except FileNotFoundError:
        raise RuntimeError('/proc/vmstat not found')
    except PermissionError:
        raise RuntimeError('Permission denied reading /proc/vmstat')
    return vmstat


def read_proc_meminfo(context: Context) -> dict[str, int]:
    """Read memory information from /proc/meminfo."""
    meminfo = {}
    try:
        content = context.read_file('/proc/meminfo')
        for line in content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                value = value.strip().split()[0]
                meminfo[key.strip()] = int(value)
    except FileNotFoundError:
        raise RuntimeError('/proc/meminfo not found')
    except PermissionError:
        raise RuntimeError('Permission denied reading /proc/meminfo')
    return meminfo


def calculate_reclaim_metrics(vmstat: dict[str, int]) -> dict[str, Any]:
    """Calculate memory reclaim metrics from vmstat."""
    metrics = {}

    # kswapd activity (background reclaim)
    metrics['kswapd_steal'] = vmstat.get('pgsteal_kswapd', 0)
    metrics['kswapd_scan'] = vmstat.get('pgscan_kswapd', 0)

    # Direct reclaim (synchronous, application-blocking)
    metrics['direct_steal'] = vmstat.get('pgsteal_direct', 0)
    metrics['direct_scan'] = vmstat.get('pgscan_direct', 0)

    # Fallback to older kernel naming
    if metrics['kswapd_steal'] == 0:
        metrics['kswapd_steal'] = (
            vmstat.get('pgsteal_kswapd_normal', 0) +
            vmstat.get('pgsteal_kswapd_movable', 0) +
            vmstat.get('pgsteal_kswapd_dma', 0) +
            vmstat.get('pgsteal_kswapd_dma32', 0)
        )

    if metrics['direct_steal'] == 0:
        metrics['direct_steal'] = (
            vmstat.get('pgsteal_direct_normal', 0) +
            vmstat.get('pgsteal_direct_movable', 0) +
            vmstat.get('pgsteal_direct_dma', 0) +
            vmstat.get('pgsteal_direct_dma32', 0)
        )

    if metrics['kswapd_scan'] == 0:
        metrics['kswapd_scan'] = (
            vmstat.get('pgscan_kswapd_normal', 0) +
            vmstat.get('pgscan_kswapd_movable', 0) +
            vmstat.get('pgscan_kswapd_dma', 0) +
            vmstat.get('pgscan_kswapd_dma32', 0)
        )

    if metrics['direct_scan'] == 0:
        metrics['direct_scan'] = (
            vmstat.get('pgscan_direct_normal', 0) +
            vmstat.get('pgscan_direct_movable', 0) +
            vmstat.get('pgscan_direct_dma', 0) +
            vmstat.get('pgscan_direct_dma32', 0)
        )

    # Total reclaim activity
    metrics['total_steal'] = metrics['kswapd_steal'] + metrics['direct_steal']
    metrics['total_scan'] = metrics['kswapd_scan'] + metrics['direct_scan']

    # Reclaim efficiency
    if metrics['total_scan'] > 0:
        metrics['reclaim_efficiency'] = metrics['total_steal'] / metrics['total_scan'] * 100
    else:
        metrics['reclaim_efficiency'] = 100.0

    # Compaction activity
    metrics['compact_stall'] = vmstat.get('compact_stall', 0)
    metrics['compact_fail'] = vmstat.get('compact_fail', 0)
    metrics['compact_success'] = vmstat.get('compact_success', 0)

    # OOM killer invocations
    metrics['oom_kill'] = vmstat.get('oom_kill', 0)

    # Page allocation stalls
    metrics['allocstall'] = vmstat.get('allocstall', 0)
    if metrics['allocstall'] == 0:
        metrics['allocstall'] = (
            vmstat.get('allocstall_normal', 0) +
            vmstat.get('allocstall_movable', 0) +
            vmstat.get('allocstall_dma', 0) +
            vmstat.get('allocstall_dma32', 0)
        )

    # Swap activity
    metrics['pswpout'] = vmstat.get('pswpout', 0)
    metrics['pswpin'] = vmstat.get('pswpin', 0)

    return metrics


def analyze_reclaim_activity(
    metrics: dict[str, Any],
    thresholds: dict[str, Any],
    meminfo: dict[str, int]
) -> list[dict[str, Any]]:
    """Analyze reclaim metrics and return issues."""
    issues = []

    # Check for OOM kills
    if metrics['oom_kill'] > 0:
        issues.append({
            'severity': 'CRITICAL',
            'metric': 'oom_kill',
            'value': metrics['oom_kill'],
            'message': f"OOM killer invoked {metrics['oom_kill']} time(s) since boot"
        })

    # Check direct reclaim activity
    if metrics['direct_scan'] > thresholds['direct_reclaim']:
        issues.append({
            'severity': 'WARNING',
            'metric': 'direct_scan',
            'value': metrics['direct_scan'],
            'threshold': thresholds['direct_reclaim'],
            'message': (
                f"High direct reclaim activity: {metrics['direct_scan']:,} pages scanned "
                f"(applications may be blocking)"
            )
        })

    # Check allocation stalls
    if metrics['allocstall'] > thresholds['allocstall']:
        issues.append({
            'severity': 'WARNING',
            'metric': 'allocstall',
            'value': metrics['allocstall'],
            'threshold': thresholds['allocstall'],
            'message': f"High allocation stalls: {metrics['allocstall']:,}"
        })

    # Check reclaim efficiency
    if metrics['total_scan'] > 10000:
        if metrics['reclaim_efficiency'] < thresholds['efficiency']:
            issues.append({
                'severity': 'WARNING',
                'metric': 'reclaim_efficiency',
                'value': metrics['reclaim_efficiency'],
                'threshold': thresholds['efficiency'],
                'message': f"Low reclaim efficiency: {metrics['reclaim_efficiency']:.1f}%"
            })

    # Check compaction failures
    if metrics['compact_stall'] > thresholds['compact_stall']:
        failure_rate = 0
        if metrics['compact_stall'] > 0:
            failure_rate = metrics['compact_fail'] / metrics['compact_stall'] * 100

        if failure_rate > 50:
            issues.append({
                'severity': 'WARNING',
                'metric': 'compact_fail',
                'value': failure_rate,
                'message': f"High compaction failure rate: {failure_rate:.1f}%"
            })

    # Check available memory
    mem_total = meminfo.get('MemTotal', 0)
    mem_available = meminfo.get('MemAvailable', 0)
    if mem_total > 0:
        avail_pct = (mem_available / mem_total) * 100
        if avail_pct < 5:
            issues.append({
                'severity': 'CRITICAL',
                'metric': 'mem_available',
                'value': avail_pct,
                'message': f"Very low available memory: {avail_pct:.1f}% - imminent OOM risk"
            })
        elif avail_pct < 10:
            issues.append({
                'severity': 'WARNING',
                'metric': 'mem_available',
                'value': avail_pct,
                'message': f"Low available memory: {avail_pct:.1f}%"
            })

    return issues


def format_pages(pages: int) -> str:
    """Format page count to human readable (assuming 4KB pages)."""
    bytes_val = pages * 4096
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.1f} GB"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.1f} MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KB"
    else:
        return f"{bytes_val} B"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = pressure detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Monitor kernel memory reclamation activity'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show additional metrics')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    parser.add_argument('--direct-reclaim', type=int, default=100000,
                        help='Direct reclaim threshold (default: 100000)')
    parser.add_argument('--allocstall', type=int, default=1000,
                        help='Allocation stall threshold (default: 1000)')
    parser.add_argument('--efficiency', type=float, default=10.0,
                        help='Minimum reclaim efficiency %% (default: 10)')
    parser.add_argument('--compact-stall', type=int, default=10000,
                        help='Compaction stall threshold (default: 10000)')
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.direct_reclaim < 0:
        output.error('--direct-reclaim must be non-negative')

        output.render(opts.format, "Monitor kernel memory reclamation activity and detect memory pressure")
        return 2
    if opts.allocstall < 0:
        output.error('--allocstall must be non-negative')

        output.render(opts.format, "Monitor kernel memory reclamation activity and detect memory pressure")
        return 2
    if opts.efficiency < 0 or opts.efficiency > 100:
        output.error('--efficiency must be between 0 and 100')

        output.render(opts.format, "Monitor kernel memory reclamation activity and detect memory pressure")
        return 2
    if opts.compact_stall < 0:
        output.error('--compact-stall must be non-negative')

        output.render(opts.format, "Monitor kernel memory reclamation activity and detect memory pressure")
        return 2

    thresholds = {
        'direct_reclaim': opts.direct_reclaim,
        'allocstall': opts.allocstall,
        'efficiency': opts.efficiency,
        'compact_stall': opts.compact_stall,
    }

    # Read system information
    try:
        vmstat = read_proc_vmstat(context)
        meminfo = read_proc_meminfo(context)
    except RuntimeError as e:
        output.error(str(e))

        output.render(opts.format, "Monitor kernel memory reclamation activity and detect memory pressure")
        return 2

    # Calculate metrics
    metrics = calculate_reclaim_metrics(vmstat)

    # Analyze for issues
    issues = analyze_reclaim_activity(metrics, thresholds, meminfo)

    # Build output
    mem_total = meminfo.get('MemTotal', 0)
    mem_available = meminfo.get('MemAvailable', 0)
    avail_pct = (mem_available / mem_total * 100) if mem_total > 0 else 0

    data = {
        'reclaim': {
            'kswapd_scan': metrics['kswapd_scan'],
            'kswapd_steal': metrics['kswapd_steal'],
            'direct_scan': metrics['direct_scan'],
            'direct_steal': metrics['direct_steal'],
            'total_scan': metrics['total_scan'],
            'total_steal': metrics['total_steal'],
            'efficiency_percent': round(metrics['reclaim_efficiency'], 2),
        },
        'memory': {
            'total_kb': mem_total,
            'available_kb': mem_available,
            'available_percent': round(avail_pct, 2),
        },
        'issues': issues,
        'has_issues': len([i for i in issues if i['severity'] != 'INFO']) > 0,
    }

    if opts.verbose:
        data['additional'] = {
            'allocstall': metrics['allocstall'],
            'compact_stall': metrics['compact_stall'],
            'compact_fail': metrics['compact_fail'],
            'compact_success': metrics['compact_success'],
            'oom_kill': metrics['oom_kill'],
            'pswpin': metrics['pswpin'],
            'pswpout': metrics['pswpout'],
        }

    output.emit(data)

    # Set summary
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical:
        output.set_summary('CRITICAL: Memory pressure detected')
    elif has_warning:
        output.set_summary('WARNING: Elevated reclaim activity')
    else:
        output.set_summary('No memory pressure detected')

    # Determine exit code
    if has_critical or has_warning:

        output.render(opts.format, "Monitor kernel memory reclamation activity and detect memory pressure")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
