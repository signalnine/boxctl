#!/usr/bin/env python3
# boxctl:
#   category: baremetal/io
#   tags: [writeback, dirty-pages, io, disk, performance]
#   requires: []
#   privilege: user
#   related: [disk_io_latency, memory_pressure, swap_monitor]
#   brief: Monitor kernel writeback cache behavior and dirty page pressure

"""
Monitor kernel writeback cache behavior and dirty page pressure.

This script monitors the Linux kernel's writeback subsystem by analyzing:
- Dirty page counts and ratios vs configured thresholds
- Background writeback activity and throttling
- Per-BDI (backing device info) writeback statistics
- Writeback congestion indicators

High dirty page ratios can cause:
- Application stalls when dirty_ratio threshold is hit
- Increased I/O latency spikes
- Memory pressure as pages cannot be reclaimed
- Risk of data loss on sudden power failure
"""

import argparse
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_meminfo(context: Context) -> dict[str, int]:
    """Parse /proc/meminfo and return dict of values in bytes."""
    meminfo: dict[str, int] = {}

    try:
        content = context.read_file('/proc/meminfo')
    except (FileNotFoundError, PermissionError):
        return meminfo

    for line in content.split('\n'):
        if ':' not in line:
            continue
        parts = line.split(':')
        key = parts[0].strip()
        value_parts = parts[1].strip().split()
        if value_parts:
            try:
                value = int(value_parts[0])
                # Convert kB to bytes if unit present
                if len(value_parts) > 1 and value_parts[1].lower() == 'kb':
                    value *= 1024
                meminfo[key] = value
            except ValueError:
                continue

    return meminfo


def get_vm_settings(context: Context) -> dict[str, int]:
    """Read vm.dirty_* sysctl settings."""
    settings: dict[str, int] = {}

    def read_int(path: str, default: int) -> int:
        try:
            content = context.read_file(path)
            return int(content.strip())
        except (FileNotFoundError, PermissionError, ValueError):
            return default

    # Dirty thresholds (percentage of total memory)
    settings['dirty_background_ratio'] = read_int(
        '/proc/sys/vm/dirty_background_ratio', 10
    )
    settings['dirty_ratio'] = read_int(
        '/proc/sys/vm/dirty_ratio', 20
    )

    # Dirty thresholds (absolute bytes, 0 means use ratio)
    settings['dirty_background_bytes'] = read_int(
        '/proc/sys/vm/dirty_background_bytes', 0
    )
    settings['dirty_bytes'] = read_int(
        '/proc/sys/vm/dirty_bytes', 0
    )

    # Writeback timing
    settings['dirty_expire_centisecs'] = read_int(
        '/proc/sys/vm/dirty_expire_centisecs', 3000
    )
    settings['dirty_writeback_centisecs'] = read_int(
        '/proc/sys/vm/dirty_writeback_centisecs', 500
    )

    return settings


def get_bdi_stats(context: Context) -> list[dict[str, Any]]:
    """Get per-BDI (backing device info) writeback statistics."""
    bdi_list: list[dict[str, Any]] = []

    bdi_base = '/sys/class/bdi'
    if not context.file_exists(bdi_base):
        return bdi_list

    def read_int(path: str) -> int:
        try:
            content = context.read_file(path)
            return int(content.strip())
        except (FileNotFoundError, PermissionError, ValueError):
            return 0

    try:
        bdi_dirs = context.glob('*', bdi_base)
        for bdi_path in bdi_dirs:
            bdi_name = os.path.basename(bdi_path)
            bdi_info: dict[str, Any] = {
                'name': bdi_name,
                'read_ahead_kb': read_int(f'{bdi_path}/read_ahead_kb'),
                'min_ratio': read_int(f'{bdi_path}/min_ratio'),
                'max_ratio': read_int(f'{bdi_path}/max_ratio'),
            }
            bdi_list.append(bdi_info)
    except (OSError, PermissionError):
        pass

    return bdi_list


def get_vmstat(context: Context) -> dict[str, int]:
    """Parse /proc/vmstat for writeback-related counters."""
    vmstat: dict[str, int] = {}

    try:
        content = context.read_file('/proc/vmstat')
    except (FileNotFoundError, PermissionError):
        return vmstat

    # Counters we care about
    wb_counters = [
        'nr_dirty', 'nr_writeback', 'nr_writeback_temp',
        'nr_dirty_threshold', 'nr_dirty_background_threshold',
        'pgpgin', 'pgpgout', 'pswpin', 'pswpout',
        'nr_vmscan_write', 'nr_written',
    ]

    for line in content.split('\n'):
        parts = line.split()
        if len(parts) >= 2 and parts[0] in wb_counters:
            try:
                vmstat[parts[0]] = int(parts[1])
            except ValueError:
                continue

    return vmstat


def analyze_writeback(
    meminfo: dict[str, int],
    vmstat: dict[str, int],
    settings: dict[str, int],
    warn_dirty_pct: float,
    crit_dirty_pct: float
) -> dict[str, Any]:
    """Analyze writeback state and identify issues."""
    result: dict[str, Any] = {
        'status': 'ok',
        'issues': [],
        'metrics': {},
    }

    total_mem = meminfo.get('MemTotal', 0)
    if total_mem == 0:
        result['status'] = 'error'
        result['issues'].append('Cannot determine total memory')
        return result

    # Get dirty page counts (in pages, convert to bytes using 4KB page size)
    page_size = 4096
    nr_dirty = vmstat.get('nr_dirty', 0) * page_size
    nr_writeback = vmstat.get('nr_writeback', 0) * page_size
    nr_writeback_temp = vmstat.get('nr_writeback_temp', 0) * page_size

    # Alternative: use meminfo Dirty/Writeback (already in bytes from our parser)
    if nr_dirty == 0:
        nr_dirty = meminfo.get('Dirty', 0)
    if nr_writeback == 0:
        nr_writeback = meminfo.get('Writeback', 0)

    # Calculate thresholds
    if settings['dirty_bytes'] > 0:
        dirty_thresh = settings['dirty_bytes']
    else:
        dirty_thresh = (total_mem * settings['dirty_ratio']) // 100

    if settings['dirty_background_bytes'] > 0:
        bg_thresh = settings['dirty_background_bytes']
    else:
        bg_thresh = (total_mem * settings['dirty_background_ratio']) // 100

    # Calculate current dirty percentage
    dirty_pct = (nr_dirty / total_mem) * 100 if total_mem > 0 else 0
    writeback_pct = (nr_writeback / total_mem) * 100 if total_mem > 0 else 0

    # Store metrics
    result['metrics'] = {
        'total_memory_bytes': total_mem,
        'dirty_bytes': nr_dirty,
        'dirty_pct': round(dirty_pct, 2),
        'writeback_bytes': nr_writeback,
        'writeback_pct': round(writeback_pct, 2),
        'writeback_temp_bytes': nr_writeback_temp,
        'dirty_threshold_bytes': dirty_thresh,
        'dirty_threshold_pct': settings['dirty_ratio'],
        'dirty_bg_threshold_bytes': bg_thresh,
        'dirty_bg_threshold_pct': settings['dirty_background_ratio'],
        'dirty_expire_secs': settings['dirty_expire_centisecs'] / 100,
        'writeback_interval_secs': settings['dirty_writeback_centisecs'] / 100,
    }

    # Check against user-specified thresholds
    if dirty_pct >= crit_dirty_pct:
        result['status'] = 'critical'
        result['issues'].append(
            f'Dirty pages critical: {dirty_pct:.1f}% >= {crit_dirty_pct}% threshold'
        )
    elif dirty_pct >= warn_dirty_pct:
        if result['status'] == 'ok':
            result['status'] = 'warning'
        result['issues'].append(
            f'Dirty pages elevated: {dirty_pct:.1f}% >= {warn_dirty_pct}% threshold'
        )

    # Check if approaching kernel dirty_ratio (process throttling threshold)
    ratio_to_limit = (nr_dirty / dirty_thresh) * 100 if dirty_thresh > 0 else 0
    result['metrics']['ratio_to_dirty_limit_pct'] = round(ratio_to_limit, 2)

    if ratio_to_limit >= 90:
        if result['status'] == 'ok':
            result['status'] = 'critical'
        result['issues'].append(
            f'Approaching dirty_ratio limit: {ratio_to_limit:.1f}% of threshold '
            f'(processes will be throttled at 100%)'
        )
    elif ratio_to_limit >= 75:
        if result['status'] == 'ok':
            result['status'] = 'warning'
        result['issues'].append(
            f'Dirty pages at {ratio_to_limit:.1f}% of dirty_ratio limit'
        )

    # Check if background writeback is overwhelmed
    bg_ratio = (nr_dirty / bg_thresh) * 100 if bg_thresh > 0 else 0
    result['metrics']['ratio_to_bg_limit_pct'] = round(bg_ratio, 2)

    if bg_ratio >= 100:
        # We're past the background threshold, writeback should be active
        if nr_writeback == 0:
            if result['status'] == 'ok':
                result['status'] = 'warning'
            result['issues'].append(
                'Dirty pages exceed background threshold but no writeback active'
            )

    # Check for excessive writeback (I/O congestion indicator)
    if writeback_pct > 5:
        if result['status'] == 'ok':
            result['status'] = 'warning'
        result['issues'].append(
            f'High writeback volume: {writeback_pct:.1f}% of memory in flight'
        )

    return result


def format_bytes(bytes_val: float) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_val) < 1024.0:
            return f'{bytes_val:.1f}{unit}'
        bytes_val /= 1024.0
    return f'{bytes_val:.1f}PB'


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
        description='Monitor kernel writeback cache and dirty page pressure'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information including per-device stats')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show output if issues detected')
    parser.add_argument('--warn-pct', type=float, default=5.0,
                        help='Warning threshold for dirty pages as %% of memory (default: 5)')
    parser.add_argument('--crit-pct', type=float, default=10.0,
                        help='Critical threshold for dirty pages as %% of memory (default: 10)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn_pct < 0 or opts.warn_pct > 100:
        output.error('--warn-pct must be between 0 and 100')

        output.render(opts.format, "Monitor kernel writeback cache behavior and dirty page pressure")
        return 2

    if opts.crit_pct < 0 or opts.crit_pct > 100:
        output.error('--crit-pct must be between 0 and 100')

        output.render(opts.format, "Monitor kernel writeback cache behavior and dirty page pressure")
        return 2

    if opts.warn_pct > opts.crit_pct:
        output.error('--warn-pct cannot exceed --crit-pct')

        output.render(opts.format, "Monitor kernel writeback cache behavior and dirty page pressure")
        return 2

    # Check for required data sources
    if not context.file_exists('/proc/meminfo'):
        output.error('/proc/meminfo not available')

        output.render(opts.format, "Monitor kernel writeback cache behavior and dirty page pressure")
        return 2

    # Gather data
    meminfo = get_meminfo(context)
    vmstat = get_vmstat(context)
    settings = get_vm_settings(context)
    bdi_stats = get_bdi_stats(context)

    if not meminfo:
        output.error('Cannot read memory information')

        output.render(opts.format, "Monitor kernel writeback cache behavior and dirty page pressure")
        return 2

    # Analyze
    result = analyze_writeback(
        meminfo, vmstat, settings,
        opts.warn_pct, opts.crit_pct
    )

    # Prepare output data
    output_data: dict[str, Any] = {
        'status': result['status'],
        'metrics': result['metrics'],
        'issues': result['issues'],
        'settings': settings,
    }

    if opts.verbose:
        output_data['bdi_devices'] = bdi_stats

    output.emit(output_data)

    metrics = result['metrics']
    output.set_summary(
        f"Writeback: {metrics['dirty_pct']:.1f}% dirty "
        f"({format_bytes(metrics['dirty_bytes'])}), "
        f"{metrics['writeback_pct']:.1f}% in flight, "
        f"{result['status']}"
    )

    # Exit code
    if result['status'] == 'critical':

        output.render(opts.format, "Monitor kernel writeback cache behavior and dirty page pressure")
        return 1
    elif result['status'] == 'warning':
        return 1
    elif result['status'] == 'error':

        output.render(opts.format, "Monitor kernel writeback cache behavior and dirty page pressure")
        return 2
    else:

        output.render(opts.format, "Monitor kernel writeback cache behavior and dirty page pressure")
        return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
