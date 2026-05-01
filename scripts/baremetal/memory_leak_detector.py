#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [memory, leak, process, monitoring]
#   requires: []
#   privilege: user
#   related: [memory_error_detector, memory_reclaim_monitor, process_tree]
#   brief: Detect potential memory leaks by monitoring process memory growth

"""
Detect potential memory leaks by monitoring process memory growth over time.

Samples process memory usage at intervals and identifies processes whose
memory consumption is growing consistently, which may indicate memory leaks.
"""

import argparse
import re
import time
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_process_list(context: Context) -> list[tuple[int, str]]:
    """Get list of all running process PIDs."""
    processes = []
    try:
        proc_dirs = context.glob('[0-9]*', '/proc')
        for proc_dir in proc_dirs:
            import os
            pid_str = os.path.basename(proc_dir)
            if pid_str.isdigit():
                pid = int(pid_str)
                comm = get_process_comm(context, pid)
                if comm:
                    processes.append((pid, comm))
    except Exception:
        pass
    return processes


def get_process_comm(context: Context, pid: int) -> str | None:
    """Get process command name."""
    try:
        return context.read_file(f'/proc/{pid}/comm').strip()
    except (FileNotFoundError, PermissionError):
        return None


def get_process_cmdline(context: Context, pid: int) -> str | None:
    """Get full process command line."""
    try:
        cmdline = context.read_file(f'/proc/{pid}/cmdline')
        return cmdline.replace('\x00', ' ').strip() or None
    except (FileNotFoundError, PermissionError):
        return None


def get_process_memory(context: Context, pid: int) -> dict[str, int] | None:
    """Get detailed memory information for a process."""
    try:
        content = context.read_file(f'/proc/{pid}/status')
    except (FileNotFoundError, PermissionError):
        return None

    memory = {}
    patterns = {
        'VmSize': r'VmSize:\s+(\d+)\s+kB',
        'VmRSS': r'VmRSS:\s+(\d+)\s+kB',
        'VmData': r'VmData:\s+(\d+)\s+kB',
        'VmSwap': r'VmSwap:\s+(\d+)\s+kB',
        'RssAnon': r'RssAnon:\s+(\d+)\s+kB',
        'RssFile': r'RssFile:\s+(\d+)\s+kB',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, content)
        memory[key] = int(match.group(1)) if match else 0

    return memory


def sample_process_memory(
    context: Context,
    pids_to_monitor: list[int] | None = None,
    min_rss_kb: int = 10240
) -> dict[int, dict[str, Any]]:
    """Sample memory for all processes or specified PIDs."""
    samples = {}

    if pids_to_monitor:
        processes = [(pid, get_process_comm(context, pid)) for pid in pids_to_monitor]
    else:
        processes = get_process_list(context)

    for pid, comm in processes:
        if not comm:
            continue

        memory = get_process_memory(context, pid)
        if not memory:
            continue

        # Skip processes below minimum RSS threshold
        if memory.get('VmRSS', 0) < min_rss_kb:
            continue

        samples[pid] = {
            'pid': pid,
            'comm': comm,
            'cmdline': get_process_cmdline(context, pid),
            'rss_kb': memory.get('VmRSS', 0),
            'vm_data_kb': memory.get('VmData', 0),
            'rss_anon_kb': memory.get('RssAnon', 0),
            'swap_kb': memory.get('VmSwap', 0),
            'private_kb': memory.get('RssAnon', 0),  # Use RssAnon as proxy
            'timestamp': time.time(),
        }

    return samples


def analyze_memory_growth(
    samples_list: list[dict],
    min_growth_kb: int,
    min_growth_rate: float
) -> list[dict[str, Any]]:
    """Analyze memory samples to identify growing processes."""
    if len(samples_list) < 2:
        return []

    first_sample = samples_list[0]
    last_sample = samples_list[-1]

    time_delta_sec = last_sample.get('_timestamp', 0) - first_sample.get('_timestamp', 0)
    if time_delta_sec <= 0:
        return []

    time_delta_min = time_delta_sec / 60.0
    issues = []

    # Find PIDs that exist in both first and last sample
    common_pids = set(first_sample.keys()) & set(last_sample.keys())
    common_pids.discard('_timestamp')

    for pid in common_pids:
        first = first_sample[pid]
        last = last_sample[pid]

        # Ensure it's the same process
        if first['comm'] != last['comm']:
            continue

        # Calculate growth metrics
        rss_growth = last['rss_kb'] - first['rss_kb']
        private_growth = last['private_kb'] - first['private_kb']
        anon_growth = last['rss_anon_kb'] - first['rss_anon_kb']

        # Use most relevant growth metric
        primary_growth = private_growth if private_growth > 0 else rss_growth

        # Calculate growth rate in KB/min
        growth_rate = primary_growth / time_delta_min if time_delta_min > 0 else 0

        # Report if growth exceeds thresholds
        if primary_growth >= min_growth_kb and growth_rate >= min_growth_rate:
            severity = 'WARNING'
            if growth_rate >= min_growth_rate * 5:
                severity = 'CRITICAL'
            elif growth_rate >= min_growth_rate * 2:
                severity = 'HIGH'

            issues.append({
                'pid': pid,
                'comm': first['comm'],
                'cmdline': first.get('cmdline', ''),
                'severity': severity,
                'start_rss_kb': first['rss_kb'],
                'end_rss_kb': last['rss_kb'],
                'rss_growth_kb': rss_growth,
                'private_growth_kb': private_growth,
                'anon_growth_kb': anon_growth,
                'growth_rate_kb_min': round(growth_rate, 2),
                'duration_min': round(time_delta_min, 2),
            })

    # Sort by growth rate (highest first)
    issues.sort(key=lambda x: x['growth_rate_kb_min'], reverse=True)

    return issues


def format_size(kb: int) -> str:
    """Format KB value as human-readable string."""
    if kb >= 1048576:  # 1GB
        return f"{kb / 1048576:.1f}GB"
    elif kb >= 1024:  # 1MB
        return f"{kb / 1024:.1f}MB"
    else:
        return f"{kb}KB"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no leaks, 1 = leaks detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Detect potential memory leaks by monitoring process memory growth'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    parser.add_argument('--duration', type=int, default=60,
                        help='Monitoring duration in seconds (default: 60)')
    parser.add_argument('--interval', type=int, default=10,
                        help='Sampling interval in seconds (default: 10)')
    parser.add_argument('--min-rss', type=int, default=10240,
                        help='Minimum RSS in KB to monitor (default: 10240 = 10MB)')
    parser.add_argument('--min-growth', type=int, default=5120,
                        help='Minimum growth in KB to report (default: 5120 = 5MB)')
    parser.add_argument('--min-rate', type=float, default=100.0,
                        help='Minimum growth rate in KB/min (default: 100)')
    parser.add_argument('--pid', help='Comma-separated PIDs to monitor')
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.duration <= 0:
        output.error('Duration must be positive')

        output.render(opts.format, "Detect potential memory leaks by monitoring process memory growth")
        return 2

    if opts.duration > 3600:
        output.error('Duration cannot exceed 3600 seconds (1 hour)')

        output.render(opts.format, "Detect potential memory leaks by monitoring process memory growth")
        return 2

    if opts.interval <= 0:
        output.error('Interval must be positive')

        output.render(opts.format, "Detect potential memory leaks by monitoring process memory growth")
        return 2

    if opts.interval > opts.duration:
        output.error('Interval cannot exceed duration')

        output.render(opts.format, "Detect potential memory leaks by monitoring process memory growth")
        return 2

    # Parse PID list
    pids_to_monitor = None
    if opts.pid:
        try:
            pids_to_monitor = [int(p.strip()) for p in opts.pid.split(',')]
        except ValueError:
            output.error('Invalid PID format. Use comma-separated numbers')
            return 2

    # Check /proc availability
    if not context.file_exists('/proc'):
        output.error('/proc filesystem not available')

        output.render(opts.format, "Detect potential memory leaks by monitoring process memory growth")
        return 2

    # Collect samples
    all_samples = []
    num_samples = (opts.duration // opts.interval) + 1

    for i in range(num_samples):
        sample = sample_process_memory(context, pids_to_monitor, opts.min_rss)
        sample['_timestamp'] = time.time()
        all_samples.append(sample)

        if i < num_samples - 1:
            time.sleep(opts.interval)

    if len(all_samples) < 2:
        output.error('Insufficient samples collected')

        output.render(opts.format, "Detect potential memory leaks by monitoring process memory growth")
        return 2

    # Analyze for memory growth
    issues = analyze_memory_growth(all_samples, opts.min_growth, opts.min_rate)

    # Build output
    data = {
        'issues': issues,
        'summary': {
            'total_issues': len(issues),
            'critical_count': len([i for i in issues if i['severity'] == 'CRITICAL']),
            'high_count': len([i for i in issues if i['severity'] == 'HIGH']),
            'warning_count': len([i for i in issues if i['severity'] == 'WARNING']),
            'total_growth_kb': sum(i['rss_growth_kb'] for i in issues),
            'sample_count': len(all_samples),
            'duration_seconds': opts.duration,
        }
    }

    output.emit(data)

    # Set summary
    if issues:
        total_growth = sum(i['rss_growth_kb'] for i in issues)
        output.set_summary(
            f"{len(issues)} processes with memory growth, "
            f"total +{format_size(total_growth)}"
        )
    else:
        output.set_summary('No significant memory growth detected')

    # Exit based on findings
    if issues:

        output.render(opts.format, "Detect potential memory leaks by monitoring process memory growth")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
