#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [swap, memory, process, pressure]
#   requires: []
#   privilege: user
#   related: [memory_pressure, oom_kill_history]
#   brief: Monitor per-process swap usage to identify swap pressure sources

"""
Monitor per-process swap usage to identify processes contributing to swap pressure.

When system swap usage is high, administrators need to know which processes
are swapped out to make informed decisions about restarts, memory allocation,
or workload distribution. This script identifies the top swap consumers by
reading VmSwap from /proc/[pid]/status.

Key features:
- Lists processes sorted by swap usage
- Shows top N swap consumers
- Identifies processes with high swap-to-RSS ratio (thrashing candidates)
- Supports filtering by user or process name
"""

import argparse
import os
import pwd
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_proc_file(path: str) -> str | None:
    """Read a /proc file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (OSError, IOError, PermissionError):
        return None


def parse_status_value(value: str) -> int:
    """Parse a value from /proc/[pid]/status, handling 'kB' suffix."""
    parts = value.strip().split()
    if parts:
        try:
            return int(parts[0])
        except ValueError:
            return 0
    return 0


def get_process_swap_info(pid: int) -> dict[str, Any] | None:
    """Get swap and memory information for a process."""
    status_path = f'/proc/{pid}/status'
    cmdline_path = f'/proc/{pid}/cmdline'

    status_content = read_proc_file(status_path)
    if not status_content:
        return None

    info = {
        'pid': pid,
        'name': 'unknown',
        'cmdline': '',
        'user': 'unknown',
        'uid': -1,
        'vm_swap_kb': 0,
        'vm_rss_kb': 0,
        'vm_size_kb': 0,
    }

    for line in status_content.split('\n'):
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()

        if key == 'Name':
            info['name'] = value.strip()
        elif key == 'Uid':
            parts = value.split()
            if parts:
                try:
                    info['uid'] = int(parts[0])
                except ValueError:
                    pass
        elif key == 'VmSwap':
            info['vm_swap_kb'] = parse_status_value(value)
        elif key == 'VmRSS':
            info['vm_rss_kb'] = parse_status_value(value)
        elif key == 'VmSize':
            info['vm_size_kb'] = parse_status_value(value)

    # Get command line for more context
    cmdline_content = read_proc_file(cmdline_path)
    if cmdline_content:
        cmdline = cmdline_content.replace('\x00', ' ').strip()
        info['cmdline'] = cmdline[:200] if cmdline else info['name']
    else:
        info['cmdline'] = info['name']

    # Resolve username
    if info['uid'] >= 0:
        try:
            info['user'] = pwd.getpwuid(info['uid']).pw_name
        except KeyError:
            info['user'] = str(info['uid'])

    # Calculate swap ratio (swap / (swap + rss))
    total_mem = info['vm_swap_kb'] + info['vm_rss_kb']
    if total_mem > 0:
        info['swap_ratio'] = round((info['vm_swap_kb'] / total_mem) * 100, 1)
    else:
        info['swap_ratio'] = 0.0

    return info


def scan_processes() -> list[dict[str, Any]]:
    """Scan all processes and gather swap information."""
    processes = []

    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                info = get_process_swap_info(pid)
                if info and info['vm_swap_kb'] > 0:
                    processes.append(info)
    except OSError:
        pass

    return processes


def format_size(kb: int) -> str:
    """Format size in KB to human-readable format."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no high swap usage, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor per-process swap usage")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information including command lines")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--top", type=int, default=20, metavar="N",
                        help="Show top N swap consumers (default: 20, 0=all)")
    parser.add_argument("--swap-threshold", type=int, default=100 * 1024, metavar="KB",
                        help="Threshold in KB for high swap warning (default: 102400 = 100MB)")
    parser.add_argument("--ratio-threshold", type=float, default=50.0, metavar="PCT",
                        help="Swap ratio threshold for thrashing warning (default: 50%%)")
    parser.add_argument("--user", metavar="USER", help="Filter by username")
    parser.add_argument("--name", metavar="PATTERN",
                        help="Filter by process name (case-insensitive substring match)")
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.top < 0:
        output.error("--top must be non-negative")

        output.render(opts.format, "Monitor per-process swap usage to identify swap pressure sources")
        return 2

    if opts.swap_threshold < 0:
        output.error("--swap-threshold must be non-negative")

        output.render(opts.format, "Monitor per-process swap usage to identify swap pressure sources")
        return 2

    if opts.ratio_threshold < 0 or opts.ratio_threshold > 100:
        output.error("--ratio-threshold must be 0-100")

        output.render(opts.format, "Monitor per-process swap usage to identify swap pressure sources")
        return 2

    # Check for /proc filesystem
    if not os.path.isdir('/proc'):
        output.error("/proc filesystem not available")

        output.render(opts.format, "Monitor per-process swap usage to identify swap pressure sources")
        return 2

    # Scan processes
    processes = scan_processes()

    # Apply filters
    if opts.user:
        processes = [p for p in processes if p['user'] == opts.user]

    if opts.name:
        pattern = opts.name.lower()
        processes = [p for p in processes if pattern in p['name'].lower()]

    # Sort by swap usage
    sorted_procs = sorted(processes, key=lambda x: x['vm_swap_kb'], reverse=True)

    # Apply top N limit
    if opts.top > 0:
        display_procs = sorted_procs[:opts.top]
    else:
        display_procs = sorted_procs

    # Identify issues
    high_swap = [p for p in processes if p['vm_swap_kb'] >= opts.swap_threshold]
    high_ratio = [p for p in processes if p['swap_ratio'] >= opts.ratio_threshold]

    total_process_swap = sum(p['vm_swap_kb'] for p in processes)

    # Build output data
    result = {
        'processes_with_swap': len(processes),
        'total_process_swap_kb': total_process_swap,
        'high_swap_count': len(high_swap),
        'high_ratio_count': len(high_ratio),
        'swap_threshold_kb': opts.swap_threshold,
        'ratio_threshold_pct': opts.ratio_threshold,
        'top_consumers': display_procs,
    }

    if opts.verbose:
        result['high_swap_processes'] = high_swap
        result['high_ratio_processes'] = high_ratio

    output.emit(result)

    # Set summary
    if high_swap or high_ratio:
        output.set_summary(f"{len(high_swap)} high swap, {len(high_ratio)} thrashing candidates")
    else:
        output.set_summary(f"{len(processes)} processes using swap, none above thresholds")

    output.render(opts.format, "Monitor per-process swap usage to identify swap pressure sources")

    return 1 if (high_swap or high_ratio) else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
