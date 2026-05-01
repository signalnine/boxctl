#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [load, cpu, performance, capacity]
#   requires: []
#   privilege: user
#   related: [proc_pressure, run_queue]
#   brief: Analyze system load average and CPU scheduling pressure

"""
Analyze system load average and correlate with CPU count for scheduling pressure.

Monitors /proc/loadavg and compares against CPU core count to detect CPU
saturation. Provides normalized load metrics and identifies when the system
is under pressure.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_loadavg(context: Context) -> dict[str, Any] | None:
    """Read load average from /proc/loadavg."""
    try:
        content = context.read_file('/proc/loadavg')
    except (FileNotFoundError, PermissionError):
        return None

    # Format: "0.37 0.48 0.52 1/742 12345"
    parts = content.strip().split()
    if len(parts) < 4:
        return None

    try:
        running_total = parts[3].split('/')
        return {
            'load_1min': float(parts[0]),
            'load_5min': float(parts[1]),
            'load_15min': float(parts[2]),
            'running_processes': int(running_total[0]),
            'total_processes': int(running_total[1]),
            'last_pid': int(parts[4]) if len(parts) > 4 else None,
        }
    except (ValueError, IndexError):
        return None


def get_uptime(context: Context) -> float | None:
    """Get system uptime in seconds."""
    try:
        content = context.read_file('/proc/uptime')
        return float(content.split()[0])
    except (FileNotFoundError, PermissionError, ValueError, IndexError):
        return None


def format_uptime(seconds: float) -> str:
    """Format uptime in human-readable form."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)

    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"


def analyze_load(
    loadavg: dict[str, Any],
    cpu_count: int,
    warn_threshold: float,
    crit_threshold: float
) -> dict[str, Any]:
    """Analyze load averages and generate assessment."""
    # Calculate per-CPU (normalized) load
    load_1min_norm = loadavg['load_1min'] / cpu_count
    load_5min_norm = loadavg['load_5min'] / cpu_count
    load_15min_norm = loadavg['load_15min'] / cpu_count

    issues = []

    # Check 1-minute load
    if load_1min_norm >= crit_threshold:
        issues.append({
            'type': 'LOAD_1MIN_CRITICAL',
            'severity': 'critical',
            'load': loadavg['load_1min'],
            'normalized': round(load_1min_norm, 2),
            'threshold': crit_threshold,
            'message': (
                f"1-min load {loadavg['load_1min']:.2f} "
                f"({load_1min_norm:.2f} per CPU) exceeds critical "
                f"threshold {crit_threshold}"
            )
        })
    elif load_1min_norm >= warn_threshold:
        issues.append({
            'type': 'LOAD_1MIN_WARNING',
            'severity': 'warning',
            'load': loadavg['load_1min'],
            'normalized': round(load_1min_norm, 2),
            'threshold': warn_threshold,
            'message': (
                f"1-min load {loadavg['load_1min']:.2f} "
                f"({load_1min_norm:.2f} per CPU) exceeds warning "
                f"threshold {warn_threshold}"
            )
        })

    # Check 5-minute load
    if load_5min_norm >= crit_threshold:
        issues.append({
            'type': 'LOAD_5MIN_CRITICAL',
            'severity': 'critical',
            'load': loadavg['load_5min'],
            'normalized': round(load_5min_norm, 2),
            'threshold': crit_threshold,
            'message': (
                f"5-min load {loadavg['load_5min']:.2f} "
                f"({load_5min_norm:.2f} per CPU) indicates sustained "
                f"critical pressure"
            )
        })
    elif load_5min_norm >= warn_threshold:
        issues.append({
            'type': 'LOAD_5MIN_WARNING',
            'severity': 'warning',
            'load': loadavg['load_5min'],
            'normalized': round(load_5min_norm, 2),
            'threshold': warn_threshold,
            'message': (
                f"5-min load {loadavg['load_5min']:.2f} "
                f"({load_5min_norm:.2f} per CPU) indicates sustained "
                f"warning pressure"
            )
        })

    # Determine overall status
    overall_status = 'ok'
    if any(i['severity'] == 'critical' for i in issues):
        overall_status = 'critical'
    elif any(i['severity'] == 'warning' for i in issues):
        overall_status = 'warning'

    # Trend analysis
    trend = 'stable'
    if loadavg['load_1min'] > loadavg['load_5min'] * 1.5:
        trend = 'increasing'
    elif loadavg['load_1min'] < loadavg['load_5min'] * 0.5:
        trend = 'decreasing'

    return {
        'status': overall_status,
        'cpu_count': cpu_count,
        'loadavg': loadavg,
        'normalized': {
            'load_1min': round(load_1min_norm, 2),
            'load_5min': round(load_5min_norm, 2),
            'load_15min': round(load_15min_norm, 2),
        },
        'trend': trend,
        'issues': issues,
    }


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
        description='Analyze system load average and CPU scheduling pressure'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed interpretation')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    parser.add_argument('--warn', type=float, default=1.0,
                        help='Warning threshold (per-CPU load, default: 1.0)')
    parser.add_argument('--crit', type=float, default=2.0,
                        help='Critical threshold (per-CPU load, default: 2.0)')
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0:
        output.error('--warn must be non-negative')

        output.render(opts.format, "Analyze system load average and CPU scheduling pressure")
        return 2
    if opts.crit < 0:
        output.error('--crit must be non-negative')

        output.render(opts.format, "Analyze system load average and CPU scheduling pressure")
        return 2
    if opts.crit < opts.warn:
        output.error('--crit must be >= --warn')

        output.render(opts.format, "Analyze system load average and CPU scheduling pressure")
        return 2

    # Check if we can read /proc
    if not context.file_exists('/proc/loadavg'):
        output.error('/proc/loadavg not available')

        output.render(opts.format, "Analyze system load average and CPU scheduling pressure")
        return 2

    # Get load average
    loadavg = get_loadavg(context)
    if loadavg is None:
        output.error('Unable to read load average')

        output.render(opts.format, "Analyze system load average and CPU scheduling pressure")
        return 2

    # Get CPU count
    cpu_count = context.cpu_count()

    # Get uptime
    uptime = get_uptime(context)

    # Analyze
    analysis = analyze_load(
        loadavg,
        cpu_count,
        warn_threshold=opts.warn,
        crit_threshold=opts.crit
    )

    # Build output
    data = {
        'status': analysis['status'],
        'cpu_count': cpu_count,
        'uptime_seconds': uptime,
        'uptime_formatted': format_uptime(uptime) if uptime else None,
        'load': {
            'raw': {
                '1min': loadavg['load_1min'],
                '5min': loadavg['load_5min'],
                '15min': loadavg['load_15min'],
            },
            'normalized': analysis['normalized'],
        },
        'processes': {
            'running': loadavg['running_processes'],
            'total': loadavg['total_processes'],
        },
        'trend': analysis['trend'],
        'issues': analysis['issues'],
    }

    output.emit(data)

    # Set summary
    output.set_summary(
        f"Load {loadavg['load_1min']:.2f}/{loadavg['load_5min']:.2f}/"
        f"{loadavg['load_15min']:.2f} ({analysis['status']})"
    )

    # Render output
    output.render(opts.format, "Analyze system load average and CPU scheduling pressure")

    # Return exit code
    if analysis['status'] in ['critical', 'warning']:
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
