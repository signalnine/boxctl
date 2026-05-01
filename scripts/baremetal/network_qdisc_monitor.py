#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [network, qdisc, traffic, drops, performance]
#   requires: [tc]
#   privilege: user
#   related: [network_peer_latency, socket_state_monitor]
#   brief: Monitor network qdisc statistics for packet drops and congestion

"""
Monitor network queuing discipline (qdisc) statistics for packet drops.

Analyzes traffic control (tc) qdisc statistics to identify:
- Interfaces with high packet drop rates
- Queues experiencing overlimit events
- Backlog buildup indicating congestion
"""

import argparse
import os
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_interfaces(context: Context) -> list[str]:
    """Get list of network interfaces from /sys/class/net."""
    interfaces = []
    try:
        net_path = '/sys/class/net'
        if context.file_exists(net_path):
            entries = context.glob('*', net_path)
            for entry in entries:
                iface = os.path.basename(entry)
                if iface != 'lo':
                    interfaces.append(iface)
    except Exception:
        pass
    return sorted(interfaces)


def parse_tc_qdisc_output(
    context: Context,
    interface: str
) -> list[dict[str, Any]]:
    """Parse tc -s qdisc show dev <interface> output."""
    qdiscs = []

    try:
        result = context.run(
            ['tc', '-s', 'qdisc', 'show', 'dev', interface],
            check=False
        )

        if result.returncode != 0:
            return qdiscs

        output = result.stdout
        if not output.strip():
            return qdiscs

        current_qdisc = None

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # New qdisc definition line
            if line.startswith('qdisc '):
                if current_qdisc:
                    qdiscs.append(current_qdisc)

                parts = line.split()
                qdisc_type = parts[1] if len(parts) > 1 else 'unknown'
                handle = parts[2] if len(parts) > 2 else ''

                parent = 'root'
                if 'parent' in line:
                    parent_match = re.search(r'parent\s+(\S+)', line)
                    if parent_match:
                        parent = parent_match.group(1)

                current_qdisc = {
                    'interface': interface,
                    'type': qdisc_type,
                    'handle': handle.rstrip(':'),
                    'parent': parent,
                    'sent_bytes': 0,
                    'sent_packets': 0,
                    'dropped': 0,
                    'overlimits': 0,
                    'requeues': 0,
                    'backlog_bytes': 0,
                    'backlog_packets': 0,
                    'qlen': 0,
                }

            # Statistics line
            elif current_qdisc and 'Sent' in line:
                sent_match = re.search(
                    r'Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt',
                    line
                )
                if sent_match:
                    current_qdisc['sent_bytes'] = int(sent_match.group(1))
                    current_qdisc['sent_packets'] = int(sent_match.group(2))

                dropped_match = re.search(r'dropped\s+(\d+)', line)
                if dropped_match:
                    current_qdisc['dropped'] = int(dropped_match.group(1))

                overlimits_match = re.search(r'overlimits\s+(\d+)', line)
                if overlimits_match:
                    current_qdisc['overlimits'] = int(overlimits_match.group(1))

                requeues_match = re.search(r'requeues\s+(\d+)', line)
                if requeues_match:
                    current_qdisc['requeues'] = int(requeues_match.group(1))

            # Backlog line
            elif current_qdisc and 'backlog' in line:
                backlog_match = re.search(
                    r'backlog\s+(\d+)b\s+(\d+)p',
                    line
                )
                if backlog_match:
                    current_qdisc['backlog_bytes'] = int(backlog_match.group(1))
                    current_qdisc['backlog_packets'] = int(backlog_match.group(2))

                qlen_match = re.search(r'qlen\s+(\d+)', line)
                if qlen_match:
                    current_qdisc['qlen'] = int(qlen_match.group(1))

        if current_qdisc:
            qdiscs.append(current_qdisc)

    except Exception:
        pass

    return qdiscs


def get_all_qdisc_stats(
    context: Context,
    interfaces: list[str] | None = None,
    include_loopback: bool = False
) -> list[dict[str, Any]]:
    """Get qdisc statistics for all interfaces."""
    all_qdiscs = []

    if interfaces is None:
        interfaces = get_interfaces(context)
        if include_loopback:
            interfaces.append('lo')

    for iface in interfaces:
        qdiscs = parse_tc_qdisc_output(context, iface)
        all_qdiscs.extend(qdiscs)

    return all_qdiscs


def calculate_drop_rate(qdisc: dict[str, Any]) -> float:
    """Calculate drop rate as percentage of sent packets."""
    sent = qdisc['sent_packets']
    dropped = qdisc['dropped']

    if sent == 0 and dropped == 0:
        return 0.0
    if sent == 0:
        return 100.0

    return (dropped / (sent + dropped)) * 100.0


def analyze_qdiscs(
    qdiscs: list[dict[str, Any]],
    drop_warn: float,
    drop_crit: float,
    backlog_warn: int,
    backlog_crit: int,
    min_packets: int
) -> dict[str, list[dict[str, Any]]]:
    """Analyze qdiscs and identify those with concerning statistics."""
    issues = {
        'critical': [],
        'warning': [],
        'info': [],
    }

    for qdisc in qdiscs:
        total_packets = qdisc['sent_packets'] + qdisc['dropped']
        if total_packets < min_packets:
            continue

        issue = {
            'qdisc': qdisc,
            'reasons': [],
        }

        severity = None
        drop_rate = calculate_drop_rate(qdisc)

        # Check drop rate
        if drop_rate >= drop_crit:
            issue['reasons'].append(
                f'Drop rate critical: {drop_rate:.2f}% '
                f'({qdisc["dropped"]} dropped of {total_packets} total)'
            )
            severity = 'critical'
        elif drop_rate >= drop_warn:
            issue['reasons'].append(
                f'Drop rate warning: {drop_rate:.2f}%'
            )
            severity = 'warning' if not severity else severity

        # Check backlog
        backlog = qdisc['backlog_packets']
        if backlog >= backlog_crit:
            issue['reasons'].append(
                f'Backlog critical: {backlog} packets queued'
            )
            severity = 'critical'
        elif backlog >= backlog_warn:
            issue['reasons'].append(
                f'Backlog warning: {backlog} packets queued'
            )
            severity = 'warning' if not severity else severity

        # Check overlimits
        if qdisc['overlimits'] > 0 and qdisc['overlimits'] > qdisc['sent_packets'] * 0.1:
            overlimit_pct = (qdisc['overlimits'] / max(qdisc['sent_packets'], 1)) * 100
            issue['reasons'].append(
                f'High overlimit rate: {overlimit_pct:.1f}%'
            )
            if not severity:
                severity = 'info'

        if issue['reasons']:
            issues[severity or 'info'].append(issue)

    return issues


def format_size(bytes_val: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(bytes_val) < 1024.0:
            return f'{bytes_val:.1f}{unit}'
        bytes_val /= 1024.0
    return f'{bytes_val:.1f}TB'


def format_count(count: int) -> str:
    """Format large numbers with K/M/G suffixes."""
    for unit in ['', 'K', 'M', 'G']:
        if abs(count) < 1000.0:
            if unit == '':
                return str(int(count))
            return f'{count:.1f}{unit}'
        count /= 1000.0
    return f'{count:.1f}T'


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Monitor network qdisc statistics for packet drops'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information including all qdisc stats')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    parser.add_argument('-i', '--interface', action='append', dest='interfaces',
                        help='Interface to monitor (can be specified multiple times)')
    parser.add_argument('--include-loopback', action='store_true',
                        help='Include loopback interface in monitoring')
    parser.add_argument('--drop-warn', type=float, default=1.0,
                        help='Drop rate warning threshold %% (default: 1.0)')
    parser.add_argument('--drop-crit', type=float, default=5.0,
                        help='Drop rate critical threshold %% (default: 5.0)')
    parser.add_argument('--backlog-warn', type=int, default=1000,
                        help='Backlog warning threshold packets (default: 1000)')
    parser.add_argument('--backlog-crit', type=int, default=10000,
                        help='Backlog critical threshold packets (default: 10000)')
    parser.add_argument('--min-packets', type=int, default=1000,
                        help='Minimum packets for analysis (default: 1000)')
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.drop_warn < 0 or opts.drop_crit < 0:
        output.error('Drop thresholds must be non-negative')

        output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
        return 2
    if opts.drop_warn > 100 or opts.drop_crit > 100:
        output.error('Drop thresholds cannot exceed 100%%')

        output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
        return 2
    if opts.drop_warn > opts.drop_crit:
        output.error('Drop warning threshold cannot exceed critical')

        output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
        return 2
    if opts.backlog_warn < 0 or opts.backlog_crit < 0:
        output.error('Backlog thresholds must be non-negative')

        output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
        return 2
    if opts.backlog_warn > opts.backlog_crit:
        output.error('Backlog warning threshold cannot exceed critical')

        output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
        return 2
    if opts.min_packets < 0:
        output.error('Minimum packets must be non-negative')

        output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
        return 2

    # Check if tc command is available
    if not context.check_tool('tc'):
        output.error('tc command not found. Install iproute2 package')

        output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
        return 2

    # Get qdisc statistics
    qdiscs = get_all_qdisc_stats(
        context,
        interfaces=opts.interfaces,
        include_loopback=opts.include_loopback
    )

    if not qdiscs:
        output.emit({
            'qdiscs': [],
            'issues': {'critical': [], 'warning': []},
            'summary': {
                'total_qdiscs': 0,
                'critical_count': 0,
                'warning_count': 0,
                'total_dropped': 0,
                'total_sent': 0,
            }
        })
        output.set_summary('No qdisc statistics available')

        output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
        return 0

    # Analyze qdiscs
    issues = analyze_qdiscs(
        qdiscs,
        opts.drop_warn, opts.drop_crit,
        opts.backlog_warn, opts.backlog_crit,
        opts.min_packets
    )

    # Build output
    data = {
        'summary': {
            'total_qdiscs': len(qdiscs),
            'critical_count': len(issues['critical']),
            'warning_count': len(issues['warning']),
            'total_dropped': sum(q['dropped'] for q in qdiscs),
            'total_sent': sum(q['sent_packets'] for q in qdiscs),
        },
        'issues': {
            'critical': [
                {
                    'qdisc': i['qdisc'],
                    'reasons': i['reasons'],
                    'drop_rate': calculate_drop_rate(i['qdisc']),
                }
                for i in issues['critical']
            ],
            'warning': [
                {
                    'qdisc': i['qdisc'],
                    'reasons': i['reasons'],
                    'drop_rate': calculate_drop_rate(i['qdisc']),
                }
                for i in issues['warning']
            ],
        },
    }

    if opts.verbose:
        data['qdiscs'] = qdiscs

    output.emit(data)

    # Set summary
    crit_count = len(issues['critical'])
    warn_count = len(issues['warning'])
    total_dropped = sum(q['dropped'] for q in qdiscs)

    if crit_count > 0 or warn_count > 0:
        output.set_summary(
            f"{crit_count} critical, {warn_count} warnings, "
            f"{format_count(total_dropped)} dropped"
        )
    else:
        output.set_summary('All qdiscs healthy')

    # Exit based on findings
    if issues['critical'] or issues['warning']:

        output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
        return 1

    output.render(opts.format, "Monitor network qdisc statistics for packet drops and congestion")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
