#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [udp, sockets, network, resources, connections]
#   requires: []
#   privilege: user
#   related: [tcp_connection_monitor, conntrack_monitor, route_health_monitor]
#   brief: Monitor UDP socket usage to detect resource exhaustion and anomalies

"""
Monitor UDP socket usage to detect resource exhaustion and anomalies.

Analyzes /proc/net/udp and /proc/net/udp6 to provide visibility into UDP
socket states across the system. Identifies processes with high socket counts,
queue buildup, and potential resource exhaustion.

Key features:
- Reports UDP socket counts by local port
- Identifies processes holding many UDP sockets
- Detects receive queue buildup (packets waiting to be read)
- Detects transmit queue buildup (packets waiting to be sent)
- Supports filtering by port or process

Use cases:
- Detecting UDP socket leaks in long-running services
- Identifying receive queue buildup on DNS/NTP/SNMP servers
- Finding services not draining UDP buffers
- Pre-incident visibility into UDP resource pressure
- Capacity planning for high-UDP workloads
"""

import argparse
import re
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def hex_to_ip(hex_ip: str) -> str:
    """Convert hex IP address to dotted decimal notation."""
    if len(hex_ip) == 8:
        # Little-endian byte order in /proc/net/udp
        ip_int = int(hex_ip, 16)
        return '.'.join([
            str((ip_int >> 0) & 0xFF),
            str((ip_int >> 8) & 0xFF),
            str((ip_int >> 16) & 0xFF),
            str((ip_int >> 24) & 0xFF),
        ])
    elif len(hex_ip) == 32:
        return 'ipv6'
    return hex_ip


def hex_to_port(hex_port: str) -> int:
    """Convert hex port to integer."""
    return int(hex_port, 16)


def parse_udp_sockets(content: str, ipv6: bool = False) -> list[dict[str, Any]]:
    """Parse /proc/net/udp or /proc/net/udp6 content."""
    sockets = []
    lines = content.strip().split('\n')[1:]  # Skip header

    for line in lines:
        parts = line.split()
        if len(parts) < 13:
            continue

        try:
            # Parse local address
            local_addr = parts[1]
            local_ip, local_port = local_addr.split(':')
            local_port_int = hex_to_port(local_port)

            # Parse remote address
            remote_addr = parts[2]
            remote_ip, remote_port = remote_addr.split(':')
            remote_port_int = hex_to_port(remote_port)

            # Parse queues (tx_queue:rx_queue in hex)
            queue_info = parts[4]
            tx_queue_hex, rx_queue_hex = queue_info.split(':')
            tx_queue = int(tx_queue_hex, 16)
            rx_queue = int(rx_queue_hex, 16)

            # Get inode
            inode = int(parts[9])

            # Get drops if available
            drops = 0
            if len(parts) > 12:
                try:
                    drops = int(parts[12])
                except ValueError:
                    drops = 0

            sockets.append({
                'local_ip': hex_to_ip(local_ip),
                'local_port': local_port_int,
                'remote_ip': hex_to_ip(remote_ip),
                'remote_port': remote_port_int,
                'tx_queue': tx_queue,
                'rx_queue': rx_queue,
                'drops': drops,
                'inode': inode,
                'ipv6': ipv6,
            })
        except (ValueError, IndexError):
            continue

    return sockets


def get_inode_to_pid_map(context: Context) -> dict[int, tuple[int, str]]:
    """Build a map from socket inode to (pid, command name)."""
    inode_map: dict[int, tuple[int, str]] = {}

    # Get list of process directories
    proc_dirs = context.glob('[0-9]*', '/proc')

    for proc_dir in proc_dirs:
        pid_str = proc_dir.split('/')[-1]
        if not pid_str.isdigit():
            continue

        pid = int(pid_str)

        # Get command name
        try:
            comm = context.read_file(f'{proc_dir}/comm').strip()
        except (FileNotFoundError, PermissionError):
            comm = 'unknown'

        # Scan file descriptors for socket inodes
        fd_pattern = f'{proc_dir}/fd/*'
        try:
            fd_files = context.glob('*', f'{proc_dir}/fd')
            for fd_path in fd_files:
                try:
                    # Use readlink for symlinks
                    link = context.readlink(fd_path)
                    if not link:
                        continue
                    if link.startswith('socket:['):
                        inode = int(link[8:-1])
                        inode_map[inode] = (pid, comm)
                except (FileNotFoundError, PermissionError, ValueError):
                    continue
        except (FileNotFoundError, PermissionError):
            continue

    return inode_map


def enrich_with_process_info(
    sockets: list[dict],
    inode_map: dict[int, tuple[int, str]]
) -> None:
    """Add process information to sockets."""
    for sock in sockets:
        inode = sock.get('inode', 0)
        if inode in inode_map:
            pid, comm = inode_map[inode]
            sock['pid'] = pid
            sock['process'] = comm
        else:
            sock['pid'] = None
            sock['process'] = None


def filter_sockets(
    sockets: list[dict],
    port_filter: int | None = None,
    process_filter: str | None = None
) -> list[dict]:
    """Filter sockets by port or process."""
    filtered = sockets

    if port_filter is not None:
        filtered = [s for s in filtered
                    if s['local_port'] == port_filter or s['remote_port'] == port_filter]

    if process_filter:
        pattern = re.compile(process_filter, re.IGNORECASE)
        filtered = [s for s in filtered
                    if s.get('process') and pattern.search(s['process'])]

    return filtered


def analyze_sockets(
    sockets: list[dict],
    socket_warn: int,
    rx_queue_warn: int,
    tx_queue_warn: int
) -> dict[str, Any]:
    """Analyze sockets and generate summary."""
    # Count by process
    process_counts: dict[str, dict[str, int]] = defaultdict(lambda: {
        'count': 0,
        'total_rx_queue': 0,
        'total_tx_queue': 0,
        'total_drops': 0,
    })
    for sock in sockets:
        proc = sock.get('process') or 'unknown'
        process_counts[proc]['count'] += 1
        process_counts[proc]['total_rx_queue'] += sock['rx_queue']
        process_counts[proc]['total_tx_queue'] += sock['tx_queue']
        process_counts[proc]['total_drops'] += sock['drops']

    # Count by local port
    port_counts: dict[int, dict[str, int]] = defaultdict(lambda: {
        'count': 0,
        'total_rx_queue': 0,
        'total_tx_queue': 0,
    })
    for sock in sockets:
        port = sock['local_port']
        port_counts[port]['count'] += 1
        port_counts[port]['total_rx_queue'] += sock['rx_queue']
        port_counts[port]['total_tx_queue'] += sock['tx_queue']

    # Calculate totals
    total_rx_queue = sum(s['rx_queue'] for s in sockets)
    total_tx_queue = sum(s['tx_queue'] for s in sockets)
    total_drops = sum(s['drops'] for s in sockets)

    # Identify issues
    issues = []

    total_count = len(sockets)
    if total_count >= socket_warn:
        issues.append({
            'type': 'SOCKET_COUNT_HIGH',
            'severity': 'warning',
            'count': total_count,
            'threshold': socket_warn,
            'message': f'High UDP socket count: {total_count} (threshold: {socket_warn})'
        })

    if total_rx_queue >= rx_queue_warn:
        issues.append({
            'type': 'RX_QUEUE_HIGH',
            'severity': 'warning',
            'bytes': total_rx_queue,
            'threshold': rx_queue_warn,
            'message': f'High total RX queue: {total_rx_queue} bytes (threshold: {rx_queue_warn})'
        })

    if total_tx_queue >= tx_queue_warn:
        issues.append({
            'type': 'TX_QUEUE_HIGH',
            'severity': 'warning',
            'bytes': total_tx_queue,
            'threshold': tx_queue_warn,
            'message': f'High total TX queue: {total_tx_queue} bytes (threshold: {tx_queue_warn})'
        })

    # Find sockets with significant queue buildup
    for sock in sockets:
        if sock['rx_queue'] >= 100000:  # 100KB
            proc = sock.get('process') or 'unknown'
            issues.append({
                'type': 'SOCKET_RX_QUEUE_HIGH',
                'severity': 'warning',
                'process': proc,
                'port': sock['local_port'],
                'bytes': sock['rx_queue'],
                'message': f'Socket on port {sock["local_port"]} ({proc}) has {sock["rx_queue"]} bytes in RX queue'
            })

    # Find processes with many sockets
    for proc, stats in process_counts.items():
        if stats['count'] >= 100:
            issues.append({
                'type': 'PROCESS_SOCKET_HIGH',
                'severity': 'warning',
                'process': proc,
                'count': stats['count'],
                'message': f'Process "{proc}" has {stats["count"]} UDP sockets'
            })

    return {
        'total': len(sockets),
        'total_rx_queue': total_rx_queue,
        'total_tx_queue': total_tx_queue,
        'total_drops': total_drops,
        'process_counts': {k: dict(v) for k, v in process_counts.items()},
        'port_counts': {k: dict(v) for k, v in port_counts.items()},
        'issues': issues,
    }


def format_bytes(num: int) -> str:
    """Format bytes in human-readable form."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num) < 1024.0:
            return f"{num:.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}TB"


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
        description='Monitor UDP socket usage for issues'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show individual sockets')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show if there are issues')
    parser.add_argument('--port', type=int, metavar='PORT',
                        help='Filter to sockets on this port')
    parser.add_argument('--process', type=str, metavar='PATTERN',
                        help='Filter to processes matching pattern (regex)')
    parser.add_argument('--socket-warn', type=int, default=1000, metavar='N',
                        help='Warn if socket count exceeds N (default: 1000)')
    parser.add_argument('--rx-queue-warn', type=int, default=1048576, metavar='BYTES',
                        help='Warn if total RX queue exceeds BYTES (default: 1MB)')
    parser.add_argument('--tx-queue-warn', type=int, default=1048576, metavar='BYTES',
                        help='Warn if total TX queue exceeds BYTES (default: 1MB)')
    parser.add_argument('--top', type=int, default=10, metavar='N',
                        help='Show top N processes/ports (default: 10)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.socket_warn < 0:
        output.error('--socket-warn must be non-negative')

        output.render(opts.format, "Monitor UDP socket usage to detect resource exhaustion and anomalies")
        return 2
    if opts.rx_queue_warn < 0:
        output.error('--rx-queue-warn must be non-negative')

        output.render(opts.format, "Monitor UDP socket usage to detect resource exhaustion and anomalies")
        return 2
    if opts.tx_queue_warn < 0:
        output.error('--tx-queue-warn must be non-negative')

        output.render(opts.format, "Monitor UDP socket usage to detect resource exhaustion and anomalies")
        return 2

    # Validate regex pattern
    if opts.process:
        try:
            re.compile(opts.process)
        except re.error as e:
            output.error(f'Invalid process pattern: {e}')
            return 2

    # Check if we can read /proc
    if not context.file_exists('/proc/net/udp'):
        output.error('/proc/net/udp not available. Requires procfs.')

        output.render(opts.format, "Monitor UDP socket usage to detect resource exhaustion and anomalies")
        return 2

    # Get sockets
    sockets = []
    try:
        udp_content = context.read_file('/proc/net/udp')
        sockets.extend(parse_udp_sockets(udp_content, ipv6=False))
    except (FileNotFoundError, PermissionError):
        pass

    try:
        udp6_content = context.read_file('/proc/net/udp6')
        sockets.extend(parse_udp_sockets(udp6_content, ipv6=True))
    except (FileNotFoundError, PermissionError):
        pass

    # Build inode to process map (skip if no sockets to enrich)
    if sockets:
        inode_map = get_inode_to_pid_map(context)
        enrich_with_process_info(sockets, inode_map)

    # Apply filters
    sockets = filter_sockets(
        sockets,
        port_filter=opts.port,
        process_filter=opts.process
    )

    # Analyze
    analysis = analyze_sockets(
        sockets,
        socket_warn=opts.socket_warn,
        rx_queue_warn=opts.rx_queue_warn,
        tx_queue_warn=opts.tx_queue_warn
    )

    # Prepare output
    status = 'warning' if analysis['issues'] else 'ok'

    output_data: dict[str, Any] = {
        'status': status,
        'summary': {
            'total_sockets': analysis['total'],
            'total_rx_queue': analysis['total_rx_queue'],
            'total_tx_queue': analysis['total_tx_queue'],
            'total_drops': analysis['total_drops'],
            'issue_count': len(analysis['issues']),
        },
        'issues': analysis['issues'],
        'by_process': analysis['process_counts'],
        'by_port': {str(k): v for k, v in analysis['port_counts'].items()},
    }

    if opts.verbose:
        output_data['sockets'] = sockets

    output.emit(output_data)
    output.set_summary(
        f"UDP: {analysis['total']} sockets, "
        f"RX queue: {format_bytes(analysis['total_rx_queue'])}, "
        f"{len(analysis['issues'])} issues"
    )

    # Exit code based on issues

    output.render(opts.format, "Monitor UDP socket usage to detect resource exhaustion and anomalies")
    return 1 if analysis['issues'] else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
