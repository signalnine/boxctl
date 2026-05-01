#!/usr/bin/env python3
# boxctl:
#   category: baremetal/ipc
#   tags: [ipc, semaphores, shared-memory, message-queues, resources]
#   requires: [ipcs]
#   privilege: user
#   related: [memory_pressure, process_limits_monitor]
#   brief: Monitor System V IPC resource usage (semaphores, shared memory, message queues)

"""
Monitor System V IPC resource usage (semaphores, shared memory, message queues).

System V IPC resources are used by many enterprise applications including:
- Databases (PostgreSQL, Oracle, MySQL, SAP HANA)
- Message brokers and middleware
- Legacy enterprise applications
- High-performance computing applications

This script monitors:
- Semaphore arrays and individual semaphores
- Shared memory segments and total usage
- Message queues and queue sizes
- Usage vs kernel limits (from /proc/sys/kernel)

Common failure modes:
- "No space left on device" when semaphore arrays exhausted
- "Cannot allocate memory" for shared memory limits
- Orphaned IPC resources from crashed applications
- Resource leaks over time
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_kernel_limits(context: Context) -> dict[str, Any]:
    """Get System V IPC kernel limits from /proc/sys/kernel."""
    limits: dict[str, Any] = {}

    # Semaphore limits (SEMMSL SEMMNS SEMOPM SEMMNI)
    try:
        sem_val = context.read_file('/proc/sys/kernel/sem')
        parts = sem_val.split()
        if len(parts) >= 4:
            limits['sem'] = {
                'semmsl': int(parts[0]),  # Max semaphores per array
                'semmns': int(parts[1]),  # Max semaphores system-wide
                'semopm': int(parts[2]),  # Max ops per semop call
                'semmni': int(parts[3]),  # Max semaphore arrays
            }
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    # Shared memory limits
    try:
        shmmax = context.read_file('/proc/sys/kernel/shmmax')
        limits['shmmax'] = int(shmmax.strip())
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    try:
        shmall = context.read_file('/proc/sys/kernel/shmall')
        limits['shmall'] = int(shmall.strip())
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    try:
        shmmni = context.read_file('/proc/sys/kernel/shmmni')
        limits['shmmni'] = int(shmmni.strip())
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    # Message queue limits
    try:
        msgmax = context.read_file('/proc/sys/kernel/msgmax')
        limits['msgmax'] = int(msgmax.strip())
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    try:
        msgmnb = context.read_file('/proc/sys/kernel/msgmnb')
        limits['msgmnb'] = int(msgmnb.strip())
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    try:
        msgmni = context.read_file('/proc/sys/kernel/msgmni')
        limits['msgmni'] = int(msgmni.strip())
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    return limits


def run_ipcs(resource_type: str, context: Context) -> list[dict[str, Any]] | None:
    """Run ipcs command and parse output."""
    result = context.run(['ipcs', f'-{resource_type}'], check=False)
    if result.returncode != 0:
        return None

    resources = []
    lines = result.stdout.strip().split('\n')

    # Skip header lines (varies by type)
    in_data = False
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Detect start of data section
        if line.startswith('---'):
            in_data = True
            continue

        if not in_data:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        if resource_type == 's':  # Semaphores
            if len(parts) >= 5:
                try:
                    resources.append({
                        'key': parts[0],
                        'id': int(parts[1]),
                        'owner': parts[2],
                        'perms': parts[3],
                        'nsems': int(parts[4]) if len(parts) > 4 else 0
                    })
                except (ValueError, IndexError):
                    continue

        elif resource_type == 'm':  # Shared memory
            if len(parts) >= 5:
                try:
                    resources.append({
                        'key': parts[0],
                        'id': int(parts[1]),
                        'owner': parts[2],
                        'perms': parts[3],
                        'bytes': int(parts[4]),
                        'nattch': int(parts[5]) if len(parts) > 5 else 0
                    })
                except (ValueError, IndexError):
                    continue

        elif resource_type == 'q':  # Message queues
            if len(parts) >= 5:
                try:
                    resources.append({
                        'key': parts[0],
                        'id': int(parts[1]),
                        'owner': parts[2],
                        'perms': parts[3],
                        'used_bytes': int(parts[4]),
                        'messages': int(parts[5]) if len(parts) > 5 else 0
                    })
                except (ValueError, IndexError):
                    continue

    return resources


def calculate_usage(stats: dict[str, Any]) -> dict[str, Any]:
    """Calculate usage statistics."""
    usage: dict[str, Any] = {}
    limits = stats.get('limits', {})

    # Semaphore usage
    sem_arrays = len(stats.get('semaphores', []))
    total_sems = sum(s.get('nsems', 0) for s in stats.get('semaphores', []))

    sem_limits = limits.get('sem', {})
    usage['semaphores'] = {
        'arrays': sem_arrays,
        'total_semaphores': total_sems,
        'max_arrays': sem_limits.get('semmni', 0),
        'max_total': sem_limits.get('semmns', 0),
        'arrays_pct': (sem_arrays / sem_limits['semmni'] * 100)
            if sem_limits.get('semmni', 0) > 0 else 0,
        'total_pct': (total_sems / sem_limits['semmns'] * 100)
            if sem_limits.get('semmns', 0) > 0 else 0,
    }

    # Shared memory usage
    shm_segments = len(stats.get('shared_memory', []))
    shm_bytes = sum(s.get('bytes', 0) for s in stats.get('shared_memory', []))
    shm_max_segments = limits.get('shmmni', 0)

    usage['shared_memory'] = {
        'segments': shm_segments,
        'total_bytes': shm_bytes,
        'max_segments': shm_max_segments,
        'segments_pct': (shm_segments / shm_max_segments * 100)
            if shm_max_segments > 0 else 0,
    }

    # Message queue usage
    queues = stats.get('message_queues', [])
    queue_count = len(queues)
    queue_bytes = sum(q.get('used_bytes', 0) for q in queues)
    queue_msgs = sum(q.get('messages', 0) for q in queues)
    max_queues = limits.get('msgmni', 0)

    usage['message_queues'] = {
        'queues': queue_count,
        'total_bytes': queue_bytes,
        'total_messages': queue_msgs,
        'max_queues': max_queues,
        'queues_pct': (queue_count / max_queues * 100)
            if max_queues > 0 else 0,
    }

    return usage


def detect_orphans(stats: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect potentially orphaned IPC resources."""
    orphans = []

    # Check for shared memory with 0 attachments (potential orphan)
    for shm in stats.get('shared_memory', []):
        if shm.get('nattch', 0) == 0:
            orphans.append({
                'type': 'shared_memory',
                'id': shm['id'],
                'owner': shm['owner'],
                'bytes': shm['bytes'],
                'reason': 'No processes attached'
            })

    return orphans


def format_bytes(bytes_val: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f}PB"


def analyze_ipc(
    stats: dict[str, Any],
    usage: dict[str, Any],
    warn_pct: float,
    crit_pct: float
) -> list[dict[str, Any]]:
    """Analyze IPC usage and generate issues."""
    issues = []

    # Check semaphore array usage
    sem_arrays_pct = usage['semaphores']['arrays_pct']
    if sem_arrays_pct >= crit_pct:
        issues.append({
            'severity': 'CRITICAL',
            'resource': 'semaphore_arrays',
            'value': usage['semaphores']['arrays'],
            'max': usage['semaphores']['max_arrays'],
            'pct': round(sem_arrays_pct, 1),
            'message': f"Semaphore arrays near limit: {sem_arrays_pct:.1f}%"
        })
    elif sem_arrays_pct >= warn_pct:
        issues.append({
            'severity': 'WARNING',
            'resource': 'semaphore_arrays',
            'value': usage['semaphores']['arrays'],
            'max': usage['semaphores']['max_arrays'],
            'pct': round(sem_arrays_pct, 1),
            'message': f"Semaphore arrays usage high: {sem_arrays_pct:.1f}%"
        })

    # Check total semaphore usage
    sem_total_pct = usage['semaphores']['total_pct']
    if sem_total_pct >= crit_pct:
        issues.append({
            'severity': 'CRITICAL',
            'resource': 'semaphores_total',
            'value': usage['semaphores']['total_semaphores'],
            'max': usage['semaphores']['max_total'],
            'pct': round(sem_total_pct, 1),
            'message': f"Total semaphores near limit: {sem_total_pct:.1f}%"
        })
    elif sem_total_pct >= warn_pct:
        issues.append({
            'severity': 'WARNING',
            'resource': 'semaphores_total',
            'value': usage['semaphores']['total_semaphores'],
            'max': usage['semaphores']['max_total'],
            'pct': round(sem_total_pct, 1),
            'message': f"Total semaphores usage high: {sem_total_pct:.1f}%"
        })

    # Check shared memory segment usage
    shm_pct = usage['shared_memory']['segments_pct']
    if shm_pct >= crit_pct:
        issues.append({
            'severity': 'CRITICAL',
            'resource': 'shm_segments',
            'value': usage['shared_memory']['segments'],
            'max': usage['shared_memory']['max_segments'],
            'pct': round(shm_pct, 1),
            'message': f"Shared memory segments near limit: {shm_pct:.1f}%"
        })
    elif shm_pct >= warn_pct:
        issues.append({
            'severity': 'WARNING',
            'resource': 'shm_segments',
            'value': usage['shared_memory']['segments'],
            'max': usage['shared_memory']['max_segments'],
            'pct': round(shm_pct, 1),
            'message': f"Shared memory segments usage high: {shm_pct:.1f}%"
        })

    # Check message queue usage
    queue_pct = usage['message_queues']['queues_pct']
    if queue_pct >= crit_pct:
        issues.append({
            'severity': 'CRITICAL',
            'resource': 'message_queues',
            'value': usage['message_queues']['queues'],
            'max': usage['message_queues']['max_queues'],
            'pct': round(queue_pct, 1),
            'message': f"Message queues near limit: {queue_pct:.1f}%"
        })
    elif queue_pct >= warn_pct:
        issues.append({
            'severity': 'WARNING',
            'resource': 'message_queues',
            'value': usage['message_queues']['queues'],
            'max': usage['message_queues']['max_queues'],
            'pct': round(queue_pct, 1),
            'message': f"Message queue usage high: {queue_pct:.1f}%"
        })

    # Check for orphaned resources
    orphans = detect_orphans(stats)
    if orphans:
        orphan_bytes = sum(o.get('bytes', 0) for o in orphans)
        issues.append({
            'severity': 'WARNING',
            'resource': 'orphaned_shm',
            'value': len(orphans),
            'bytes': orphan_bytes,
            'message': f"Found {len(orphans)} potentially orphaned shared memory segments "
                      f"({format_bytes(orphan_bytes)} total)"
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
    parser = argparse.ArgumentParser(
        description='Monitor System V IPC resource usage'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information including per-owner breakdown')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show warnings and errors')
    parser.add_argument('--warn', type=float, default=75.0, metavar='PERCENT',
                        help='Warning threshold percentage (default: 75)')
    parser.add_argument('--crit', type=float, default=90.0, metavar='PERCENT',
                        help='Critical threshold percentage (default: 90)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error('--warn must be between 0 and 100')

        output.render(opts.format, "Monitor System V IPC resource usage (semaphores, shared memory, message queues)")
        return 2

    if opts.crit < 0 or opts.crit > 100:
        output.error('--crit must be between 0 and 100')

        output.render(opts.format, "Monitor System V IPC resource usage (semaphores, shared memory, message queues)")
        return 2

    if opts.crit <= opts.warn:
        output.error('--crit must be greater than --warn')

        output.render(opts.format, "Monitor System V IPC resource usage (semaphores, shared memory, message queues)")
        return 2

    # Check if ipcs is available
    if not context.check_tool('ipcs'):
        output.error('ipcs command not found. Install util-linux.')

        output.render(opts.format, "Monitor System V IPC resource usage (semaphores, shared memory, message queues)")
        return 2

    # Gather IPC statistics
    stats: dict[str, Any] = {
        'semaphores': [],
        'shared_memory': [],
        'message_queues': [],
        'limits': get_kernel_limits(context)
    }

    # Get semaphores
    sems = run_ipcs('s', context)
    if sems is not None:
        stats['semaphores'] = sems

    # Get shared memory
    shm = run_ipcs('m', context)
    if shm is not None:
        stats['shared_memory'] = shm

    # Get message queues
    queues = run_ipcs('q', context)
    if queues is not None:
        stats['message_queues'] = queues

    # Calculate usage percentages
    usage = calculate_usage(stats)

    # Analyze and detect issues
    issues = analyze_ipc(stats, usage, opts.warn, opts.crit)

    # Prepare output
    output_data: dict[str, Any] = {
        'usage': usage,
        'limits': stats.get('limits', {}),
        'issues': issues,
        'resource_counts': {
            'semaphore_arrays': len(stats.get('semaphores', [])),
            'shm_segments': len(stats.get('shared_memory', [])),
            'message_queues': len(stats.get('message_queues', []))
        },
        'has_issues': len(issues) > 0
    }

    if opts.verbose:
        # Add detailed breakdown
        output_data['semaphores'] = stats['semaphores']
        output_data['shared_memory'] = stats['shared_memory']
        output_data['message_queues'] = stats['message_queues']

    output.emit(output_data)

    # Set summary
    sem = usage['semaphores']
    shm = usage['shared_memory']
    mq = usage['message_queues']
    output.set_summary(
        f"IPC: {sem['arrays']} sem arrays, {shm['segments']} shm segments, "
        f"{mq['queues']} msg queues, {len(issues)} issues"
    )

    # Exit with appropriate code

    output.render(opts.format, "Monitor System V IPC resource usage (semaphores, shared memory, message queues)")
    return 1 if issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
