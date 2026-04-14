# boxctl

A diagnostic toolkit designed for LLM agents to investigate baremetal and Kubernetes infrastructure issues.

## Why boxctl?

LLM agents excel at reasoning about complex systems, but they need structured access to system state. boxctl provides:

- **315 diagnostic scripts** covering baremetal (216) and Kubernetes (93) systems
- **Consistent JSON output** that agents can parse and reason about
- **Semantic exit codes** (0=healthy, 1=issues, 2=error) for decision-making
- **Rich metadata** so agents can discover relevant scripts by symptom or keyword
- **MCP server** so Claude Code / Cursor / Windsurf can call scripts as tools
- **Remote execution** over SSH against an inventory of hosts, with a
  restricted-shell provisioning flow for read-only access
- **Automatic secret redaction** of PEM keys, AWS keys, JWTs, API tokens, and
  DB connection strings in all rendered output
- **Testable design** with dependency injection for reliable operation

## How Agents Use boxctl

### 1. Discover Relevant Scripts

When investigating an issue, agents search for scripts by symptom:

```bash
boxctl search "high load"
# Returns: loadavg_analyzer, cpu_usage, context_switch_monitor, run_queue_monitor

boxctl search "disk full"
# Returns: disk_space_forecaster, inode_usage, filesystem_usage

boxctl search "pod pending"
# Returns: pending_pod_analyzer, node_capacity, resource_quota_auditor
```

### 2. Run Diagnostics with JSON Output

Agents run scripts and parse structured output:

```bash
boxctl run loadavg_analyzer --format json
```

```json
{
  "load_1m": 4.2,
  "load_5m": 3.8,
  "load_15m": 2.1,
  "cpu_count": 4,
  "per_cpu_load_1m": 1.05,
  "status": "elevated",
  "top_contributors": [
    {"pid": 1234, "comm": "postgres", "cpu_percent": 45.2},
    {"pid": 5678, "comm": "nginx", "cpu_percent": 22.1}
  ]
}
```

### 3. Follow Investigation Paths

Scripts include `related` metadata pointing to next steps:

```bash
boxctl show loadavg_analyzer
# Related: cpu_usage, context_switch_monitor, process_tree, run_queue_monitor
```

Agents use exit codes to guide investigation depth:
- Exit 0: Move to next area
- Exit 1: Found issues, investigate further with related scripts
- Exit 2: Tool missing, try alternative approach

### 4. Synthesize Findings

After running multiple scripts, agents combine structured data to form conclusions:

```
Investigation: High API latency on production servers

Scripts run:
- loadavg_analyzer (exit 1): Load 4.2 on 4 CPUs, postgres consuming 45%
- disk_io_latency (exit 1): /dev/sda p99 latency 45ms (threshold: 20ms)
- memory_fragmentation (exit 0): Normal
- tcp_connection_monitor (exit 0): Normal connection counts

Conclusion: Database I/O contention causing elevated load.
Recommendation: Investigate postgres query patterns, consider SSD upgrade.
```

## Script Categories

### Baremetal (216 scripts)

| Category | Scripts | Coverage |
|----------|---------|----------|
| `baremetal/network` | 30 | TCP/UDP monitoring, ARP, ethtool, firewall audit |
| `baremetal/disk` | 29 | SMART health, I/O latency, NVMe, ZFS, RAID |
| `baremetal/security` | 25 | Kernel hardening, SSH audit, SUID/SGID, auditd |
| `baremetal/memory` | 16 | Fragmentation, OOM risk, hugepages, NUMA |
| `baremetal/kernel` | 14 | Taint flags, module audit, dmesg analysis |
| `baremetal/process` | 14 | FD exhaustion, zombie detection, connection audit |
| `baremetal/storage` | 13 | LVM, btrfs, multipath, iSCSI, Ceph |
| `baremetal/hardware` | 12 | IPMI sensors, temperature, PCIe, USB |
| `baremetal/cpu` | 10 | Steal time, context switches, NUMA locality |
| `baremetal/systemd` | 9 | Service health, timer monitoring, journal analysis |

### Kubernetes (93 scripts)

| Category | Scripts | Coverage |
|----------|---------|----------|
| `k8s/workloads` | 10 | Deployments, StatefulSets, DaemonSets, Jobs |
| `k8s/security` | 10 | Pod security, RBAC, secrets, network policies |
| `k8s/nodes` | 9 | Node health, capacity, pressure conditions |
| `k8s/resources` | 9 | Quotas, limits, resource utilization |
| `k8s/networking` | 8 | Services, ingress, endpoints, DNS |
| `k8s/cluster` | 8 | API server, etcd, control plane health |
| `k8s/storage` | 8 | PV/PVC health, storage classes, CSI |
| `k8s/pods` | 5 | Pending analysis, disruption budgets, eviction |

## CLI Reference

### Discovery Commands

```bash
# List all scripts
boxctl list

# Filter by category
boxctl list --category baremetal/disk
boxctl list --category k8s/pods

# Filter by tag
boxctl list --tag health
boxctl list --tag security

# Search by keyword (searches names, tags, descriptions)
boxctl search "memory leak"
boxctl search "node pressure"
```

### Execution Commands

```bash
# Run a script
boxctl run disk_health

# JSON output for agent parsing
boxctl run disk_health --format json

# Pass arguments to script
boxctl run disk_health -- --device /dev/sda

# Verbose output
boxctl run disk_health -v
```

### Inspection Commands

```bash
# Show script metadata
boxctl show disk_health
# Displays: category, tags, required tools, privilege level, related scripts, docstring

# Check script health
boxctl doctor
boxctl doctor --category baremetal

# Validate metadata format
boxctl lint
```

### Remote Execution

Run any script against a remote host (or a group of hosts) via SSH:

```bash
# One-off against an inventory host
boxctl run loadavg_analyzer --host prod-1

# Fan out to a named group
boxctl run disk_health --host group:web

# Comma-separated selectors
boxctl run nvme_health --host prod-1,prod-2 --format json

# Override the inventory path
boxctl run loadavg_analyzer --host prod-1 --inventory /etc/boxctl/hosts.yml
```

Inventory format (`~/.config/boxctl/hosts.yml` by default):

```yaml
hosts:
  prod-1:
    host: 10.0.0.1
    user: boxctl-readonly
    port: 22
    identity: ~/.ssh/id_ed25519
  prod-2:
    host: 10.0.0.2
groups:
  web: [prod-1, prod-2]
```

SSH is invoked with `BatchMode=yes` and `ConnectTimeout=10`, so commands
fail fast instead of hanging on password prompts. The script source is
piped over stdin to `python3 -` on the remote, which means the only
binary the restricted shell needs to permit is `python3`.

### Provisioning a Read-Only Host

`boxctl source prepare` provisions a `boxctl-readonly` user on a target
host with a custom login shell that rejects interactive sessions, shell
metacharacters (`; | & < > $ \``), and any command outside a narrow
allowlist. Tool-level access (smartctl, mdadm, ...) is carried by the
Unix user's own privileges, not by the SSH shell.

```bash
# List hosts in the current inventory
boxctl source list
boxctl source list --format json

# Provision the restricted user on a target (requires passwordless sudo
# as the connecting admin user)
boxctl source prepare prod-1 --pubkey ~/.ssh/boxctl_ed25519.pub

# Override the connecting user
boxctl source prepare prod-1 --pubkey key.pub --admin-user root

# Extend the SSH allowlist (each --allow is validated against an
# injection-safe regex)
boxctl source prepare prod-1 --pubkey key.pub --allow smartctl --allow mdadm
```

Re-running `prepare` is idempotent: it updates the shell in place, adds
the public key if missing, and ensures the shell is registered in
`/etc/shells`.

### MCP Server

`boxctl mcp` starts a Model Context Protocol server on stdio so Claude
Code, Cursor, or Windsurf can discover and call scripts as tools:

```bash
# Smoke test
boxctl mcp  # then ^C
```

Claude Code config snippet:

```json
{
  "mcpServers": {
    "boxctl": {
      "command": "boxctl",
      "args": ["mcp", "--scripts-dir", "/home/you/boxctl"]
    }
  }
}
```

Four tools are exposed: `list_scripts`, `search_scripts`, `show_script`,
`run_script`. Script output passes through the redaction filter by
default; the `run_script` tool accepts `redact=False` for callers that
need raw output. Install the optional extra: `pip install boxctl[mcp]`.

### Secret Redaction

All rendered output (CLI and MCP) is scrubbed for common secret shapes
before it leaves the process:

| Pattern | Replacement |
|---------|-------------|
| PEM private key blocks (RSA/EC/OpenSSH/ED25519) | `[REDACTED:pem-key]` |
| AWS access/session keys (`AKIA...`, `ASIA...`) | `[REDACTED:aws-key]` |
| JWTs (`eyJ...`) | `[REDACTED:jwt]` |
| `sk-*` API tokens | `[REDACTED:api-key]` |
| DB URI credentials (`postgres://user:pw@...`) | `postgres://[REDACTED:db-cred]@...` |

`output.data` itself is never mutated -- redaction runs only at render
time. Disable with `boxctl --no-redact` or `BOXCTL_NO_REDACT=1` in the
environment (useful for local debugging).

### Requesting New Scripts

When agents can't find a script for what they need, they can file a request:

```bash
boxctl request "Check Redis replication lag" \
  --searched "redis replication, redis lag" \
  --context "Debugging slow API responses, suspected replica drift"
```

This creates a GitHub/GitLab issue with the `script-request` label.

**Platform detection** (in order):
1. `.boxctl.yaml` in repo (`issue_platform: github` or `gitlab`)
2. `~/.config/boxctl/config.yaml` (user default)
3. Auto-detect from git remote URL

**Requirements:** `gh` CLI (GitHub) or `glab` CLI (GitLab)

## Exit Code Convention

All scripts follow consistent exit codes for programmatic decision-making:

| Code | Meaning | Agent Action |
|------|---------|--------------|
| 0 | Healthy / no issues | Move to next investigation area |
| 1 | Issues detected | Dig deeper with related scripts |
| 2 | Missing dependency or usage error | Try alternative approach |

## Output Formats

**json** (recommended for agents):
```json
{
  "status": "warning",
  "data": { ... },
  "summary": "2 issues found"
}
```

**plain** (human-readable):
```
Disk /dev/sda: HEALTHY
  Temperature: 32C
  Power-on hours: 12,345
```

**table** (terminal display):
```
DISK       STATUS   TEMP   HOURS
/dev/sda   HEALTHY  32C    12,345
```

## Installation

```bash
# Clone and install
git clone https://github.com/signalnine/boxctl.git
cd boxctl
pip install -e .

# Verify installation
boxctl doctor
```

## Claude Code Integration

boxctl includes Claude Skills for AI-assisted troubleshooting:

```bash
# Install skills
cp -r skills/* ~/.claude/skills/
```

Skills available:
- `boxctl-discovery` - Auto-suggests scripts based on symptoms
- `baremetal-troubleshooting` - Guided investigation with step tracking
- `k8s-troubleshooting` - Graph-based Kubernetes investigation

## Architecture

boxctl is designed for testability and agent integration:

- **Context abstraction**: All system access goes through a `Context` class that can be mocked
- **Output helper**: Scripts use `Output` class for consistent structured data; redaction is applied at render time
- **Metadata-driven**: YAML frontmatter in each script defines category, tags, requirements
- **Remote and MCP surfaces** reuse the same discovered scripts and metadata
- **2867 unit tests**: Full coverage without requiring real hardware, clusters, or SSH

## Required Tools

Scripts check for dependencies and exit with code 2 if missing:

| Category | Tools |
|----------|-------|
| Disk | smartctl, nvme, lsblk, btrfs, zpool |
| Network | ss, ip, ethtool, iptables |
| Hardware | ipmitool, sensors, dmidecode |
| Kubernetes | kubectl |
| Security | auditctl, openssl |

Run `boxctl doctor` to check tool availability.

## Requirements

- Python 3.11+
- For remote execution: `ssh` on the client, `python3` on the target host
- For `source prepare`: passwordless sudo for the connecting admin user
- Other tools vary by script (graceful degradation with exit code 2)

## License

MIT
