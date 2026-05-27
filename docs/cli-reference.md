# CLI Reference

Complete reference for all boxctl commands.

## Global Options

These options apply to all commands:

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--scripts-dir PATH` | Directory containing scripts (default: `$BOXCTL_SCRIPTS_DIR` or current directory) |
| `--format {plain,json}` | Output format (default: plain) |

## Commands

### list

List available scripts with optional filtering.

```
boxctl list [OPTIONS]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--category CATEGORY` | `-c` | Filter by category (e.g., `baremetal/disk`, `k8s/pods`) |
| `--tag TAG` | `-t` | Filter by tag (can be specified multiple times) |

**Examples:**

```bash
# List all scripts
boxctl list

# List scripts in a category
boxctl list -c baremetal/disk
boxctl list --category k8s/nodes

# List scripts with specific tags
boxctl list -t health
boxctl list -t network -t monitoring

# Combine category and tag filters
boxctl list -c baremetal -t security

# JSON output (one object per line)
boxctl list --format json
```

**Output (plain):**
```
disk_health                    Check disk health using SMART attributes
disk_space_forecaster          Predict disk space exhaustion
disk_io_latency_monitor        Monitor disk I/O latency
```

**Output (json):**
```json
{"name": "disk_health", "category": "baremetal/disk", "tags": ["health", "smart", "storage"], "brief": "Check disk health using SMART attributes"}
```

---

### run

Execute a script by name.

```
boxctl run SCRIPT [OPTIONS] [-- SCRIPT_ARGS...]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `SCRIPT` | Script name (with or without `.py` extension) |
| `SCRIPT_ARGS` | Arguments passed to the script (after `--`) |

**Options:**

| Option | Description |
|--------|-------------|
| `--timeout SECONDS` | Timeout in seconds (default: 60) |
| `--sudo` | Run with sudo (auto-enabled for privileged scripts) |

Scripts marked `privilege: root` auto-run through `sudo`. The MCP `run_script`
tool uses the same behavior, so only expose the MCP server to trusted clients.

**Examples:**

```bash
# Run a script
boxctl run disk_health

# Pass arguments to the script
boxctl run disk_health -- --device /dev/sda --verbose

# Run with longer timeout
boxctl run slow_analysis --timeout 300

# Force sudo even if not marked privileged
boxctl run custom_check --sudo

# JSON output (if script supports it)
boxctl run disk_health -- --format json
```

**Exit Codes:**

The command returns the script's exit code:
- `0` - Script succeeded / healthy
- `1` - Script found issues / warnings
- `2` - Script error or not found

---

### show

Display detailed metadata for a script.

```
boxctl show SCRIPT
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `SCRIPT` | Script name to show details for |

**Examples:**

```bash
# Show script details
boxctl show disk_health

# JSON output
boxctl show disk_health --format json
```

**Output (plain):**
```
Name:     disk_health
Path:     /path/to/scripts/baremetal/disk_health.py
Category: baremetal/disk
Tags:     health, smart, storage, hardware
Brief:    Check disk health using SMART attributes
Requires: smartctl
Privilege: root
Related:  disk_space_forecaster, disk_life_predictor
```

**Output (json):**
```json
{
  "name": "disk_health",
  "path": "/path/to/scripts/baremetal/disk_health.py",
  "category": "baremetal/disk",
  "tags": ["health", "smart", "storage", "hardware"],
  "brief": "Check disk health using SMART attributes",
  "requires": ["smartctl"],
  "privilege": "root",
  "related": ["disk_space_forecaster", "disk_life_predictor"]
}
```

---

### search

Find scripts by keyword in name, tags, description, or category.

```
boxctl search QUERY
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `QUERY` | Search term (case-insensitive) |

**Examples:**

```bash
# Search by topic
boxctl search disk
boxctl search kubernetes
boxctl search memory

# Search for specific functionality
boxctl search "pending pod"
boxctl search fragmentation

# JSON output
boxctl search network --format json
```

**Search Scope:**

The query matches against:
- Script name
- Brief description
- Tags
- Category path

---

### doctor

Check system health and tool availability for scripts.

```
boxctl doctor
```

**Examples:**

```bash
# Run health check
boxctl doctor

# JSON output
boxctl doctor --format json
```

**Output (plain):**
```
=== boxctl doctor ===

Scripts: 181 total
  baremetal/disk: 15
  baremetal/memory: 12
  baremetal/network: 18
  k8s/pods: 14
  ...

Privileged scripts (require root): 45

Required tools:
  kubectl: ✓
  smartctl: ✓
  mdadm: ✗ MISSING
  nvme: ✓

⚠ 1 missing tool(s): mdadm
```

**Output (json):**
```json
{
  "scripts_total": 181,
  "scripts_by_category": {
    "baremetal/disk": 15,
    "baremetal/memory": 12
  },
  "privileged_scripts": 45,
  "tools": {
    "kubectl": true,
    "smartctl": true,
    "mdadm": false
  },
  "missing_tools": ["mdadm"]
}
```

**Exit Codes:**
- `0` - All required tools available
- `1` - Some tools missing

---

### lint

Validate script metadata headers.

```
boxctl lint [SCRIPTS...]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `SCRIPTS` | Specific scripts to lint (default: all) |

**Examples:**

```bash
# Lint all scripts
boxctl lint

# Lint specific scripts
boxctl lint disk_health memory_pressure

# JSON output
boxctl lint --format json
```

**Output (plain):**
```
/path/to/script.py:
  ✗ ERROR: Missing required field: category
  ⚠ WARNING: No tags specified

Linted 181 file(s): 1 error(s), 1 warning(s)
```

**Output (json):**
```json
{
  "results": [
    {
      "path": "/path/to/script.py",
      "ok": false,
      "errors": ["Missing required field: category"],
      "warnings": ["No tags specified"]
    }
  ],
  "errors": 1,
  "warnings": 1
}
```

**Exit Codes:**
- `0` - No errors (warnings allowed)
- `1` - Errors found

---

## Exit Code Summary

| Code | Meaning |
|------|---------|
| 0 | Success / healthy / no issues |
| 1 | Warnings or issues found |
| 2 | Usage error or script not found |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `BOXCTL_SCRIPTS_DIR` | Default scripts directory (alternative to `--scripts-dir`) |

## See Also

- [Writing Scripts](writing-scripts.md) - Guide for creating new scripts
- [Architecture](architecture.md) - System design overview
