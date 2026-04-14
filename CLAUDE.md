# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

`boxctl` is a unified CLI wrapping ~315 diagnostic scripts for baremetal (216) and Kubernetes (93) systems, designed for LLM agents to investigate infrastructure issues. Scripts are self-describing via YAML-in-comment metadata, emit structured JSON, and use semantic exit codes.

## Commands

```bash
# Environment setup
make setup                      # runs scripts/setup-dev.sh (pip install -e .[dev])

# Testing (unit, excludes tests/integration)
make test
make test-cov                   # with coverage, fails under 80%
make test-verbose

# Integration tests (slower, may shell out)
make test-integration
make test-all                   # unit + integration

# Single test
python3 -m pytest tests/scripts/baremetal/test_loadavg_analyzer.py -v
python3 -m pytest tests/ -k "disk_health" -v

# Build / install
make build                      # scripts/build.sh -> dist/ tarball
make install                    # installs to /opt/boxctl, symlinks /usr/local/bin/boxctl

# Run the CLI during dev (no install needed after `make setup`)
boxctl list                     # list all discovered scripts
boxctl search "high load"       # find by keyword/tag
boxctl show loadavg_analyzer    # show metadata + related
boxctl run loadavg_analyzer --format json
boxctl lint scripts/baremetal/foo.py
```

## Exit Code Convention

All scripts follow:
- **0** = healthy / no issues
- **1** = issues found (warnings, errors, thresholds exceeded)
- **2** = usage error, missing dependency, or tool unavailable

Agents use these to drive investigation: exit 1 means dig deeper with `related` scripts.

## Architecture

### Two layers: framework (`boxctl/`) and scripts (`scripts/`)

**Framework** (`boxctl/` package):
- `boxctl/cli.py` - argparse entry, subcommands: `list`, `search`, `show`, `run`, `lint`, `doctor`
- `boxctl/core/discovery.py` - `Script` dataclass, walks `scripts/` tree, parses metadata
- `boxctl/core/metadata.py` - parses YAML embedded in top-of-file `# boxctl:` comment block
- `boxctl/core/runner.py` - invokes a script's `run(args, output, context)` entrypoint
- `boxctl/core/context.py` - `Context` class wraps filesystem/subprocess for DI (tests use `MockContext`)
- `boxctl/core/output.py` - `Output` class: scripts call `output.emit(key, value)` then framework calls `output.render(format)`. Supports plain/json; table handled by scripts when needed.
- `boxctl/core/linter.py` - validates script metadata and structure
- `boxctl/core/profiles.py`, `config.py` - config resolution, issue-to-script mapping

**Scripts** (`scripts/baremetal/*.py`, `scripts/k8s/*.py`):
Every script has the shape:
```python
#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [load, cpu]
#   requires: []                 # external tools (smartctl, kubectl, ...)
#   privilege: user              # or: root
#   related: [cpu_pressure_monitor, run_queue_monitor]
#   brief: One-line description

from boxctl.core.context import Context
from boxctl.core.output import Output

def run(args, output: Output, context: Context) -> int:
    ...
    output.emit("key", value)
    return 0
```
The framework discovers the script, parses metadata, constructs `Output` + `Context`, calls `run()`, then renders output.

### Testing Philosophy

- Tests live in `tests/` mirroring the source tree (`tests/scripts/baremetal/`, `tests/core/`).
- `tests/conftest.py` provides `MockContext` with a `file_contents` dict and command mocking.
- Tests must NOT require real hardware tools, AWS credentials, `kubectl` access, or network.
- Prefer asserting on `output.data` (the dict emitted) rather than stdout text.
- `Output._printed` guard prevents double-render; **do not reuse a single `Output` across multiple `run()` calls** in a test.
- `_render_plain()` title-cases keys: `total_events` renders as `Total Events`.

### Common Flags

Scripts generally accept: `--format {plain,json,table}`, `-v/--verbose`, `-w/--warn-only`. Destructive ops (rare in boxctl) use `--force` + `--dry-run`.

## Critical Rules

1. **Backward compatibility is sacred** - default output format and CLI flags must not change; scripts are consumed by agents parsing output.
2. **Script metadata must lint clean** - `boxctl lint <path>` before committing new/edited scripts; `related` entries must refer to real scripts.
3. **Every script gets a test** - `scripts/baremetal/foo.py` -> `tests/scripts/baremetal/test_foo.py`, using `MockContext`.
4. **Check tools before using them** - exit 2 with stderr message if a required binary is missing (`context.check_tool("smartctl")`).
5. **Errors to stderr** - `print(..., file=sys.stderr)`; structured data goes through `output.emit()`.
6. **Minimal deps** - stdlib + `pyyaml`. No adding runtime deps without strong justification.
