"""MCP server exposing boxctl as tools over stdio.

Usable by Claude Code / Cursor / Windsurf via the Model Context Protocol.
Four tools: list_scripts, search_scripts, show_script, run_script.

The plain-python ``*_tool`` functions are the primary surface; ``create_server``
wires them into a ``FastMCP`` instance so the same logic is used for both
direct calls and MCP tool dispatch.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from boxctl.core import needs_privilege
from boxctl.core.discovery import discover_scripts
from boxctl.core.runner import run_script


def _find(scripts_dir: Path, name: str):
    scripts = discover_scripts(scripts_dir)
    for s in scripts:
        if s.name == name or s.name == f"{name}.py" or s.name[:-3] == name:
            return s
    return None


def list_scripts_tool(
    scripts_dir: Path,
    category: str | None = None,
    tag: str | None = None,
) -> list[dict[str, Any]]:
    """Enumerate scripts, optionally filtered by category prefix or tag."""
    scripts = discover_scripts(scripts_dir)
    out = []
    for s in sorted(scripts, key=lambda x: x.name):
        if category and not s.category.startswith(category):
            continue
        if tag and tag not in s.tags:
            continue
        out.append(
            {
                "name": s.name,
                "category": s.category,
                "brief": s.brief,
                "tags": list(s.tags),
            }
        )
    return out


def search_scripts_tool(scripts_dir: Path, query: str) -> list[dict[str, Any]]:
    """Case-insensitive substring match on name/brief/tag/category."""
    q = query.lower()
    scripts = discover_scripts(scripts_dir)
    out = []
    for s in sorted(scripts, key=lambda x: x.name):
        if (
            q in s.name.lower()
            or q in s.brief.lower()
            or q in s.category.lower()
            or any(q in t.lower() for t in s.tags)
        ):
            out.append({"name": s.name, "category": s.category, "brief": s.brief})
    return out


def show_script_tool(scripts_dir: Path, name: str) -> dict[str, Any]:
    """Return full metadata for a script, or an error dict if not found."""
    s = _find(scripts_dir, name)
    if s is None:
        return {"error": f"not found: {name}"}
    return {
        "name": s.name,
        "path": str(s.path),
        "category": s.category,
        "tags": list(s.tags),
        "brief": s.brief,
        "requires": list(s.requires or []),
        "privilege": s.privilege,
        "related": list(s.related or []),
    }


def run_script_tool(
    scripts_dir: Path,
    name: str,
    args: list[str] | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Execute a script and return captured stdout/stderr/exit-code."""
    s = _find(scripts_dir, name)
    if s is None:
        return {"error": f"not found: {name}"}
    result = run_script(
        s.path,
        args=args or [],
        timeout=timeout,
        use_sudo=needs_privilege(s.path),
    )
    return {
        "exit_code": result.returncode if result.returncode is not None else -1,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
    }


def create_server(scripts_dir: Path):
    """Build a FastMCP server with the four boxctl tools registered."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("boxctl")

    @server.tool(description="List boxctl scripts, optionally filtered by category prefix or tag.")
    def list_scripts(category: str | None = None, tag: str | None = None) -> list[dict[str, Any]]:
        return list_scripts_tool(scripts_dir, category=category, tag=tag)

    @server.tool(description="Search scripts by substring across name, brief, tags, and category.")
    def search_scripts(query: str) -> list[dict[str, Any]]:
        return search_scripts_tool(scripts_dir, query)

    @server.tool(description="Show full metadata for a named script (category, tags, brief, requires, related).")
    def show_script(name: str) -> dict[str, Any]:
        return show_script_tool(scripts_dir, name)

    @server.tool(
        name="run_script",
        description="Run a boxctl script and return its exit code, stdout, and stderr.",
    )
    def run_script_tool_wrapper(
        name: str, args: list[str] | None = None, timeout: int = 60
    ) -> dict[str, Any]:
        return run_script_tool(scripts_dir, name, args=args, timeout=timeout)

    return server


def serve_stdio(scripts_dir: Path) -> None:
    """Run the MCP server on stdio until the client disconnects."""
    server = create_server(scripts_dir)
    server.run("stdio")
