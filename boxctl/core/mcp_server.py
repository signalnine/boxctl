"""MCP server exposing boxctl as tools over stdio.

Usable by Claude Code / Cursor / Windsurf via the Model Context Protocol.
Four tools: list_scripts, search_scripts, show_script, run_script.

The plain-python ``*_tool`` functions are the primary surface; ``create_server``
wires them into a ``FastMCP`` instance so the same logic is used for both
direct calls and MCP tool dispatch.
"""

from __future__ import annotations

from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

import asyncio
import os

from boxctl.core import needs_privilege
from boxctl.core.discovery import discover_scripts
from boxctl.core.redact import redact_value
from boxctl.core.runner import run_script


def _find(scripts_dir: Path, name: str):
    scripts = discover_scripts(scripts_dir)
    target = name.removesuffix(".py")
    for s in scripts:
        if s.name == name or s.name.removesuffix(".py") == target:
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
    redact: bool = True,
) -> dict[str, Any]:
    """Execute a script and return captured stdout/stderr/exit-code.

    Secrets in stdout/stderr are redacted by default. Callers can pass
    ``redact=False`` to get raw output; the env var ``BOXCTL_NO_REDACT=1``
    also disables redaction (matching the CLI behavior).
    """
    s = _find(scripts_dir, name)
    if s is None:
        return {"error": f"not found: {name}"}
    result = run_script(
        s.path,
        args=args or [],
        timeout=timeout,
        use_sudo=needs_privilege(s.path),
    )
    if os.environ.get("BOXCTL_NO_REDACT") == "1":
        redact = False
    stdout = redact_value(result.stdout) if redact else result.stdout
    stderr = redact_value(result.stderr) if redact else result.stderr
    # Timeout maps to exit 2 so agents see the same sentinel the CLI emits.
    exit_code = result.returncode if result.returncode is not None else 2
    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
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
        description=(
            "Run a boxctl script and return its exit code, stdout, and stderr. "
            "Secrets in output are redacted by default; pass redact=False to disable."
        ),
    )
    def run_script_tool_wrapper(
        name: str,
        args: list[str] | None = None,
        timeout: int = 60,
        redact: bool = True,
    ) -> dict[str, Any]:
        return run_script_tool(scripts_dir, name, args=args, timeout=timeout, redact=redact)

    return server


@asynccontextmanager
async def _stdio_transport():
    """Asyncio stdio transport that avoids AnyIO's thread-backed file wrapper."""
    import anyio
    import mcp.types as types
    from mcp.shared.message import SessionMessage

    read_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_reader = anyio.create_memory_object_stream(0)

    loop = asyncio.get_running_loop()
    stdin_fd = 0
    stdout_fd = 1
    stdin_was_blocking = os.get_blocking(stdin_fd)
    buffer = bytearray()
    inbound: asyncio.Queue[Any] = asyncio.Queue()
    eof = object()
    reader_active = True

    def _send_line(line: bytes) -> None:
        try:
            text = line.decode("utf-8")
            message = types.JSONRPCMessage.model_validate_json(text)
        except Exception as exc:  # pragma: no cover - malformed client input
            inbound.put_nowait(exc)
        else:
            inbound.put_nowait(SessionMessage(message))

    def _close_reader() -> None:
        nonlocal reader_active
        if not reader_active:
            return
        reader_active = False
        with suppress(Exception):
            loop.remove_reader(stdin_fd)
        if buffer:
            _send_line(bytes(buffer))
            buffer.clear()
        inbound.put_nowait(eof)

    def _read_ready() -> None:
        while True:
            try:
                chunk = os.read(stdin_fd, 65536)
            except BlockingIOError:
                return
            except OSError as exc:
                inbound.put_nowait(exc)
                _close_reader()
                return

            if not chunk:
                _close_reader()
                return

            buffer.extend(chunk)
            while True:
                try:
                    newline = buffer.index(10)
                except ValueError:
                    break
                line = bytes(buffer[:newline]).removesuffix(b"\r")
                del buffer[: newline + 1]
                _send_line(line)

    async def _stdin_forwarder() -> None:
        async with read_writer:
            while True:
                item = await inbound.get()
                if item is eof:
                    return
                await read_writer.send(item)

    async def _write_all(data: bytes) -> None:
        view = memoryview(data)
        while view:
            try:
                written = os.write(stdout_fd, view)
            except BlockingIOError:  # pragma: no cover - pipe backpressure
                await asyncio.sleep(0.01)
                continue
            view = view[written:]

    async def _stdout_writer() -> None:
        async with write_reader:
            async for session_message in write_reader:
                payload = session_message.message.model_dump_json(
                    by_alias=True,
                    exclude_none=True,
                )
                await _write_all((payload + "\n").encode("utf-8"))

    os.set_blocking(stdin_fd, False)
    loop.add_reader(stdin_fd, _read_ready)
    reader_task = loop.create_task(_stdin_forwarder())
    writer_task = loop.create_task(_stdout_writer())

    try:
        yield read_stream, write_stream
    finally:
        _close_reader()
        await write_stream.aclose()
        reader_task.cancel()
        writer_task.cancel()
        with suppress(asyncio.CancelledError):
            await reader_task
        with suppress(asyncio.CancelledError):
            await writer_task
        os.set_blocking(stdin_fd, stdin_was_blocking)


def serve_stdio(scripts_dir: Path) -> None:
    """Run the MCP server on stdio until the client disconnects."""
    import anyio

    server = create_server(scripts_dir)

    async def _run() -> None:
        async with _stdio_transport() as (read_stream, write_stream):
            await server._mcp_server.run(
                read_stream,
                write_stream,
                server._mcp_server.create_initialization_options(),
            )

    anyio.run(_run)
