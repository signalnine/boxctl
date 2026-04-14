"""Command-line interface for boxctl."""

import argparse
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from boxctl import __version__
from boxctl.core import discover_scripts, filter_scripts, run_script, needs_privilege
from boxctl.core.config import resolve_issue_platform


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="boxctl",
        description="Unified CLI for baremetal and Kubernetes utility scripts",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"boxctl {__version__}",
    )
    parser.add_argument(
        "--scripts-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory containing scripts (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable automatic secret redaction in script output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list command
    list_parser = subparsers.add_parser("list", help="List available scripts")
    list_parser.add_argument(
        "--category",
        "-c",
        help="Filter by category (e.g., baremetal/disk)",
    )
    list_parser.add_argument(
        "--tag",
        "-t",
        action="append",
        dest="tags",
        help="Filter by tag (can be specified multiple times)",
    )

    # run command
    run_parser = subparsers.add_parser("run", help="Run a script")
    run_parser.add_argument("script", help="Script name to run")
    run_parser.add_argument(
        "args",
        nargs="*",
        help="Arguments to pass to the script",
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in seconds (default: 60)",
    )
    run_parser.add_argument(
        "--sudo",
        action="store_true",
        help="Run with sudo (auto-enabled for privileged scripts)",
    )

    # show command
    show_parser = subparsers.add_parser("show", help="Show script details")
    show_parser.add_argument("script", help="Script name to show")

    # search command
    search_parser = subparsers.add_parser("search", help="Search scripts")
    search_parser.add_argument("query", help="Search query")

    # doctor command
    subparsers.add_parser("doctor", help="Check system health and tool availability")

    # lint command
    lint_parser = subparsers.add_parser("lint", help="Validate script metadata headers")
    lint_parser.add_argument(
        "scripts",
        nargs="*",
        help="Specific scripts to lint (default: all)",
    )

    # mcp command
    subparsers.add_parser(
        "mcp",
        help="Run boxctl as an MCP (Model Context Protocol) server over stdio",
    )

    # request command
    request_parser = subparsers.add_parser(
        "request",
        help="Request a new script capability (files GitHub/GitLab issue)"
    )
    request_parser.add_argument(
        "capability",
        help="Description of the needed capability",
    )
    request_parser.add_argument(
        "--searched",
        help="Search terms tried (comma-separated)",
    )
    request_parser.add_argument(
        "--context",
        help="Investigation context that led to this request",
    )

    return parser


def cmd_list(args: argparse.Namespace) -> int:
    """List available scripts."""
    scripts = discover_scripts(args.scripts_dir)
    scripts = filter_scripts(scripts, category=args.category, tags=args.tags)

    if not scripts:
        print("No scripts found.")
        return 0

    for script in sorted(scripts, key=lambda s: s.name):
        if args.format == "json":
            import json
            print(json.dumps({
                "name": script.name,
                "category": script.category,
                "tags": script.tags,
                "brief": script.brief,
            }))
        else:
            print(f"{script.name:30} {script.brief}")

    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run a script."""
    scripts = discover_scripts(args.scripts_dir)
    matches = [s for s in scripts if s.name == args.script or s.name == f"{args.script}.py"]

    if not matches:
        print(f"Script not found: {args.script}", file=sys.stderr)
        return 2

    script = matches[0]
    use_sudo = args.sudo or needs_privilege(script.path)

    result = run_script(
        script.path,
        args=args.args,
        timeout=args.timeout,
        use_sudo=use_sudo,
    )

    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")

    if result.timed_out:
        print("Script timed out", file=sys.stderr)
        return 1

    return result.returncode or 0


def cmd_show(args: argparse.Namespace) -> int:
    """Show script details."""
    scripts = discover_scripts(args.scripts_dir)
    matches = [s for s in scripts if s.name == args.script or s.name == f"{args.script}.py"]

    if not matches:
        print(f"Script not found: {args.script}", file=sys.stderr)
        return 2

    script = matches[0]

    if args.format == "json":
        import json
        print(json.dumps({
            "name": script.name,
            "path": str(script.path),
            "category": script.category,
            "tags": script.tags,
            "brief": script.brief,
            "requires": script.requires,
            "privilege": script.privilege,
            "related": script.related,
        }, indent=2))
    else:
        print(f"Name:     {script.name}")
        print(f"Path:     {script.path}")
        print(f"Category: {script.category}")
        print(f"Tags:     {', '.join(script.tags)}")
        print(f"Brief:    {script.brief}")
        if script.requires:
            print(f"Requires: {', '.join(script.requires)}")
        if script.privilege:
            print(f"Privilege: {script.privilege}")
        if script.related:
            print(f"Related:  {', '.join(script.related)}")

    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Search scripts."""
    scripts = discover_scripts(args.scripts_dir)
    query = args.query.lower()

    matches = [
        s for s in scripts
        if query in s.name.lower()
        or query in s.brief.lower()
        or any(query in tag.lower() for tag in s.tags)
        or query in s.category.lower()
    ]

    if not matches:
        print(f"No scripts matching: {args.query}")
        return 0

    for script in sorted(matches, key=lambda s: s.name):
        if args.format == "json":
            import json
            print(json.dumps({
                "name": script.name,
                "category": script.category,
                "brief": script.brief,
            }))
        else:
            print(f"{script.name:30} {script.brief}")

    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    """Validate script metadata headers."""
    from boxctl.core.linter import lint_script, lint_all, LintResult

    if args.scripts:
        # Lint specific scripts
        results = []
        for script_name in args.scripts:
            path = args.scripts_dir / script_name
            if not path.suffix:
                path = path.with_suffix(".py")
            if path.exists():
                results.append(lint_script(path))
            else:
                results.append(LintResult(path=path, errors=[f"File not found: {path}"]))
    else:
        # Lint all scripts
        results = lint_all(args.scripts_dir)

    total_errors = 0
    total_warnings = 0

    if args.format == "json":
        import json
        output = []
        for result in results:
            output.append({
                "path": str(result.path),
                "ok": result.ok,
                "errors": result.errors,
                "warnings": result.warnings,
            })
            total_errors += len(result.errors)
            total_warnings += len(result.warnings)
        print(json.dumps({"results": output, "errors": total_errors, "warnings": total_warnings}, indent=2))
    else:
        for result in results:
            total_errors += len(result.errors)
            total_warnings += len(result.warnings)

            if result.errors or result.warnings:
                print(f"\n{result.path}:")
                for error in result.errors:
                    print(f"  ✗ ERROR: {error}")
                for warning in result.warnings:
                    print(f"  ⚠ WARNING: {warning}")

        print(f"\nLinted {len(results)} file(s): {total_errors} error(s), {total_warnings} warning(s)")

    return 1 if total_errors > 0 else 0


def cmd_request(args: argparse.Namespace) -> int:
    """Request a new script capability by filing a GitHub/GitLab issue."""
    # Determine platform
    platform = resolve_issue_platform()

    if not platform:
        print("Error: Could not determine issue platform.", file=sys.stderr)
        print("Options:", file=sys.stderr)
        print("  1. Set 'issue_platform: github' in .boxctl.yaml", file=sys.stderr)
        print("  2. Set 'issue_platform: gitlab' in ~/.config/boxctl/config.yaml", file=sys.stderr)
        print("  3. Ensure git remote points to github.com or gitlab.com", file=sys.stderr)
        return 2

    # Check for CLI tool
    cli_tool = 'gh' if platform == 'github' else 'glab'
    if not shutil.which(cli_tool):
        print(f"Error: {cli_tool} CLI not found.", file=sys.stderr)
        print(f"Install it to file {platform.title()} issues.", file=sys.stderr)
        return 2

    # Build issue body
    body_lines = [
        "## Requested Capability",
        args.capability,
        "",
    ]

    if args.searched:
        body_lines.extend([
            "## Searches Tried",
            args.searched,
            "",
        ])

    if args.context:
        body_lines.extend([
            "## Investigation Context",
            args.context,
            "",
        ])

    body_lines.extend([
        "---",
        "*Filed by LLM agent via `boxctl request`*",
    ])

    body = "\n".join(body_lines)
    title = f"Script request: {args.capability}"

    # Create issue
    if platform == 'github':
        cmd = ['gh', 'issue', 'create', '--title', title, '--body', body, '--label', 'script-request']
    else:
        cmd = ['glab', 'issue', 'create', '--title', title, '--description', body, '--label', 'script-request']

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout, end="")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"Error creating issue: {e.stderr}", file=sys.stderr)
        return 1


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check system health and tool availability."""
    scripts = discover_scripts(args.scripts_dir)

    # Collect all required tools
    all_tools: set[str] = set()
    tools_by_script: dict[str, list[str]] = {}
    for script in scripts:
        if script.requires:
            all_tools.update(script.requires)
            tools_by_script[script.name] = script.requires

    # Check tool availability
    tool_status = {}
    for tool in sorted(all_tools):
        tool_status[tool] = shutil.which(tool) is not None

    # Count scripts by category
    category_counts: dict[str, int] = defaultdict(int)
    for script in scripts:
        category_counts[script.category] += 1

    # Count privileged scripts
    privileged_count = sum(1 for s in scripts if s.privilege == "root")

    # Check for missing tools
    missing_tools = [t for t, available in tool_status.items() if not available]

    if args.format == "json":
        import json
        print(json.dumps({
            "scripts_total": len(scripts),
            "scripts_by_category": dict(category_counts),
            "privileged_scripts": privileged_count,
            "tools": tool_status,
            "missing_tools": missing_tools,
        }, indent=2))
    else:
        print("=== boxctl doctor ===\n")

        print(f"Scripts: {len(scripts)} total")
        for category in sorted(category_counts.keys()):
            print(f"  {category}: {category_counts[category]}")
        print()

        print(f"Privileged scripts (require root): {privileged_count}")
        print()

        if all_tools:
            print("Required tools:")
            for tool in sorted(all_tools):
                status = "✓" if tool_status[tool] else "✗ MISSING"
                print(f"  {tool}: {status}")
            print()

        if missing_tools:
            print(f"⚠ {len(missing_tools)} missing tool(s): {', '.join(missing_tools)}")
        else:
            print("✓ All required tools available")

    return 1 if missing_tools else 0


def cmd_mcp(args: argparse.Namespace) -> int:
    """Run boxctl as an MCP server on stdio."""
    from boxctl.core.mcp_server import serve_stdio

    serve_stdio(args.scripts_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if getattr(args, "no_redact", False):
        os.environ["BOXCTL_NO_REDACT"] = "1"

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "list": cmd_list,
        "run": cmd_run,
        "show": cmd_show,
        "search": cmd_search,
        "doctor": cmd_doctor,
        "lint": cmd_lint,
        "request": cmd_request,
        "mcp": cmd_mcp,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
