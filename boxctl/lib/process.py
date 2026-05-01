"""Process utilities for scripts."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxctl.core.context import Context


class CommandError(Exception):
    """Error running a command."""

    pass


def run_command(
    cmd: list[str],
    context: "Context | None" = None,
    check: bool = False,
) -> str:
    """
    Run a command and return its output.

    Args:
        cmd: Command and arguments
        context: Execution context (for testing)
        check: Raise on non-zero exit

    Returns:
        Command stdout

    Raises:
        CommandError: If check=True and command fails
    """
    if context is None:
        from boxctl.core.context import Context
        context = Context()

    try:
        result = context.run(cmd, check=check)
        return result.stdout
    except Exception as e:
        if check:
            raise CommandError(f"Command failed: {cmd}") from e
        return ""


def check_tool(
    name: str,
    context: "Context | None" = None,
    required: bool = False,
) -> bool:
    """
    Check if a tool exists in PATH.

    Args:
        name: Tool name to check
        context: Execution context (for testing)
        required: Raise if tool is missing

    Returns:
        True if tool exists

    Raises:
        CommandError: If required=True and tool is missing
    """
    if context is None:
        from boxctl.core.context import Context
        context = Context()

    exists = context.check_tool(name)

    if required and not exists:
        raise CommandError(f"Required tool not found: {name}")

    return exists
