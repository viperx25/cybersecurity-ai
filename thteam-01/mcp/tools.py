"""
Threat Hunting MCP Server
Exposes two tools to a security analyst agent via streamable HTTP:
  - list_log_files : ls on the logs directory
  - run_command    : run awk/sed/cat/grep/head/tail against log files
"""

import logging
import os
import re
import shlex
import subprocess
from pathlib import Path

from fastmcp import FastMCP

logging.basicConfig(
    level=logging.INFO,
    format="[MCP] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

LOGS_DIR = (Path(__file__).parent.parent / "logs").resolve()

ALLOWED_COMMANDS = {"awk", "sed", "cat", "grep", "head", "tail"}

# Matches simple absolute paths: starts with / and contains only path-safe
# characters (no spaces, no regex metacharacters).  Used to block attempts
# like "cat /etc/passwd" while allowing awk programs such as '/FAILED/{print}'.
_ABS_PATH_RE = re.compile(r"^/[a-zA-Z0-9_./ -]+$")

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="Threat Hunting Tools",
    instructions=(
        "Tools for a security analyst threat-hunting agent. "
        "All file operations are restricted to the logs directory."
    ),
)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def list_log_files() -> str:
    """List all files in the logs directory."""
    log.info("list_log_files()")
    result = subprocess.run(
        ["ls", "-lh", str(LOGS_DIR)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return f"Error listing logs directory: {result.stderr.strip()}"
    return result.stdout


@mcp.tool()
def run_command(command: str) -> str:
    """Run a shell command against files in the logs directory.

    Permitted commands: awk, sed, cat, grep, head, tail.
    File paths must be relative — absolute paths and path traversal (../)
    are not allowed.  The working directory is fixed to the logs directory.

    Examples:
        grep "FAILED" conn.log
        tail -n 100 weird.log
        awk '{print $1, $4}' http.log
        sed -n '1,50p' reporter.log
        cat files.log | head -20
    """
    # --- parse -----------------------------------------------------------
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return f"Error: could not parse command — {exc}"

    if not tokens:
        return "Error: empty command."

    # --- validate command name ------------------------------------------
    # Accept bare names ("grep") or full paths ("/usr/bin/grep"); always
    # run the bare name so we can't be tricked into running something else.
    cmd_name = os.path.basename(tokens[0])
    if cmd_name not in ALLOWED_COMMANDS:
        allowed = ", ".join(sorted(ALLOWED_COMMANDS))
        return f"Error: '{cmd_name}' is not permitted. Allowed commands: {allowed}."

    tokens[0] = cmd_name  # normalise to bare name

    # --- validate arguments --------------------------------------------
    for arg in tokens[1:]:
        # Block path traversal in any form
        if ".." in arg:
            return f"Error: path traversal detected in argument '{arg}'."

        # Block simple absolute filesystem paths while preserving awk/sed
        # regex patterns that may start with /.
        if _ABS_PATH_RE.match(arg):
            return (
                f"Error: absolute path '{arg}' is not allowed. "
                "Use filenames relative to the logs directory."
            )

    # --- execute ---------------------------------------------------------
    log.info("run_command(%s)", " ".join(tokens))
    try:
        result = subprocess.run(
            tokens,
            cwd=str(LOGS_DIR),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return f"Error: command '{cmd_name}' was not found on this system."
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 30 seconds."

    output = result.stdout
    if result.returncode != 0 and result.stderr:
        stderr = result.stderr.strip()
        output = (output + f"\n[stderr]: {stderr}").strip()

    return output or "(no output)"


@mcp.tool()
def run_commands(commands: list[str]) -> str:
    """Run multiple shell commands in one call and return all output.

    Accepts a list of up to 10 commands. Each command follows the same rules
    as run_command (permitted: awk, sed, cat, grep, head, tail; relative paths
    only; no path traversal). Results are returned with a header per command.

    Example:
        ["head -5 conn.log", "grep FAILED conn.log", "awk '{print $3}' dns.log | sort | uniq -c | sort -rn | head -20"]
    """
    if not commands:
        return "Error: empty command list."
    if len(commands) > 10:
        return "Error: maximum 10 commands per batch."

    log.info("run_commands(%d commands)", len(commands))
    parts = []
    for raw in commands:
        # --- parse ---
        try:
            tokens = shlex.split(raw)
        except ValueError as exc:
            parts.append(f">>> {raw}\nError: could not parse — {exc}")
            continue

        if not tokens:
            parts.append(f">>> {raw}\nError: empty command.")
            continue

        cmd_name = os.path.basename(tokens[0])
        if cmd_name not in ALLOWED_COMMANDS:
            allowed = ", ".join(sorted(ALLOWED_COMMANDS))
            parts.append(f">>> {raw}\nError: '{cmd_name}' not permitted. Allowed: {allowed}.")
            continue

        tokens[0] = cmd_name

        # --- validate args ---
        error = None
        for arg in tokens[1:]:
            if ".." in arg:
                error = f"Error: path traversal in '{arg}'."
                break
            if _ABS_PATH_RE.match(arg):
                error = f"Error: absolute path '{arg}' not allowed."
                break
        if error:
            parts.append(f">>> {raw}\n{error}")
            continue

        # --- execute ---
        log.info("  -> %s", " ".join(tokens))
        try:
            result = subprocess.run(
                tokens,
                cwd=str(LOGS_DIR),
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            parts.append(f">>> {raw}\nError: '{cmd_name}' not found on this system.")
            continue
        except subprocess.TimeoutExpired:
            parts.append(f">>> {raw}\nError: timed out after 30 seconds.")
            continue

        output = result.stdout
        if result.returncode != 0 and result.stderr:
            output = (output + f"\n[stderr]: {result.stderr.strip()}").strip()
        parts.append(f">>> {raw}\n{output or '(no output)'}")

    return "\n\n".join(parts)

if __name__ == "__main__":
    mcp.run(transport="http", host="localhost", port=5000)
