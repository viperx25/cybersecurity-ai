"""
Threat Hunting MCP Server
Exposes tools to a security analyst agent via streamable HTTP:
  - list_log_files    : ls on the logs directory
  - run_command       : run awk/sed/cat/grep/head/tail against log files
  - run_commands      : run multiple commands in one batch
  - write_script      : write a bash or python script to the scripts directory
  - run_script        : execute a script from the scripts directory
  - run_pcap_tcpdump  : run tcpdump against a pcap file in the logs directory
  - run_pcap_tshark   : run tshark against a pcap file in the logs directory
  - save_asom         : save the ASOM as a markdown file
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

_REPO_ROOT = Path(__file__).parent.parent.resolve()

# Set this to change which dataset's log directory is used.
LOG_DIR = _REPO_ROOT / "datasets" / "logs" / "malware"

LOGS_DIR = LOG_DIR.resolve()
SCRIPTS_DIR = (_REPO_ROOT / "thteam-01" / "scripts").resolve()
ASOMS_DIR = (_REPO_ROOT / "thteam-02" / "asom").resolve()

ALLOWED_COMMANDS = {"awk", "sed", "cat", "grep", "head", "tail"}
ALLOWED_SCRIPT_TYPES = {"bash", "python"}

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


@mcp.tool()
def write_script(filename: str, script_type: str, content: str) -> str:
    """Write a bash or python script to the scripts directory.

    Args:
        filename:    Name of the script file (e.g. 'parse_pcap.py' or 'extract_iocs.sh').
                     Must not contain path separators or '..'.
        script_type: Either 'python' or 'bash'.
        content:     Full source code of the script.

    Returns:
        Absolute path to the written file, or an error message.

    Examples:
        write_script("count_ips.py", "python", "import sys\\nprint('hello')")
        write_script("extract_dns.sh", "bash", "#!/bin/bash\\ngrep -oP '...' dns.log")
    """
    if script_type not in ALLOWED_SCRIPT_TYPES:
        allowed = ", ".join(sorted(ALLOWED_SCRIPT_TYPES))
        return f"Error: script_type '{script_type}' is not allowed. Must be one of: {allowed}."

    # Reject filenames with path separators or traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        return f"Error: filename '{filename}' must not contain path separators or '..'."

    # Enforce correct extension
    if script_type == "python" and not filename.endswith(".py"):
        filename += ".py"
    elif script_type == "bash" and not filename.endswith(".sh"):
        filename += ".sh"

    target = SCRIPTS_DIR / filename

    # Resolve and confirm the final path is inside SCRIPTS_DIR (defence-in-depth)
    try:
        target.resolve().relative_to(SCRIPTS_DIR)
    except ValueError:
        return f"Error: resolved path escapes the scripts directory."

    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    target.chmod(0o755)

    log.info("write_script(%s)", target)
    return str(target)


@mcp.tool()
def run_script(filename: str, args: list[str] | None = None) -> str:
    """Execute a previously written script from the scripts directory.

    The script must already exist in the scripts directory (use write_script first).
    Filenames must not contain path separators or '..'.
    Scripts run with the logs/malware directory as their working directory so
    they can reference log files by name.

    Args:
        filename: Name of the script file (e.g. 'parse_pcap.py').
        args:     Optional list of command-line arguments to pass to the script.

    Returns:
        Combined stdout/stderr output, or an error message.

    Examples:
        run_script("count_ips.py")
        run_script("extract_dns.sh", ["conn.log"])
    """
    if args is None:
        args = []

    if "/" in filename or "\\" in filename or ".." in filename:
        return f"Error: filename '{filename}' must not contain path separators or '..'."

    script_path = SCRIPTS_DIR / filename
    if not script_path.exists():
        return f"Error: script '{filename}' not found in scripts directory."

    # Choose interpreter based on extension
    if filename.endswith(".py"):
        interpreter = "python3"
    elif filename.endswith(".sh"):
        interpreter = "bash"
    else:
        return f"Error: cannot determine interpreter for '{filename}'. Use .py or .sh extension."

    # Validate args — block path traversal
    for arg in args:
        if ".." in arg:
            return f"Error: path traversal detected in argument '{arg}'."

    cmd = [interpreter, str(script_path)] + args
    log.info("run_script(%s)", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            cwd=str(LOGS_DIR),
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        return f"Error: interpreter '{interpreter}' was not found on this system."
    except subprocess.TimeoutExpired:
        return "Error: script timed out after 60 seconds."

    output = result.stdout
    if result.stderr:
        output = (output + f"\n[stderr]: {result.stderr.strip()}").strip()

    return output or "(no output)"


# ---------------------------------------------------------------------------
# PCAP analysis tools
# ---------------------------------------------------------------------------

_SAFE_ARG_RE = re.compile(r"^[a-zA-Z0-9_./:@=,^+*?!~%&|()\[\]{}-]+$")


def _validate_pcap_args(filename: str, extra_args: list[str]) -> str | None:
    """Return an error string if any argument is unsafe, else None."""
    if "/" in filename or "\\" in filename or ".." in filename:
        return f"Error: filename '{filename}' must not contain path separators or '..'."
    if not filename.endswith(".pcap") and not filename.endswith(".pcapng"):
        return f"Error: '{filename}' does not look like a pcap file (.pcap / .pcapng)."
    pcap_path = LOGS_DIR / filename
    if not pcap_path.exists():
        return f"Error: pcap file '{filename}' not found in logs directory."
    for arg in extra_args:
        if ".." in arg:
            return f"Error: path traversal detected in argument '{arg}'."
        if _ABS_PATH_RE.match(arg):
            return f"Error: absolute path '{arg}' is not allowed."
    return None


@mcp.tool()
def run_pcap_tcpdump(filename: str, args: list[str] | None = None) -> str:
    """Run tcpdump against a pcap file in the logs directory.

    The file must already exist in the logs directory. Only .pcap and .pcapng
    files are accepted. Absolute paths and path traversal are blocked.
    tcpdump is always invoked in read-only mode (-r); you may not pass -w.

    Args:
        filename: Name of the pcap file (e.g. 'capture.pcap').
        args:     Additional tcpdump flags and filter expressions.
                  Do NOT include -r / --read-file; it is added automatically.

    Returns:
        tcpdump output (stdout + stderr), or an error message.

    Examples:
        run_pcap_tcpdump("malware_infection.pcap")
        run_pcap_tcpdump("malware_infection.pcap", ["-nn", "-c", "100"])
        run_pcap_tcpdump("malware_infection.pcap", ["-nn", "tcp port 443"])
        run_pcap_tcpdump("malware_infection.pcap", ["-nn", "-q", "host 10.0.0.5"])
    """
    if args is None:
        args = []

    err = _validate_pcap_args(filename, args)
    if err:
        return err

    # Block write mode — analysts must not exfiltrate or overwrite files
    for arg in args:
        if arg in ("-w", "--write"):
            return "Error: -w/--write is not permitted."

    pcap_path = str(LOGS_DIR / filename)
    cmd = ["tcpdump", "-r", pcap_path] + args
    log.info("run_pcap_tcpdump(%s)", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        return "Error: tcpdump was not found on this system."
    except subprocess.TimeoutExpired:
        return "Error: tcpdump timed out after 60 seconds."

    output = result.stdout
    if result.stderr:
        output = (output + f"\n[stderr]: {result.stderr.strip()}").strip()
    return output or "(no output)"


@mcp.tool()
def run_pcap_tshark(filename: str, args: list[str] | None = None) -> str:
    """Run tshark against a pcap file in the logs directory.

    The file must already exist in the logs directory. Only .pcap and .pcapng
    files are accepted. Absolute paths and path traversal are blocked.
    tshark is always invoked in read-only mode (-r); you may not pass -w or -i.

    Args:
        filename: Name of the pcap file (e.g. 'capture.pcap').
        args:     Additional tshark flags, display filters, and field options.
                  Do NOT include -r; it is added automatically.

    Returns:
        tshark output (stdout + stderr), or an error message.

    Examples:
        run_pcap_tshark("malware_infection.pcap")
        run_pcap_tshark("malware_infection.pcap", ["-q", "-z", "conv,tcp"])
        run_pcap_tshark("malware_infection.pcap", ["-Y", "http.request", "-T", "fields",
                         "-e", "ip.src", "-e", "http.host", "-e", "http.request.uri"])
        run_pcap_tshark("malware_infection.pcap", ["-Y", "dns", "-T", "fields",
                         "-e", "ip.src", "-e", "dns.qry.name"])
    """
    if args is None:
        args = []

    err = _validate_pcap_args(filename, args)
    if err:
        return err

    for arg in args:
        if arg in ("-w", "-i"):
            return f"Error: '{arg}' is not permitted."

    pcap_path = str(LOGS_DIR / filename)
    cmd = ["tshark", "-r", pcap_path] + args
    log.info("run_pcap_tshark(%s)", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        return "Error: tshark was not found on this system."
    except subprocess.TimeoutExpired:
        return "Error: tshark timed out after 60 seconds."

    output = result.stdout
    if result.stderr:
        output = (output + f"\n[stderr]: {result.stderr.strip()}").strip()
    return output or "(no output)"


@mcp.tool()
def save_asom(content: str, filename: str = "asom.md") -> str:
    """Save the Analytic Scheme of Maneuver (ASOM) as a markdown file.

    Writes the ASOM to the thteam-02/asom/ directory. The directory is created
    if it does not exist. Filenames must not contain path separators or '..'.

    Args:
        content:  Full markdown content of the ASOM.
        filename: Name of the output file (default: 'asom.md').
                  Must end with .md and must not contain path separators or '..'.

    Returns:
        Absolute path to the saved file, or an error message.

    Examples:
        save_asom("# ANALYTIC SCHEME OF MANEUVER...")
        save_asom("# ANALYTIC SCHEME OF MANEUVER...", "apt29_asom.md")
    """
    if "/" in filename or "\\" in filename or ".." in filename:
        return f"Error: filename '{filename}' must not contain path separators or '..'."
    if not filename.endswith(".md"):
        filename += ".md"

    target = ASOMS_DIR / filename
    try:
        target.resolve().relative_to(ASOMS_DIR)
    except ValueError:
        return "Error: resolved path escapes the asom directory."

    ASOMS_DIR.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")

    log.info("save_asom(%s)", target)
    return str(target)


if __name__ == "__main__":
    mcp.run(transport="http", host="localhost", port=5000)
