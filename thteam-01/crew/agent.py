"""
Threat Hunting Crew — ADK 2.0 Workflow
=======================================
Topology
--------
root_agent = LoopAgent(
    sub_agents=[
        crew_lead,           # 1. Issues directed tasks / synthesizes findings / calls exit_loop
        parallel_analysts,   # 2. ParallelAgent(analyst_1, analyst_2) — run simultaneously
    ]
)

Each loop iteration:
  - crew_lead runs first (iteration 1: scope the mission; iteration 2+: synthesize findings)
  - Both analysts run in parallel against the MCP-backed Zeek log toolset
  - Loop exits when crew_lead calls exit_loop() after producing the final report

Prerequisites:
  - MCP server must be running on localhost:5000 before starting the agent.
    From the mcp/ directory:  python tools.py
"""

from google.adk.agents import LlmAgent, LoopAgent, ParallelAgent
from google.adk.tools import MCPToolset, exit_loop
from google.adk.tools.mcp_tool import StreamableHTTPConnectionParams
from google.genai import types

# ---------------------------------------------------------------------------
# Retry policy — exponential backoff on 429 RESOURCE_EXHAUSTED
# Applied to every LlmAgent via generate_content_config.
# ---------------------------------------------------------------------------

retry_config = types.GenerateContentConfig(
    http_options=types.HttpOptions(
        retry_options=types.HttpRetryOptions(
            attempts=5,              # up to 5 retries per LLM call (includes original)
            initial_delay=2.0,       # 2 s before the first retry
            exp_base=2.0,            # doubles each delay: 2 → 4 → 8 → 16 → 32 s
            max_delay=60.0,          # cap at 60 s between retries
            http_status_codes=[429], # only retry on quota errors
        )
    )
)

# ---------------------------------------------------------------------------
# MCP Toolset — shared between both analysts
# Connects to the FastMCP threat-hunting server (streamable HTTP, localhost:5000/mcp).
# ---------------------------------------------------------------------------

mcp_tools = MCPToolset(
    connection_params=StreamableHTTPConnectionParams(
        url="http://localhost:5000/mcp",
    )
)

# ---------------------------------------------------------------------------
# Network Analyst 1 — Connection-Layer Focus
# Investigates OSI layers 3/4: IP flows, port patterns, lateral movement,
# DNS anomalies, scanning activity.
# ---------------------------------------------------------------------------

network_analyst_1 = LlmAgent(
    model="gemini-2.5-flash",
    name="network_analyst_1",
    description="Connection-layer analyst: IP flows, scanning, lateral movement, DNS anomalies.",
    generate_content_config=retry_config,
    instruction="""
You are a network-layer (L3/L4) threat hunter. Follow the crew lead's task in the conversation history.

TOOLS:
  - list_log_files: see available log files (including pcap files)
  - run_commands(commands): run 5-10 shell commands in ONE call (awk/grep/sed/cat/head/tail; relative paths only)
  - run_pcap_tcpdump(filename, args): run tcpdump against a pcap file in the logs directory
  - run_pcap_tshark(filename, args): run tshark against a pcap file in the logs directory
  - write_script(filename, script_type, content): write a Python or bash script to the scripts directory
  - run_script(filename, args): execute a previously written script; runs with the logs directory as cwd

STRATEGY:
  1. list_log_files — orient yourself (note any .pcap/.pcapng files)
  2. run_commands([...]) — send ALL your queries in one batch (5-10 commands)
  3. For pcap analysis: use run_pcap_tcpdump or run_pcap_tshark directly for quick queries
  4. If deeper analysis is needed (e.g. statistical correlation, IP enrichment):
     a. write_script(...) — author a Python or bash script
     b. run_script(...) — execute it and collect output

FOCUS: unusual outbound ports, lateral movement, port/host scanning, DNS anomalies, large/long sessions.
Prioritise conn.log, dns.log, and any pcap files.

OUTPUT: Numbered findings only. Each: timestamp range | src/dst IP:port | protocol | anomaly | MITRE TTP | confidence.
State "No findings" if clean. No commentary.
""",
    tools=[mcp_tools],
)

# ---------------------------------------------------------------------------
# Network Analyst 2 — Application-Layer Focus
# Investigates OSI layer 7: HTTP/S traffic, authentication events,
# C2 beaconing patterns, suspicious file transfers, credential abuse.
# ---------------------------------------------------------------------------

network_analyst_2 = LlmAgent(
    model="gemini-2.5-flash",
    name="network_analyst_2",
    description="Application-layer analyst: HTTP, auth events, C2 beaconing, file transfers.",
    generate_content_config=retry_config,
    instruction="""
You are an application-layer (L7) threat hunter. Follow the crew lead's task in the conversation history.

TOOLS:
  - list_log_files: see available log files (including pcap files)
  - run_commands(commands): run 5-10 shell commands in ONE call (awk/grep/sed/cat/head/tail; relative paths only)
  - run_pcap_tcpdump(filename, args): run tcpdump against a pcap file in the logs directory
  - run_pcap_tshark(filename, args): run tshark against a pcap file in the logs directory
  - write_script(filename, script_type, content): write a Python or bash script to the scripts directory
  - run_script(filename, args): execute a previously written script; runs with the logs directory as cwd

STRATEGY:
  1. list_log_files — orient yourself (note any .pcap/.pcapng files)
  2. run_commands([...]) — send ALL your queries in one batch (5-10 commands)
  3. For pcap analysis: use run_pcap_tshark for HTTP/TLS/DNS dissection; use run_pcap_tcpdump for raw packet inspection
  4. If deeper analysis is needed (e.g. payload parsing, entropy analysis, beacon detection):
     a. write_script(...) — author a Python or bash script
     b. run_script(...) — execute it and collect output

FOCUS: suspicious user-agents, encoded/large POSTs, C2 beaconing, exe/rare-MIME transfers, brute-force/credential-stuffing.
Prioritise http.log, files.log, weird.log, and any pcap files.

OUTPUT: Numbered findings only. Each: timestamp range | src IP/dst host | protocol/URI | anomaly | MITRE TTP | confidence.
State "No findings" if nothing anomalous. No commentary.
""",
    tools=[mcp_tools],
)

# ---------------------------------------------------------------------------
# Parallel Analysts — both run simultaneously in each loop iteration
# ---------------------------------------------------------------------------

parallel_analysts = ParallelAgent(
    name="parallel_analysts",
    description="Runs both network analysts in parallel to cover connection and application layers simultaneously.",
    sub_agents=[network_analyst_1, network_analyst_2],
)

# ---------------------------------------------------------------------------
# Crew Lead
# Orchestrates the investigation loop.
#   - Iteration 1 : scopes mission, issues specific tasks to each analyst
#   - Iteration 2+: synthesizes prior findings, re-tasks analysts OR exits with report
# ---------------------------------------------------------------------------

crew_lead = LlmAgent(
    model="gemini-2.5-flash",
    name="crew_lead",
    description="Mission commander: directs analysts, synthesizes findings, produces final report.",
    generate_content_config=retry_config,
    instruction="""
You lead a threat hunting crew with two analysts:
  - network_analyst_1: connection layer (conn.log, dns.log)
  - network_analyst_2: application layer (http.log, files.log, weird.log)

Analysts have access to shell commands AND scripting tools (write_script / run_script).
When issuing tasks, you may instruct an analyst to write and run a script if the analysis
requires logic beyond what one-liners can provide (e.g. pcap parsing, beacon detection,
statistical correlation, entropy scoring).

ITERATION 1 — No analyst findings yet: issue concise tasks to each analyst.
Format:
  TASK FOR network_analyst_1: <specific files + patterns + any scripting to perform>
  TASK FOR network_analyst_2: <specific files + patterns + any scripting to perform>

ITERATION 2+ — Analyst findings present: synthesize results.
  - If gaps remain (max 2 more iterations): issue focused follow-up tasks (scripting encouraged for deep-dive).
  - If picture is complete OR on iteration 3: write the final report and call exit_loop().

FINAL REPORT FORMAT (use only when ready to exit):
# THREAT ASSESSMENT REPORT
## Executive Summary
## Timeline of Events (table: Timestamp | Source | Dest | Event | Significance)
## MITRE ATT&CK Mapping (table: Tactic | Technique | ID | Evidence)
## IOCs (IPs, Domains, User-Agents, Files)
## Recommended Actions

Rules: no fabrication; base all claims on analyst-reported evidence; be concise.
""",
    tools=[exit_loop],
)

# ---------------------------------------------------------------------------
# Root Agent — LoopAgent ties the crew together
# Order: crew_lead (directs) → parallel_analysts (execute) → repeat
# ---------------------------------------------------------------------------

root_agent = LoopAgent(
    name="threat_hunting_crew",
    description="Iterative threat hunting workflow: crew lead directs parallel analysts until a complete assessment is produced.",
    max_iterations=10,
    sub_agents=[crew_lead, parallel_analysts],
)