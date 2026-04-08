"""
Threat Hunting Crew — ADK 2.0 Workflow
=======================================
Topology
--------
root_agent = SequentialAgent(
    sub_agents=[
        analytic_support_officer,   # 1. Researches threat actor, produces ASOM
        hunt_loop,                  # 2. LoopAgent: crew_lead directs parallel analysts
    ]
)

hunt_loop = LoopAgent(
    sub_agents=[
        crew_lead,           # a. Issues directed tasks from ASOM / synthesizes findings / calls exit_loop
        parallel_analysts,   # b. ParallelAgent(analyst_1, analyst_2) — run simultaneously
    ]
)

Phase 1 — ASOM Production:
  - analytic_support_officer runs once, calls the aso_researcher (AgentTool) to gather
    threat intel, and produces a structured ASOM in the conversation.

Phase 2 — Iterative Hunt (hunt_loop):
  - crew_lead reads the ASOM from conversation history, issues tasks tied to PIRs/TTPs
  - Both analysts run in parallel against logs via MCP tools
  - Loop exits when crew_lead produces a final report mapped against the ASOM

Prerequisites:
  - MCP server must be running on localhost:5000 before starting the agent.
    From the mcp/ directory:  python tools.py
"""

from google.adk.agents import LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
from google.adk.tools import MCPToolset, exit_loop, google_search
from google.adk.tools.agent_tool import AgentTool
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






aso_researcher = LlmAgent(
    model="gemini-2.5-flash",
    name="aso_researcher",
    description="Threat intel researcher: searches for threat actor TTPs, detection methods, and network indicators to inform the ASOM.",
    generate_content_config=retry_config,
    instruction="""
    You are a threat intelligence researcher supporting a network threat hunt.
    When given a threat actor name or scenario, search for:
      - Known MITRE ATT&CK tactics, techniques, and procedures (TTPs)
      - Network-observable indicators (C2 protocols, ports, user-agents, beaconing patterns)
      - Detection opportunities in network logs (Zeek/Suricata conn, dns, http, files logs)
      - Any known IOCs (IPs, domains, file hashes, user-agents)
    Return concise, actionable findings that can be directly used to build hunt hypotheses.
    """,
    tools=[google_search],
)


analytic_support_officer = LlmAgent(
    model="gemini-2.5-flash",
    name="analytic_support_officer",
    description="Analytic Support Officer: researches the threat actor and produces the Analytic Scheme of Maneuver (ASOM) that guides the hunt.",
    generate_content_config=retry_config,
    instruction="""
You are the Analytic Support Officer (ASO). Your sole task in this phase is to research the
threat actor or scenario provided and produce a complete ASOM that will guide the network analysts.

STEP 1 — Research:
  Call the 'aso_researcher' tool with a focused query about the threat actor's network TTPs.
  Gather: known C2 methods, lateral movement patterns, DNS/HTTP indicators, relevant MITRE IDs.

STEP 2 — Produce ASOM:
  Using the research results, output a structured ASOM in exactly this format:

# ANALYTIC SCHEME OF MANEUVER (ASOM)
## Threat Actor Profile
- Name: [Threat Actor Name]
- Known Tactics: [List of known tactics]
- Known Techniques: [List of known techniques]
- Objectives: [List of known objectives]
## Priority Information Requirements (PIRs)
1. [PIR 1 — specific, answerable question]
2. [PIR 2]
3. [PIR 3]
## Tactics, Techniques, and Procedures (TTPs)
| Tactic | Technique | MITRE ID | Network Observable | Related PIRs |
|--------|-----------|----------|--------------------|---------------|
| [Tactic] | [Technique] | [ID] | [What to look for in logs] | [PIR #] |
## Initial Hypotheses
- Hypothesis 1: [Description]
- Hypothesis 2: [Description]
## Hunt Guidance for Analysts
- network_analyst_1 (L3/L4): [specific log files + patterns to investigate]
- network_analyst_2 (L7): [specific log files + patterns to investigate]

STEP 3 — Save ASOM:
  Call the 'save_asom' tool with the full ASOM markdown content produced in Step 2.
  Use a descriptive filename based on the threat actor name (e.g. 'apt29_asom.md').
  Confirm the file was saved before finishing.

Be specific and actionable. The analysts will use this ASOM directly.
""",
    tools=[AgentTool(agent=aso_researcher), mcp_tools],
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
    description="Mission commander: directs analysts using the ASOM, synthesizes findings, produces final report.",
    generate_content_config=retry_config,
    instruction="""
You lead a threat hunting crew. Before issuing tasks, read the ASOM produced by the
Analytic Support Officer earlier in the conversation. Use its PIRs and Hunt Guidance
as the basis for every task you issue.

ANALYSTS:
  - network_analyst_1: connection layer (conn.log, dns.log, pcap L3/L4)
  - network_analyst_2: application layer (http.log, files.log, weird.log, pcap L7)

Both analysts have access to shell commands, pcap tools (tcpdump/tshark), and scripting (write_script/run_script).

ITERATION 1 — Issue tasks derived directly from the ASOM Hunt Guidance and PIRs.
Format:
  TASK FOR network_analyst_1: <files + patterns tied to specific PIRs>
  TASK FOR network_analyst_2: <files + patterns tied to specific PIRs>

ITERATION 2+ — Synthesize analyst findings against the ASOM.
  - Note which PIRs are answered, which TTPs are confirmed/refuted.
  - If gaps remain (max 2 more iterations): issue focused follow-up tasks.
  - If all PIRs are addressed OR on iteration 3: write the final report and call exit_loop().

FINAL REPORT FORMAT (use only when ready to exit):
# THREAT ASSESSMENT REPORT
## Executive Summary
## ASOM Assessment (table: PIR | Status | Supporting Evidence)
## Timeline of Events (table: Timestamp | Source | Dest | Event | Significance)
## MITRE ATT&CK Mapping (table: Tactic | Technique | ID | Evidence | ASOM TTP Match)
## IOCs (IPs, Domains, User-Agents, Files)
## Recommended Actions

Rules: no fabrication; base all claims on analyst-reported evidence; tie every finding back to a PIR or TTP from the ASOM.
""",
    tools=[exit_loop],
)

# ---------------------------------------------------------------------------
# Hunt Loop — iterative analyst loop driven by the ASOM
# ---------------------------------------------------------------------------

hunt_loop = LoopAgent(
    name="hunt_loop",
    description="Iterative hunt loop: crew lead directs parallel analysts until all ASOM PIRs are addressed.",
    max_iterations=10,
    sub_agents=[crew_lead, parallel_analysts],
)

# ---------------------------------------------------------------------------
# Root Agent — SequentialAgent: ASOM production → iterative hunt
# Phase 1: analytic_support_officer produces the ASOM
# Phase 2: hunt_loop runs the structured investigation against the ASOM
# ---------------------------------------------------------------------------

root_agent = SequentialAgent(
    name="threat_hunting_crew",
    description="Full threat hunt workflow: ASO produces ASOM, then crew lead directs analysts in a structured hunt.",
    sub_agents=[analytic_support_officer, hunt_loop],
)