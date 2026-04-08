# ANALYTIC SCHEME OF MANEUVER (ASOM)
## Threat Actor Profile
- Name: Non-Nation-State ICS Threat Actors (e.g., Z-Pentest, Dark Engine, Sector 16)
- Known Tactics: Initial Access, Discovery, Execution, Lateral Movement, Command and Control, Impact, Exfiltration
- Known Techniques: Internet Accessible Device, Exploit Public-Facing Application, Default Credentials, Remote Services, Command Line Interface, Remote Desktop Protocol, DNS Tunneling, Program PLC, Data Destruction, Manipulate Control Logic
- Objectives: Disruption, data exfiltration for notoriety or financial gain, politically motivated sabotage, defacement.
## Priority Information Requirements (PIRs)
1. Are there any internet-facing ICS/OT services (e.g., VNC, RDP, web-based HMIs) being accessed from suspicious external IPs or utilizing default/weak credentials?
2. Are internal systems within the OT network establishing covert Command and Control (C2) channels via disguised protocols (e.g., HTTP/S, DNS) or legitimate cloud services to external infrastructure?
3. Is there evidence of lateral movement attempts, such as internal scanning or anomalous RDP/SMB connections, between IT and OT networks or deeper within OT segments?
4. Are there any anomalous commands or data writes being sent over industrial protocols that could indicate manipulation of ICS processes or safety functions?
## Tactics, Techniques, and Procedures (TTPs)
| Tactic | Technique | MITRE ID | Network Observable | Related PIRs |
|--------|-----------|----------|--------------------|---------------|
| Initial Access | Internet Accessible Device | T0868 | Connections to known OT service ports (e.g., VNC 5900, RDP 3389, common HTTP/HTTPS ports) from external IPs not on an allowlist. | 1 |
| Initial Access | Exploit Public-Facing Application | T0806 | Unusual HTTP requests to web-based HMIs, connections to devices with known vulnerabilities. | 1 |
| Initial Access | Default Credentials | T0874.001 | Repeated failed login attempts or successful logins using default/weak credentials in authentication logs (if available via network logs). | 1 |
| Command and Control | Remote Services | T0862 | Consistent outbound connections on non-standard ports, repetitive low-volume HTTP/HTTPS requests to suspicious domains/IPs, unusual user-agent strings. | 2 |
| Command and Control | Standard Application Layer Protocol | T0862 | High volumes of DNS queries to uncommon or newly observed domains, particularly with algorithmic or long, random-looking subdomains (DNS tunneling). | 2 |
| Lateral Movement | Remote Desktop Protocol | T0875 | Anomalous RDP/SMB connections between IT and OT zones or unusual internal host connections. | 3 |
| Discovery | Scan for Vulnerable Devices | T0883 | Internal scanning activity on ICS-specific ports (e.g., Modbus TCP 502, DNP3 20000/20001) or open ports like VNC. | 3 |
| Impact | Manipulate Control Logic | T0848 | Anomalous commands or data writes using industrial protocols (e.g., Modbus, DNP3) in specialized ICS monitoring logs (if available via network-level DFI). | 4 |
| Exfiltration | Data Exfiltration | T0813 | Suspicious file transfers to or from critical assets, especially executables or uncommon file types, frequent connections to cloud storage services. | 2 |
## Initial Hypotheses
- Hypothesis 1: Adversaries have gained initial access to the power plant network by exploiting internet-facing ICS/OT services, possibly utilizing weak credentials or unpatched vulnerabilities.
- Hypothesis 2: Compromised internal systems are communicating with external C2 infrastructure, likely using covert channels disguised as legitimate HTTP/HTTPS or DNS traffic.
- Hypothesis 3: Threat actors are actively performing internal network reconnaissance and attempting to move laterally from IT to OT networks or deeper within OT segments.
- Hypothesis 4: Malicious payloads are being delivered and executed on IT/OT workstations, leading to further compromise and potential process manipulation attempts.
## Hunt Guidance for Analysts
- network_analyst_1 (L3/L4):
    - `conn.log`: Filter for connections to known OT service ports (e.g., 5900, 3389, 80, 443) from external IPs not on an allowlist. Look for connections on non-standard ports. Analyze connection duration and frequency for beaconing patterns. Filter for connections to geo-anomalous locations. Monitor for internal scanning activity on ICS-specific ports (e.g., 502, 20000/20001).
    - `dns.log`: Identify anomalous query patterns (e.g., excessively long domains, frequent lookups for non-existent subdomains, queries resolving to unusual external IPs).
- network_analyst_2 (L7):
    - `http.log`: Inspect `host` headers for suspicious domains. Analyze `uri` paths and query parameters for encoded data or unusual structures. Monitor `user_agent` strings for anomalies or known malicious agents. Look for repetitive HTTP GET/POST requests at regular intervals.
    - `files.log`: Detect downloaded executable files (`.exe`, `.dll`) or suspicious archives. Extract file hashes (MD5, SHA1, SHA256) and compare them against threat intelligence databases.
    - `dpd.log` (if available for deep packet inspection of industrial protocols): Monitor for anomalous commands or data writes using protocols like Modbus or DNP3.