# ASOM: Network-Layer Threat Hunt

## 1. Overview
This ASOM outlines the strategy for a network-layer threat hunt, focusing on identifying unusual network activity, potential command and control (C2), lateral movement, and data exfiltration. The hunt will prioritize analysis of connection logs (conn.log), DNS logs (dns.log), and any available PCAP files.

## 2. Priority Intelligence Requirements (PIRs)

*   **PIR 1:** Are there any outbound connections to unusual ports (e.g., non-standard HTTP/S, common C2 ports, or unassigned ports)?
    *   **Indicator Type:** Network Flow, Unusual Port
    *   **Log Sources:** conn.log, pcap files
    *   **MITRE ATT&CK TTPs:** TA0011 (Command and Control), T1071.001 (Application Layer Protocol: Web Protocols), T1571 (Non-Standard Port)

*   **PIR 2:** Is there evidence of internal reconnaissance or scanning activity (e.g., multiple failed connection attempts to different internal hosts/ports from a single source)?
    *   **Indicator Type:** Network Flow, Scanning
    *   **Log Sources:** conn.log, pcap files
    *   **MITRE ATT&CK TTPs:** TA0007 (Discovery), T1046 (Network Service Discovery), T1018 (Remote System Discovery)

*   **PIR 3:** Are there any suspicious DNS queries (e.g., queries for known malicious domains, unusually long/randomized domain names, high volume of unique domain queries from a single host)?
    *   **Indicator Type:** DNS Query, Malicious Domain
    *   **Log Sources:** dns.log, pcap files
    *   **MITRE ATT&CK TTPs:** TA0011 (Command and Control), T1071.004 (Application Layer Protocol: DNS)

*   **PIR 4:** Is there evidence of lateral movement attempts (e.g., connections from internal hosts to other internal hosts on administrative or remote access ports that are not typical for their role)?
    *   **Indicator Type:** Network Flow, Lateral Movement
    *   **Log Sources:** conn.log, pcap files
    *   **MITRE ATT&CK TTPs:** TA0008 (Lateral Movement), T1021 (Remote Services)

*   **PIR 5:** Are there any unusually large or long-duration connections, especially outbound, that might indicate data exfiltration?
    *   **Indicator Type:** Network Flow, Data Volume/Duration
    *   **Log Sources:** conn.log, pcap files
    *   **MITRE ATT&CK TTPs:** TA0010 (Exfiltration), T1041 (Exfiltration Over C2 Channel)

## 3. Hunt Guidance

1.  **Initial Data Review:**
    *   List all available log files to understand the data landscape.
    *   Prioritize `conn.log`, `dns.log`, and any `.pcap`/`.pcapng` files.

2.  **Unusual Outbound Ports (PIR 1):**
    *   Analyze `conn.log` for connections to destination ports other than 80, 443, 53, 21, 22, 25, 110, 143, 993, 995, 3389 (common ports).
    *   Specifically look for high-numbered ports, or ports associated with known C2 frameworks.
    *   Use `tcpdump` or `tshark` on PCAP files to filter for non-standard ports and examine payload if possible.

3.  **Scanning Activity (PIR 2):**
    *   From `conn.log`, identify source IPs with a high number of distinct destination IPs and/or ports, especially those with many connection failures (`status=REJ` or similar).
    *   Correlate with `pcap` data to confirm port scan patterns (e.g., SYN scans).

4.  **DNS Anomalies (PIR 3):**
    *   Examine `dns.log` for:
        *   Queries to known suspicious/malicious domains (if IOCs are available).
        *   High entropy domain names (randomized strings).
        *   A single source IP querying an unusually high number of unique domains in a short period.
    *   Use `tshark` on PCAP files to extract DNS queries and responses.

5.  **Lateral Movement (PIR 4):**
    *   Filter `conn.log` for internal-to-internal connections on ports like 22 (SSH), 3389 (RDP), 445 (SMB), 135/139 (RPC/NetBIOS) that originate from unusual internal sources or connect to unusual internal destinations.
    *   Look for failed authentication attempts in relevant logs if available.

6.  **Large/Long Sessions (PIR 5):**
    *   Sort `conn.log` by `orig_bytes`/`resp_bytes` and `duration` (if available) to identify unusually large or long-lived connections, particularly outbound ones.
    *   Investigate the destination IPs and ports for these connections.

## 4. Tools and Techniques
*   `grep`, `awk`, `sort`, `uniq` for log file analysis.
*   `tcpdump` for quick PCAP filtering and header inspection.
*   `tshark` for detailed PCAP analysis, protocol dissection, and field extraction.
*   Python/Bash scripting for more complex parsing, statistical analysis, or correlation across multiple log sources.

## 5. Reporting
*   Document all findings with timestamps, source/destination IPs and ports, protocols, identified anomalies, relevant MITRE ATT&CK TTPs, and confidence levels.
*   State "No findings" if no anomalies are identified.