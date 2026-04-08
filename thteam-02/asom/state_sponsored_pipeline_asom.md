# ANALYTIC SCHEME OF MANEUVER (ASOM)
## Threat Actor Profile
- Name: State-Sponsored Groups Targeting Oil Pipelines
- Known Tactics: Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Discovery, Command and Control, Impact
- Known Techniques: Spearphishing Attachment, Exploitation of Public-Facing Applications, Supply Chain Compromise, Command and Scripting Interpreter (PowerShell, VBScript), Windows Management Instrumentation (WMI), Scheduled Task, Valid Accounts, Obfuscated Files or Information, Process Injection, Masquerading, Credential Dumping (Mimikatz), System Information Discovery, Application Layer Protocol (HTTP/S), Encrypted Channel, Standard Non-Application Layer Protocol, Data Encoding, Domain Name System (DNS Tunneling), Data Destruction (Wiper Malware), Impair Process Control (ICS-specific malware like Pipedream/Incontroller)
- Objectives: Espionage, disruption, sabotage of oil and gas infrastructure

## Priority Information Requirements (PIRs)
1. Has any internal host initiated suspicious outbound connections to known C2 infrastructure (e.g., `sfrclak[.]com`, `142.11.206[.]73`, or unexpected ports like 4050, 8000)?
2. Is there evidence of unusual or excessive DNS queries, especially for TXT records or long/malformed domain names, indicative of DNS tunneling?
3. Are there HTTP requests with anomalous User-Agent strings (e.g., `Microsoft WinRM Client`), unusual POST requests to external IPs, or consistent beaconing patterns to suspicious domains?
4. Have there been any attempts to exploit public-facing applications (VPN, Citrix, OWA) from internal hosts, or signs of spearphishing leading to the execution of malicious scripts (VBScript, PowerShell)?
5. Is there any evidence of lateral movement using stolen credentials (e.g., Mimikatz activity) or remote execution methods (e.g., WMI, unencrypted remote PowerShell)?

## Tactics, Techniques, and Procedures (TTPs)
| Tactic | Technique | MITRE ID | Network Observable | Related PIRs |
|---|---|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 | Transfer of executable, VBScript, or PowerShell files over HTTP/S from suspicious sources. | PIR 4 |
| Initial Access | Exploitation of Public-Facing Applications | T1190 | Connections to VPN, Citrix, or OWA services from unexpected internal hosts or at unusual times. | PIR 4 |
| Execution | Command and Scripting Interpreter | T1059 | Outbound HTTP/S connections with `Microsoft WinRM Client` User-Agent or unusual HTTP POSTs after script execution. | PIR 3, PIR 5 |
| Persistence | Scheduled Task | T1053.005 | Periodic outbound connections to C2 domains at regular intervals. | PIR 1, PIR 3 |
| Command and Control | Application Layer Protocol | T1071 | HTTP/S traffic to suspicious domains/IPs, especially with generic or unusual User-Agents. | PIR 1, PIR 3 |
| Command and Control | Domain Name System | T1071.004 | High volume of DNS requests to unusual domains, long or malformed DNS queries, excessive TXT record requests. | PIR 2 |
| Command and Control | Standard Non-Application Layer Protocol | T1095 | Connections to unusual ports like 4050 or 8000. | PIR 1 |
| Credential Access | Credential Dumping | T1003 | SMB/DCE-RPC activity indicating Mimikatz execution or suspicious credential usage. | PIR 5 |
| Defense Evasion | Masquerading | T1036 | HTTP/S connections to C2 infrastructure using User-Agents or hostnames mimicking legitimate services (e.g., Google, Microsoft). | PIR 3 |

## Initial Hypotheses
- Hypothesis 1: Adversaries have established C2 channels using standard application layer protocols (HTTP/S) or DNS tunneling, communicating with external infrastructure mimicking legitimate traffic.
- Hypothesis 2: Initial compromise occurred via spearphishing or exploitation of public-facing applications, leading to the execution of obfuscated scripts and subsequent lateral movement within the network.

## Hunt Guidance for Analysts
- network_analyst_1 (L3/L4):
    - **`conn.log`**: Filter for connections to non-standard ports (e.g., 4050, 8000), connections to known suspicious IPs (`142.11.206[.]73`), and unusual connections to VPN/Citrix/OWA services from internal hosts. Look for connections with high duration or byte counts to external, unclassified destinations.
    - **`dns.log`**: Analyze for high volumes of DNS requests to single domains, unusually long DNS query names, or excessive TXT record queries.
    - **`notice.log`**: Review for any generated alerts related to suspicious network activity or protocol anomalies.
- network_analyst_2 (L7):
    - **`http.log`**: Examine HTTP User-Agent strings for anomalies (e.g., `Microsoft WinRM Client`, generic strings not matching common browsers). Look for frequent HTTP POST requests to external IPs/domains, particularly with low-frequency, consistent timing (beaconing). Investigate connections to `sfrclak[.]com` or `krakenfiles[.]com`.
    - **`files.log`**: Monitor for the transfer of executables, VBScripts, or PowerShell scripts over HTTP/S, especially from suspicious external sources or with enticing filenames.
    - **`smb_files.log`, `dce_rpc.log`**: Look for activity indicative of credential dumping tools (e.g., Mimikatz) being transferred or executed, or anomalous DCE-RPC activity.
    - **Suricata alerts**: Review Suricata logs for detections of known malware (e.g., PowGoop, AsyncRAT, Pipedream) or exploit attempts against public-facing applications.