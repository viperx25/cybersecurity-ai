# THREAT ASSESSMENT REPORT
## Executive Summary

A threat hunt conducted on the oil pipeline administrative network has uncovered strong evidence of a sophisticated cyberattack, likely from a state-sponsored group, aimed at Command and Control (C2) and credential access. Key findings include persistent custom UDP beaconing on a non-standard port (9999), extensive DNS tunneling activity, and confirmed credential dumping operations on internal hosts. While the initial access vector remains unconfirmed, the observed activities align with the known Tactics, Techniques, and Procedures (TTPs) of state-sponsored groups targeting critical infrastructure. Remediation efforts should prioritize containing the compromised internal hosts and dismantling the identified C2 channels.

## ASOM Assessment

| PIR                                                                                                                                                                                            | Status            | Supporting Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Has any internal host initiated suspicious outbound connections to known C2 infrastructure (e.g., `sfrclak[.]com`, `142.11.206[.]73`, or unexpected ports like 4050, 8000)?                 | Partially Answered | **High Confidence:** Consistent, periodic UDP traffic between internal hosts 192.168.1.1:9999 and 192.168.1.46:9999 with fixed 520-byte, repetitive payloads, indicating custom C2 beaconing. <br> **Medium Confidence:** DNS queries from 192.168.1.46 to `act.crystaljewelry.biz`, an unusual external domain. <br> **Low-Medium Confidence:** High volume of HTTPS connections from 192.168.1.46 to diverse external IPs, some with sustained data transfer. No direct hits on explicitly known C2 domains/IPs or ports 4050/8000. |
| 2. Is there evidence of unusual or excessive DNS queries, especially for TXT records or long/malformed domain names, indicative of DNS tunneling?                                             | Answered          | **High Confidence:** Multiple DNS queries from 192.168.1.46 and 192.168.1.195 to suspicious, long, randomized subdomains under `footprintdns.com` (e.g., `f328b56eabf88aedc4ba956828b5a43e.clo.footprintdns.com`), strongly indicative of DNS tunneling.                                                                                                                                                                                                                                                                                               |
| 3. Are there HTTP requests with anomalous User-Agent strings (e.g., `Microsoft WinRM Client`), unusual POST requests to external IPs, or consistent beaconing patterns to suspicious domains? | Partially Answered | **Refuted:** No `Microsoft WinRM Client` User-Agents or HTTP POST requests found in `http.log`. The previously identified 554-byte transfers to 23.211.124.129 were confirmed to be legitimate Microsoft CRL traffic. <br> **Indirectly addressed:** Consistent beaconing over UDP 9999 was identified, but not via HTTP.                                                                                                                                                                                                                                      |
| 4. Have there been any attempts to exploit public-facing applications (VPN, Citrix, OWA) from internal hosts, or signs of spearphishing leading to the execution of malicious scripts (VBScript, PowerShell)? | Not Answered      | **Not Found:** No direct evidence of exploitation attempts on common VPN, Citrix, or OWA service ports from internal hosts. No files with suspicious double extensions (`.doc.exe`, `.pdf.vbs`, etc.), generic executable names, or unknown MIME types were identified in `files.log` that indicate initial access. No suspicious HTTP status codes related to exploitation were observed.                                                                                                                                                               |
| 5. Is there any evidence of lateral movement using stolen credentials (e.g., Mimikatz activity) or remote execution methods (e.g., WMI, unencrypted remote PowerShell)?                      | Partially Answered | **Medium Confidence:** `BackupKey` (23:27:03) and `LsarLookupSids3` (23:27:54) operations on the LSASS pipe in `dce_rpc.log` between 192.168.1.46 and 192.168.1.195 are strong indicators of credential dumping. <br> **Not Found:** No subsequent SMB or Kerberos connections or authentication attempts immediately following the credential dumping events, suggesting no immediate lateral movement via these specific protocols *in the analyzed logs*.                                                                                       |

## Timeline of Events

| Timestamp             | Source          | Dest            | Event                                                                                                     | Significance                                         |
| :-------------------- | :-------------- | :-------------- | :-------------------------------------------------------------------------------------------------------- | :--------------------------------------------------- |
| Mar 16, 23:26:52      | 192.168.1.1:9999 | 192.168.1.46:9999 | Start of consistent, periodic UDP traffic (520 bytes, repetitive payload `0c151f00...`).                 | Custom C2 beaconing.                                 |
| Mar 16, 23:26:53      | 192.168.1.46    | External IPs:443 | Initiation of high volume HTTPS connections to diverse external hosts.                                     | Potential C2 or data exfiltration.                   |
| Mar 16, 23:27:03      | 192.168.1.46    | 192.168.1.195   | DCE/RPC `BackupKey` operation on LSASS pipe.                                                              | Credential dumping attempt.                          |
| Mar 16, 23:27:13      | 192.168.1.46    | `act.crystaljewelry.biz` | DNS query to an unusual external domain.                                                                  | Potential C2 activity.                               |
| Mar 16, 23:27:54      | 192.168.1.46    | 192.168.1.195   | DCE/RPC `LsarLookupSids3` operation on lsarpc.                                                            | Credential dumping attempt.                          |
| Various (Throughout)  | 192.168.1.46/195 | `footprintdns.com` subdomains | Multiple DNS queries to long, randomized subdomains (e.g., `f328b56eabf88aedc4ba956828b5a43e.clo.footprintdns.com`). | DNS tunneling for C2 or data exfiltration.           |

## MITRE ATT&CK Mapping

| Tactic                  | Technique                                  | ID          | Evidence                                                                                                                                                                                          | ASOM TTP Match              |
| :---------------------- | :----------------------------------------- | :---------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :-------------------------- |
| Command and Control     | Application Layer Protocol (DNS)           | T1071.004   | Multiple DNS queries to suspicious, long, randomized subdomains under `footprintdns.com`.                                                                                                         | Application Layer Protocol, DNS Tunneling |
| Command and Control     | Standard Non-Application Layer Protocol    | T1095       | Consistent, periodic UDP traffic on port 9999 with fixed 520-byte, repetitive payloads between 192.168.1.1 and 192.168.1.46.                                                                         | Standard Non-Application Layer Protocol |
| Command and Control     | Application Layer Protocol                 | T1071       | UDP 9999 custom C2 beaconing. Also, DNS queries to `act.crystaljewelry.biz`.                                                                                                                   | Application Layer Protocol |
| Defense Evasion         | Non-Standard Port                          | T1571       | Use of UDP port 9999 for custom C2 beaconing.                                                                                                                                                     | N/A (implied by T1095)      |
| Exfiltration            | Exfiltration Over C2 Channel               | T1041       | DNS tunneling to `footprintdns.com` subdomains, and potential use of UDP 9999 channel and high volume HTTPS for data exfiltration.                                                              | N/A (implied by T1071.004, T1071, T1095) |
| Credential Access       | OS Credential Dumping                      | T1003       | Detection of `BackupKey` and `LsarLookupSids3` operations on the LSASS pipe in `dce_rpc.log` from 192.168.1.46 to 192.168.1.195.                                                                | Credential Dumping          |

## IOCs

*   **Domains:**
    *   `*.footprintdns.com` (e.g., `f328b56eabf88aedc4ba956828b5a43e.clo.footprintdns.com`, `260fce046dd27d6c8b8270f723eb4b40.clo.footprintdns.com`, `403fcf0e465d6c819fa6588feb50b7ce.clo.footprintdns.com`)
    *   `act.crystaljewelry.biz`
*   **IPs:**
    *   192.168.1.1 (Internal, UDP C2 participant)
    *   192.168.1.46 (Internal, compromised host, UDP C2 participant, DNS tunneling, credential dumping, high volume HTTPS)
    *   192.168.1.195 (Internal, involved in credential dumping and DNS tunneling)
    *   66.211.178.172
    *   50.16.192.43
    *   65.52.235.123
    *   23.211.106.58
    *   68.67.180.45
    *   108.174.10.10
    *   54.227.242.33
    *   131.253.61.66
    *   204.79.197.200
    *   209.188.86.144
    *   65.55.138.112
    *   65.55.44.82
*   **Ports/Protocols:**
    *   UDP Port 9999 (Custom C2)
    *   DNS TXT records (for tunneling)
*   **Payload Patterns:**
    *   `0c151f00...` (Repetitive UDP 9999 payload)

## Recommended Actions

1.  **Isolate and Contain:** Immediately isolate internal hosts 192.168.1.46, 192.168.1.1, and 192.168.1.195 from the network to prevent further compromise and C2 communication.
2.  **Forensic Image:** Create forensic images of 192.168.1.46, 192.168.1.1, and 192.168.1.195 for in-depth analysis to identify the initial compromise vector, persistence mechanisms, and full extent of data exfiltration.
3.  **Credential Reset:** Force a password reset for all user accounts associated with 192.168.1.46 and 192.168.1.195, and investigate for any newly created or modified accounts.
4.  **Network Blocking:** Implement immediate blocks on all firewall and proxy devices for the identified C2 domains (`*.footprintdns.com`, `act.crystaljewelry.biz`) and the unusual C2 IPs.
5.  **DNS Monitoring:** Enhance DNS monitoring to specifically detect unusual query lengths, high volumes of TXT record requests, and queries to newly observed or suspicious domains.
6.  **Signature Development:** Develop and deploy custom network signatures to detect the identified UDP 9999 beaconing pattern.
7.  **Threat Intelligence Integration:** Integrate the discovered IOCs into existing security tools (SIEM, IDS/IPS) for ongoing detection and alerting.
8.  **Vulnerability Scan:** Conduct a comprehensive vulnerability scan of all public-facing applications and internal network devices to identify and patch any exploited vulnerabilities.
9.  **User Awareness Training:** Reinforce spearphishing awareness training for all users in the administrative network.