# Network Forensics: Analysis of a Malicious Spam (Malspam) Incident

## Objective
Analyze a network packet capture (PCAP) to investigate a reported security incident. The goal was to uncover the full attack chain, from initial compromise to impact, following a user's interaction with a phishing email.

## Core Scenario
An employee at Bartell Ltd opened a weaponized Word document from a phishing email, triggering a malware infection. The Security Operations Center (SOC) provided the network traffic for analysis. The investigation revealed a multi-stage attack involving initial access via a malicious macro, establishment of persistent command and control (C2) channels, and the use of the compromised host to send malicious spam.

## Tools & Technologies Used
*   **Wireshark** - Primary tool for deep packet inspection and traffic analysis.
*   **VirusTotal** - Threat intelligence platform for IOC (Indicator of Compromise) validation.
*   **MITRE ATT&CK Framework** - Used to map adversary tactics and techniques.

## 🔑 Key Achievements & Findings
*   **Full Attack Chain Reconstruction:** Traced the intrusion from the initial malicious file download (`documents.zip`) through to data exfiltration and malicious spam propagation.
*   **C2 Infrastructure Exposure:** Identified and validated multiple **Cobalt Strike** command and control servers (`survmeter.live`, `securitybusinpuff.com`) through beaconing traffic patterns and threat intelligence correlation.
*   **Encrypted Traffic Analysis:** Uncovered hidden malicious HTTPS downloads by analyzing TLS handshakes and correlating contacted domains with threat feeds.
*   **Impact Verification:** Discovered post-compromise activity where the attacker hijacked an email account (`cristianodummer@cultura.com.br`) to send malicious spam from the victim's host.

## ⚡ Attack Narrative Summary
1.  **Initial Access:** User downloaded `documents.zip` from `attirenepal.com`, containing the weaponized Excel file `chart-1530076591.xls`.
2.  **Execution & C2 Establishment:** File execution led to infection, establishing persistent C2 channels with Cobalt Strike infrastructure.
3.  **Discovery:** Attacker checked the victim's external IP address using the public API `api.apify.org`.
4.  **Impact & Propagation:** The compromised host was used to send malicious spam (malspam) from a hijacked corporate email account.

## 🛠️ Skills Demonstrated
*   **Advanced Network Forensics:** Proficient use of Wireshark filters, packet dissection, and protocol analysis (HTTP/S, TLS, DNS, SMTP).
*   **Threat Intelligence Integration:** Leveraged VirusTotal to pivot from suspicious IPs/domains to confirmed malicious infrastructure.
*   **Attack Chain Analysis:** Connected discrete events across the network to build a coherent timeline and narrative of the intrusion.
*   **Adversary Framework Mapping:** Accurately mapped observed behaviors to specific techniques in the **MITRE ATT&CK framework** (e.g., T1566.001, T1204.002, T1573.002).

## 📋 MITRE ATT&CK Techniques Identified
| Tactic | Technique | Evidence |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 - Phishing: Spearphishing Attachment | Download of `documents.zip` from phishing email. |
| **Execution** | T1204.002 - User Execution: Malicious File | Execution of `chart-1530076591.xls`. |
| **Command & Control** | T1573.002 - Encrypted Channel: Asymmetric Cryptography | HTTPS traffic to malicious domains. |
| **Defense Evasion** | T1036 - Masquerading | C2 server using `ocsp.verisign.com` host header. |
| **Discovery** | T1590 - Gather Victim Network Information | Query to `api.apify.org` for victim's IP. |
| **Impact** | T1566 - Phishing | Malspam sent from hijacked email account. |

## Overall Takeaways
This investigation underscored that a methodical approach to network data can reveal a complete intrusion story. Key lessons included the critical importance of analyzing encrypted traffic (TLS handshakes) and the power of integrating open-source threat intelligence to transform observations into high-confidence findings.

---
**See the full technical analysis:** [detailed_analysis.md](detailed_analysis.md)
