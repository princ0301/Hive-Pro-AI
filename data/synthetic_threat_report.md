# TawasolPay — MDR Advisory: Middle East Threat Watch
## April 2026 — CONFIDENTIAL — SYNTHETIC DATA FOR HIRING ASSESSMENT ONLY

---

## Executive Overview

This advisory covers active threat activity observed in the past 7 days targeting fintech, financial services, and technology firms operating in the Middle East and Gulf Cooperation Council (GCC) region. Intelligence is sourced from our threat hunting infrastructure, commercial threat feeds, and public sources including CISA KEV and MITRE ATT&CK.

**Risk level: HIGH.** Three active ransomware-associated campaigns have been observed exploiting vulnerabilities present in common fintech infrastructure. At least two of these campaigns have confirmed victims in the UAE this month.

---

## Active Campaigns — Detailed

### 1. CrimsonJackal — "Gateway Breaker"
**Target profile:** Financial services and fintech firms, UAE and Saudi Arabia  
**Exploit chain:** CVE-2024-21762 (Fortinet SSL-VPN heap overflow) → CVE-2024-55591 (Fortinet auth bypass)  
**Ransomware:** Yes — LockBit 3.0 variant observed in post-exploitation  
**Confidence:** High — confirmed victim in Dubai this week  

CrimsonJackal is a financially motivated threat actor operating since late 2024. The group achieves initial access via unpatched Fortinet VPN appliances, then moves laterally to domain controllers and backup systems before deploying ransomware. Average dwell time before ransomware deployment is 4–6 days. The group is known to exfiltrate data before encryption for double-extortion leverage.

**IOCs:** Inbound connections from 185.220.x.x/24 range; VPN log entries with empty User-Agent strings; scheduled tasks named "SystemUpdate" or "WinDefend".

---

### 2. RedMantis — "Collaboration Breach"
**Target profile:** Engineering-heavy SaaS and technology firms, MENA region  
**Exploit chain:** CVE-SYN-2026-0004 (Project Management RCE) → CVE-2023-22527 (Confluence OGNL injection) → CVE-2023-22515 (Confluence broken access control)  
**Ransomware:** Yes — Akira ransomware observed  
**Confidence:** High — multiple victims in technology sector this month  

RedMantis focuses on source code theft and supply chain access. After initial access via project management platforms, the group pivots to internal wikis and CI/CD systems to harvest credentials, SSH keys, and deployment secrets. The group has been observed planting backdoors in source code repositories. Ransomware is deployed as a secondary objective after intellectual property theft.

**IOCs:** Large outbound data transfers over port 443 from Jira/Confluence hosts; new admin accounts created after business hours; git clone activity from unknown IPs.

---

### 3. SilentForge — "Build Chain Theft"
**Target profile:** Technology firms with exposed CI/CD infrastructure, Global  
**Exploit chain:** CVE-2024-27198 (JetBrains TeamCity auth bypass) → CVE-2024-23897 (Jenkins file read) → CICD-SYN-001 (exposed build secrets)  
**Ransomware:** No — espionage and IP theft focused  
**Confidence:** High — active campaign, multiple confirmed victims globally  

SilentForge is a sophisticated actor focused on long-term access and intellectual property theft. The group exploits CI/CD infrastructure to access build secrets, private keys, and internal API credentials. Unlike ransomware groups, SilentForge maintains persistent access and harvests credentials over weeks. Detection is difficult as the group mimics normal build activity.

**IOCs:** Unusual service account logins to TeamCity/Jenkins outside business hours; new API tokens created via build automation; secrets accessed from unusual source IPs.

---

### 4. IronVeil — "CitrixBleed Exploitation"
**Target profile:** Financial services with Citrix NetScaler load balancers, Global  
**Exploit chain:** CVE-2023-4966 (Citrix NetScaler session token leak)  
**Ransomware:** Yes — ALPHV/BlackCat observed in post-exploitation  
**Confidence:** High — ongoing mass exploitation since Q4 2023, still active  

IronVeil specialises in harvesting session tokens from vulnerable NetScaler appliances, allowing authentication bypass without credentials. This is especially dangerous where NetScaler is used to protect customer-facing portals, as stolen tokens may bypass MFA. The group sells harvested tokens to ransomware affiliates.

**IOCs:** HTTP GET requests to /oauth/idp/.well-known/openid-configuration with unusual parameters; high volume of 302 redirects in NetScaler logs; anomalous session token reuse from foreign IPs.

---

### 5. WinterViper — "API Gateway Takeover"
**Target profile:** API-first fintech and payment platforms  
**Exploit chain:** CVE-SYN-2026-0011 (API Admin Interface Exposed)  
**Ransomware:** No — financial fraud and data theft focused  
**Confidence:** High — new actor, confirmed activity in Gulf region  

WinterViper targets exposed API gateway admin interfaces. Once access is obtained, the group reconfigures routing rules to intercept payment traffic, inject fraudulent transactions, or exfiltrate API credentials from connected partner integrations. Impact is direct financial loss rather than ransomware.

---

## Threat Intelligence Analyst Notes

**Prioritisation guidance:**  
Vulnerability severity scores (CVSS) alone are insufficient for effective prioritisation. The analyst team recommends weighting the following factors in order:

1. **Internet exposure** — internet-facing assets are first-stage targets in every campaign above
2. **Active exploitation in the wild** — confirmed weaponised exploits dramatically shorten the window before compromise
3. **Ransomware association** — ransomware campaigns cause the most organisational disruption and reputational damage
4. **Business criticality and compliance scope** — payment and identity infrastructure carry regulatory obligations that amplify breach impact
5. **Missing compensating controls** — absence of EDR, MFA, or network segmentation removes the layers that detect and contain attacks

**Intelligence gaps:**  
We do not have complete visibility into NightHarbor's current targeting of backup and storage infrastructure. Organisations should assume their backup systems are being actively profiled and ensure immutability policies are enforced.

---

*This report contains synthetic data generated for hiring assessment purposes. All threat actor names, campaign names, and IOCs are fictional. Do not use for operational security decisions.*
