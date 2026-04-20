[← Back to Main Portfolio](https://github.com/barryhuriwaka/cybersecurity-portfolio)

<div align="center">

# 🔥 CYBERSECURITY CASE STUDY 003  
### **Phishing Attack • Credential Harvesting • MFA Protection**

</div>

---

# CASE STUDY 003 — Phishing & Credential Harvesting Attempt  
**Status:** Contained  
**Severity:** High  
**Category:** Email Threat / Identity Compromise  

---

## 🧭 Executive Summary  

A targeted phishing email impersonating Microsoft Support attempted to lure a user into entering credentials into a fake login page.  
Shortly after submission, the attacker attempted to authenticate from Vietnam, triggering MFA prompts.

---

## 🎯 Objectives  

- Determine whether credentials were stolen  
- Identify attacker sign‑in attempts  
- Assess MFA bypass attempts  
- Contain the account  
- Provide user education  

---

## 👤 User & Alert Details  

| Field | Details |
|-------|---------|
| **User** | michael.ross@brisbanetech.com.au |
| **Role** | Sales Coordinator |
| **Suspicious Location** | Hanoi, Vietnam |
| **Alert Source** | Microsoft Defender for Office 365 |

---

## 🔍 Initial Indicators  

- User clicked phishing URL  
- Credential harvesting detected  
- MFA prompts triggered  
- Foreign login attempts  
- User reported suspicious notifications  

---

## 📊 KQL Queries Used  

```kusto
EmailEvents
| where ThreatTypes contains "CredentialPhishing"
```

```kusto
SigninLogs
| where UserPrincipalName == "michael.ross@brisbanetech.com.au"
```

---

## 📁 Evidence Summary  

### Phishing Email Indicators  

- Display name spoofing  
- Fake Microsoft login page  
- Credential harvesting URL  
- Urgent password expiry theme  

---

## 🧠 Analyst Assessment  

### Indicators of Compromise  

- Phishing URL click  
- Credential submission  
- Foreign login attempts  
- MFA fatigue attempt  

### Likely Attack Chain  

1. User receives phishing email  
2. User enters credentials  
3. Attacker attempts login  
4. MFA blocks access  
5. SOC alerted  

---

## 🛡️ Containment Actions  

- Forced password reset  
- Revoked sessions  
- Blocked IP range  
- Verified no mailbox rules  
- User education  

---

## 🧬 MITRE ATT&CK Mapping  

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Phishing | T1566 |
| Credential Access | Credential Harvesting | T1555 |
| Credential Access | MFA Fatigue | T1110.003 |

---

## 🕒 Timeline (AEST)  

| Time | Event |
|------|--------|
| 09:12 | Phishing email delivered |
| 09:13 | User clicks link |
| 09:14 | Login attempt from Vietnam |
| 09:20 | User reports MFA prompts |
| 09:25 | SOC begins investigation |

---

## 📁 Repo Structure  

```
/diagrams
/logs
/queries
/reports
/artifacts
README.md
```

---

[← Previous Case Study — Business Email Compromise](https://github.com/barryhuriwaka/Business-Email-Compromise)  
[Next Case Study → Case Study 004 — Malware Execution on Endpoint](https://github.com/barryhuriwaka/Malware-Execution-Endpoint)
[[← Back to Main Portfolio](https://github.com/barryhuriwaka/cybersecurity-portfolio)

