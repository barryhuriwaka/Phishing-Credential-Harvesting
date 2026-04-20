# CASE STUDY 003 — Phishing & Credential Harvesting Attempt  
**Status:** Contained  
**Severity:** High  
**Category:** Email Threat / Identity Compromise / Social Engineering  

---

## 🧭 Executive Summary  
A targeted phishing email impersonating Microsoft Support attempted to lure a user into entering their credentials into a fake Microsoft login page.  
Shortly after the user submitted their credentials, the attacker attempted to authenticate from Vietnam, triggering MFA prompts while the user was offline.

Investigation confirmed:  
- A credential harvesting phishing email  
- User clicked the link and entered credentials  
- Attacker attempted MFA bypass  
- Multiple failed sign‑ins from a foreign IP  
- No successful compromise due to MFA enforcement  

The incident was contained before account takeover occurred.

---

## 🎯 Objectives  
- Determine whether the phishing email resulted in credential theft  
- Identify attacker sign‑in attempts  
- Assess whether MFA was bypassed  
- Contain the account and prevent further misuse  
- Provide user education and long‑term recommendations  

---

## 👤 User & Alert Details  

| Field | Details |
|-------|---------|
| **User** | michael.ross@brisbanetech.com.au |
| **Role** | Sales Coordinator |
| **Normal Location** | Brisbane, QLD |
| **Suspicious Location** | Hanoi, Vietnam |
| **Alert Source** | Microsoft Defender for Office 365 |
| **Alert Type** | User clicked phishing link |
| **Authentication** | MFA Enabled |

---

## 🔍 Initial Indicators  
- User clicked a known phishing URL  
- Defender flagged credential harvesting behaviour  
- Sign‑in attempts from Vietnam  
- MFA prompts triggered while user was offline  
- User reported “strange login notifications”  

---

## 📊 KQL Queries Used  

### **1. Phishing Click Events**
```kql
EmailEvents
| where RecipientEmailAddress == "michael.ross@brisbanetech.com.au"
| where ThreatTypes contains "CredentialPhishing"
| project Timestamp, SenderFromAddress, Subject, ThreatTypes, Url
```

### **2. Sign‑In Attempts After Click**
```kql
SigninLogs
| where UserPrincipalName == "michael.ross@brisbanetech.com.au"
| project TimeGenerated, IPAddress, Location, ResultType, ResultDescription
```

### **3. MFA Prompt Activity**
```kql
SigninLogs
| where UserPrincipalName == "michael.ross@brisbanetech.com.au"
| where ResultDescription contains "MFA"
```

---

## 📁 Evidence Summary  

### **Phishing Email Indicators**
```
Sender: Microsoft Account Team <no-reply@microsoftsupport-security.com>
Subject: Action Required: Your Password Will Expire
URL: https://login-microsoft-auth-secure.com/verify
Threat Type: Credential Harvesting
```

### **Suspicious Sign‑In Attempts**
| Time (AEST) | IP | Location | Result |
|-------------|----|----------|--------|
| 09:14 | 113.23.88.201 | Hanoi, Vietnam | Failed |
| 09:15 | 113.23.88.201 | Hanoi, Vietnam | MFA Required |
| 09:16 | 113.23.88.201 | Hanoi, Vietnam | Failed |

### **User Behaviour**
- User clicked phishing link  
- User entered credentials  
- User ignored MFA prompts (correct behaviour)  
- User reported incident promptly  

---

## 🧠 Analyst Assessment  

### **Indicators of Compromise**
- Phishing URL click  
- Credential submission  
- Foreign login attempts  
- MFA fatigue attempt  
- High‑risk user activity flagged  

### **Likely Attack Chain**
1. User receives phishing email  
2. User clicks link and enters credentials  
3. Attacker attempts login from Vietnam  
4. MFA challenge triggered  
5. Attacker fails to bypass MFA  
6. SOC alerted and investigation begins  

**Risk Level:** **High**  
Credential harvesting is a common precursor to full account takeover.

---

## 🛡️ Containment Actions  

### **Immediate**
- Forced password reset  
- Revoked all active sessions  
- Blocked attacker IP range  
- Disabled any suspicious sessions  

### **Investigation**
- Reviewed sign‑in logs  
- Checked for mailbox rule creation  
- Verified no OAuth app consent  
- Confirmed no lateral movement  

### **Recovery**
- Re‑enabled account with MFA  
- User completed phishing awareness refresher  
- Added user to targeted threat protection group  

---

## 🧬 MITRE ATT&CK Mapping  

| Tactic | Technique | ID | Reason |
|--------|-----------|----|--------|
| Initial Access | Phishing | T1566 | User clicked malicious link |
| Credential Access | Credential Harvesting | T1555 | User entered credentials |
| Credential Access | MFA Fatigue | T1110.003 | Attacker attempted MFA bypass |
| Defense Evasion | Valid Accounts | T1078 | Attempted login with stolen creds |
| Reconnaissance | Phishing for Information | T1598 | Email designed to harvest credentials |

---

## 🕒 Timeline (AEST)

| Time | Event |
|------|--------|
| 09:12 | Phishing email delivered |
| 09:13 | User clicks link |
| 09:14 | First login attempt from Vietnam |
| 09:15 | MFA challenge triggered |
| 09:16 | Additional failed login attempts |
| 09:20 | User reports suspicious MFA prompts |
| 09:25 | SOC begins investigation |
| 09:40 | Account secured |

---

## 📁 Recommended Repo Structure  
```
/diagrams
/logs
/queries
/reports
/artifacts
README.md
```
[← Back to Main Portfolio](https://github.com/barryhuriwaka/cybersecurity-portfolio)

