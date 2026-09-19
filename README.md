# Lab 81 — AS-REP Roasting Investigation

## Overview

This lab investigates **AS-REP Roasting**, an Active Directory credential-access technique that targets accounts configured without Kerberos preauthentication.

The investigation focuses on validating the telemetry required to identify AS-REP Roasting rather than creating artificial Kerberos events.

The expected investigation chain is:

```text
4768
  ↓
PreAuthenticationType = 0
  ↓
Target account
  ↓
DONT_REQ_PREAUTH validation
  ↓
Client/source host
  ↓
Request pattern
  ↓
Sysmon process and network context
  ↓
Wazuh telemetry
  ↓
Evidence-based classification
```

The lab also examines Event ID 4771 and documents its limitations. The absence of Event ID 4771 does not rule out AS-REP Roasting because 4771 is associated with Kerberos preauthentication failures and is not generated when the account does not require Kerberos preauthentication.

---

## Lab Environment

| Component | Value |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| Operating System | Windows |
| Domain | `WORKGROUP` |
| Domain Joined | No |
| Domain Role | `0` |
| Sysmon | Installed |
| Wazuh Agent | Installed |
| Active Directory PowerShell Module | Unavailable |
| Kerberos Ticket Cache | 0 cached tickets |
| Investigation Directory | `C:\ASREPRoastingLab` |

---

## Objectives

- Validate whether the investigated endpoint is part of an Active Directory environment.
- Check the local Kerberos ticket cache.
- Determine whether Event ID 4768 is available.
- Determine whether Event ID 4771 is available.
- Understand how `PreAuthType = 0` is used during AS-REP Roasting investigations.
- Determine whether accounts with `DONT_REQ_PREAUTH` can be validated.
- Review Sysmon process and network telemetry for supporting context.
- Review Wazuh telemetry for related endpoint activity.
- Distinguish telemetry collection limitations from detection gaps.
- Classify the investigation using only observed evidence.

---

## AS-REP Roasting Concept

AS-REP Roasting targets Active Directory accounts for which Kerberos preauthentication is disabled.

When a Kerberos Authentication Service issues a TGT, Event ID 4768 can provide important investigation fields such as:

- `TargetUserName`
- `TargetDomainName`
- `ClientAddress`
- `PreAuthType`
- `TicketEncryptionType`

A `PreAuthType` value of `0` is particularly relevant because it indicates that Kerberos preauthentication was not used.

However, `PreAuthType = 0` is an investigation indicator and does not automatically prove malicious activity.

The account configuration, requesting host, request pattern, and supporting telemetry must also be considered.

---

## Investigation Approach

The investigation was performed in the following stages:

1. Created a dedicated investigation directory.
2. Validated the host's domain membership and domain role.
3. Checked the Windows Kerberos ticket cache.
4. Searched the local Security log for Event ID 4768.
5. Searched the local Security log for Event ID 4771.
6. Attempted to identify accounts configured with `DONT_REQ_PREAUTH`.
7. Reviewed Sysmon Event ID 1 for process context.
8. Reviewed Sysmon Event ID 3 for network context.
9. Reviewed Wazuh telemetry for command execution and account discovery.
10. Assessed whether the available evidence was sufficient to confirm AS-REP Roasting.

---

## Key Findings

### 1. The Endpoint Is Not Domain Joined

The workstation reported:

```text
Name         : DESKTOP-9MMM37V
Domain       : WORKGROUP
PartOfDomain : False
DomainRole   : 0
```

This establishes that the investigated system is a standalone WORKGROUP workstation.

This is the primary environmental limitation for the investigation because the required Kerberos Authentication Service telemetry is generated on Domain Controllers.

---

### 2. The Kerberos Ticket Cache Was Empty

The native Windows `klist.exe` executable was explicitly used:

```powershell
& "$env:SystemRoot\System32\klist.exe"
```

and:

```powershell
& "$env:SystemRoot\System32\klist.exe" tickets
```

The result was:

```text
Current LogonId is 0:0x47dc3

Cached Tickets: (0)
```

This establishes that no cached Kerberos tickets were present in the inspected logon session at the time of collection.

An empty ticket cache does not prove that Kerberos activity did not occur elsewhere.

---

### 3. No Local Event ID 4768 Evidence Was Available

The local Security log was queried for Event ID 4768.

The result was:

```text
No local Security Event ID 4768 events found.
```

An XML-based query attempting to extract `PreAuthType` also returned:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

Therefore, no local 4768 event was available for analysis.

Because Event ID 4768 is Domain Controller/KDC-side telemetry, its absence from this standalone workstation does not establish that no Kerberos activity occurred elsewhere.

---

### 4. No Local Event ID 4771 Evidence Was Available

The local Security log was queried for Event ID 4771.

No events were returned.

This does not rule out AS-REP Roasting.

Event ID 4771 is associated with Kerberos preauthentication failures on Domain Controllers. Accounts configured not to require Kerberos preauthentication do not generate the normal preauthentication-failure event.

Therefore:

```text
No 4771
    ≠
No AS-REP Roasting
```

---

### 5. Active Directory Account Enumeration Was Not Possible

The following command was attempted:

```powershell
Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" `
-Properties UserAccountControl |
Select-Object SamAccountName, UserPrincipalName, UserAccountControl
```

PowerShell returned:

```text
Get-ADUser: The term 'Get-ADUser' is not recognized as a name of a cmdlet, function, script file, or executable program.
```

The ActiveDirectory PowerShell module is therefore unavailable.

In addition, the endpoint is not domain joined and does not provide a local Active Directory environment from which domain accounts could be enumerated.

The account configuration check was therefore treated as **not applicable to this endpoint**.

---

### 6. Sysmon Process Telemetry Was Available

Sysmon Event ID 1 returned multiple process creation events.

The observed output included entries such as:

```text
Process Create:...
```

This confirms that process creation telemetry is available.

However, the displayed output was abbreviated and did not provide enough detail to associate a particular process with AS-REP Roasting.

Process telemetry was therefore treated as supporting evidence only.

---

### 7. Sysmon Network Telemetry Was Available

Sysmon Event ID 3 returned multiple network connection events.

Observed timestamps included:

```text
19-09-2026 06:57:10
19-09-2026 06:59:14
19-09-2026 07:01:15
19-09-2026 07:03:17
19-09-2026 07:05:25
19-09-2026 07:05:26
19-09-2026 07:07:36
19-09-2026 07:07:37
```

This confirms that network telemetry is functioning.

However, the available output does not establish a suspicious Kerberos request or identify a specific Domain Controller connection associated with AS-REP Roasting.

Network telemetry was therefore treated as supporting evidence only.

---

### 8. Wazuh Telemetry Was Available

Wazuh showed activity from:

```text
DESKTOP-9MMM37V
```

Observed detections included:

```text
Suspicious Windows cmd shell execution
Windows command prompt started by an abnormal process
A net.exe account discovery command was initiated
```

The `net.exe` account discovery activity is relevant as endpoint reconnaissance.

However, account discovery alone does not establish AS-REP Roasting.

The required correlation:

```text
4768
+
PreAuthType = 0
+
Target account
+
DONT_REQ_PREAUTH
```

was not available.

Therefore, the Wazuh activity was retained as contextual evidence and was not classified as AS-REP Roasting.

---

## Evidence Summary

| Evidence | Observation | Interpretation |
|---|---|---|
| Host role | `WORKGROUP`, `DomainRole 0` | Standalone endpoint |
| Domain membership | `False` | Not part of AD domain |
| Kerberos cache | 0 tickets | No cached tickets at collection time |
| Event ID 4768 | Not found locally | Required DC-side telemetry unavailable |
| Event ID 4771 | Not found locally | No local Kerberos failure telemetry |
| ActiveDirectory module | Not available | AD account enumeration unavailable |
| `DONT_REQ_PREAUTH` | Not validated | Candidate account configuration unknown |
| Sysmon Event ID 1 | Available | Process telemetry functioning |
| Sysmon Event ID 3 | Available | Network telemetry functioning |
| Wazuh | Available | Endpoint activity detected |
| AS-REP Roasting | Not confirmed | Insufficient evidence |

---

## Final Assessment

### Classification: Inconclusive

AS-REP Roasting could not be confirmed on the investigated endpoint.

The primary reason is an environmental and telemetry limitation:

```text
WORKGROUP
    ↓
Not domain joined
    ↓
No local Domain Controller/KDC telemetry
    ↓
No local 4768
    ↓
No local 4771
    ↓
No Active Directory account enumeration
    ↓
DONT_REQ_PREAUTH cannot be validated
    ↓
AS-REP Roasting cannot be confirmed
```

The available Sysmon and Wazuh telemetry provides useful endpoint context, but it does not contain the Domain Controller-side evidence required to establish an AS-REP Roasting investigation.

---

## Evidence Collected

The investigation workspace was created at:

```text
C:\ASREPRoastingLab
```

Evidence directory:

```text
C:\ASREPRoastingLab\Evidence
```

Evidence files created or attempted during the investigation included:

```text
01-host-role.txt
02-klist.txt
03-4768-status.txt
05-ad-module-status.txt
06-domain-status.txt
```

A 4768 XML sample could not be collected because no local 4768 event was available.

---

## Lessons Learned

### Validate the Environment First

Before interpreting a security event, determine whether the investigated system is actually capable of generating that event.

### 4768 Is Central to the Investigation

A proper AS-REP Roasting investigation depends heavily on Domain Controller-side Kerberos Authentication Service telemetry.

### 4771 Has Important Limitations

The absence of Event ID 4771 cannot be used to exclude AS-REP Roasting.

### Account Configuration Matters

`PreAuthType = 0` becomes much more meaningful when the corresponding account can also be validated as having `DONT_REQ_PREAUTH`.

### Endpoint Telemetry Is Supporting Evidence

Sysmon process and network events can provide useful context but cannot substitute for missing Domain Controller Kerberos telemetry.

### Collection and Detection Are Different

If Wazuh receives a 4768 event but does not generate an alert, that represents a detection-rule problem.

If Wazuh never receives the 4768 event, that represents a collection or forwarding problem.

---

## Investigation Principle

> Follow the evidence, not the assumption.

```text
Artifact ≠ Proof

Telemetry available
        ↓
Validate source
        ↓
Correlate evidence
        ↓
Assess confidence
        ↓
Classify
```

This lab intentionally does not generate artificial 4768 or 4771 events to create a successful attack narrative.

The absence of the required Active Directory telemetry is itself a documented investigation finding.
