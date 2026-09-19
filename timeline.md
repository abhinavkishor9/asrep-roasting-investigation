# Lab 81 — Investigation Timeline

## Investigation Date

19 September 2026

## Investigated Host

`DESKTOP-9MMM37V`

## Timeline

| Time | Source | Observation | Significance |
|---|---|---|---|
| 06:54 | PowerShell | `C:\ASREPRoastingLab\Evidence` created | Investigation workspace established |
| 06:54 | PowerShell | Both lab paths returned `True` | Workspace validated |
| 06:54+ | Host configuration | `WORKGROUP`, `PartOfDomain=False`, `DomainRole=0` | Endpoint confirmed as standalone |
| 06:54+ | Kerberos | Windows `klist.exe` executed | Kerberos client state checked |
| 06:54+ | Kerberos | `Cached Tickets: (0)` | No cached tickets in inspected session |
| 06:51:40–06:51:41 | Wazuh | Multiple `net.exe` account discovery detections | Reconnaissance-related activity observed |
| 06:52:24–06:52:25 | Wazuh | Suspicious Windows command shell detections | Command-shell activity observed |
| 07:03:07 | Wazuh | Additional suspicious command-shell detections | Additional command execution observed |
| 07:03:17 | Sysmon EID 3 | Multiple network connection events | Network telemetry available |
| 07:05:25–07:05:26 | Sysmon EID 3 | Multiple network connection events | Network telemetry available |
| 07:06:02–07:07:15 | Sysmon EID 1 | Multiple process creation events | Process telemetry available |
| 07:07:36–07:07:37 | Sysmon EID 3 | Multiple network connection events | Additional network telemetry |
| Investigation time | Security log | No local Event ID 4768 | Required DC-side Kerberos telemetry unavailable |
| Investigation time | Security log | No local Event ID 4771 | No local Kerberos preauthentication-failure telemetry |
| Investigation time | PowerShell | `Get-ADUser` unavailable | Active Directory module unavailable |
| Investigation time | AD validation | `DONT_REQ_PREAUTH` could not be checked | Candidate account configuration unavailable |

---

## Detailed Timeline

### 06:54 — Investigation Workspace Created

The investigation directory was created:

```text
C:\ASREPRoastingLab
```

with the evidence directory:

```text
C:\ASREPRoastingLab\Evidence
```

Both paths were successfully validated.

---

### Host Validation

The endpoint reported:

```text
Name         : DESKTOP-9MMM37V
Domain       : WORKGROUP
PartOfDomain : False
DomainRole   : 0
```

This established that the system was not part of an Active Directory domain.

This finding became the primary limitation for the Kerberos investigation.

---

### Kerberos Client Validation

The native Windows `klist.exe` utility was executed.

The ticket cache returned:

```text
Cached Tickets: (0)
```

This establishes the state of the inspected logon session at collection time.

No conclusion was made about Kerberos activity elsewhere.

---

### 06:51–06:52 — Wazuh Account Discovery and Command-Shell Activity

Wazuh recorded multiple detections including:

```text
A net.exe account discovery command was initiated
```

and:

```text
Suspicious Windows cmd shell execution
Windows command prompt started by an abnormal process
```

These events provide endpoint reconnaissance and command-execution context.

They do not establish AS-REP Roasting.

---

### 07:03 — Additional Wazuh Activity

Wazuh recorded additional suspicious command-shell activity around:

```text
07:03:07
```

The event was retained as contextual evidence.

No corresponding Domain Controller-side Kerberos evidence was available.

---

### 07:03–07:07 — Sysmon Network Activity

Sysmon Event ID 3 returned multiple network connection events.

Observed timestamps included:

```text
07:03:17
07:05:25
07:05:26
07:07:36
07:07:37
```

The events confirm that network telemetry was being collected.

The available output did not establish an AS-REP-related connection.

---

### 07:06–07:07 — Sysmon Process Activity

Sysmon Event ID 1 returned multiple process creation events between approximately:

```text
07:06:02
and
07:07:15
```

The displayed event messages were abbreviated.

No specific process was therefore associated with AS-REP Roasting.

---

## Missing Evidence

The following evidence required for a stronger AS-REP Roasting investigation was unavailable:

```text
Event ID 4768
PreAuthType = 0
TargetUserName
ClientAddress
DONT_REQ_PREAUTH account validation
```

The missing evidence prevents the investigation from establishing the core AS-REP Roasting chain.

---

## Evidence Sequence

The observed investigation sequence is:

```text
Standalone WORKGROUP endpoint
        ↓
Kerberos cache checked
        ↓
No cached tickets
        ↓
Wazuh account discovery activity
        ↓
Wazuh command-shell activity
        ↓
Sysmon process activity
        ↓
Sysmon network activity
        ↓
No local 4768
        ↓
No local 4771
        ↓
No AD account enumeration
        ↓
AS-REP Roasting not confirmed
```

---

## Final Assessment

### Classification: Inconclusive

The available endpoint telemetry demonstrates that monitoring is functioning, but the required Active Directory/Kerberos telemetry was not available on this workstation.

The timeline contains only observed events and documented investigation results.

No artificial 4768, 4771, account, process, or network events were added to create an attack narrative.

The investigation therefore ends with:

```text
AS-REP Roasting could not be confirmed
because the required Active Directory/Kerberos
telemetry was unavailable on the investigated endpoint.
```
```
