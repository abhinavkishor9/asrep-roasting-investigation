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

