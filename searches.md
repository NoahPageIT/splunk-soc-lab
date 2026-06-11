# SOC Detection Searches (SPL)

Splunk Processing Language searches for monitoring the Windows Security event log.
All assume the `[WinEventLog://Security]` input is feeding `index=main`.

## Authentication / brute force

**All failed logons (24h)**
```spl
index=main EventCode=4625
```

**Failed logons ranked by targeted account** — spot a targeted account
```spl
index=main EventCode=4625
| stats count by Account_Name
| sort -count
```

**Brute-force detection** — 5+ failures from one account in a 5-minute window (MITRE **T1110**)
```spl
index=main EventCode=4625
| bucket _time span=5m
| stats count by _time, Account_Name
| where count >= 5
| sort -count
```

**Possible password spray** — one source hitting many accounts
```spl
index=main EventCode=4625
| stats dc(Account_Name) as accounts_targeted by Source_Network_Address
| where accounts_targeted >= 5
```

**Successful logon after repeated failures** — possible cracked credential
```spl
index=main (EventCode=4624 OR EventCode=4625)
| transaction Account_Name maxspan=10m
| search EventCode=4625 EventCode=4624
```

## Account & privilege abuse

**New account created** (MITRE **T1136**)
```spl
index=main EventCode=4720 | table _time Account_Name
```

**Privileged logon — admin rights assigned** (MITRE **T1078.003**)
```spl
index=main EventCode=4672 | stats count by Account_Name
```

## Anti-forensics

**Security audit log cleared** (MITRE **T1070.001**) — high-severity, attacker covering tracks
```spl
index=main EventCode=1102
```

## Reference — key Windows Security event IDs
| Event ID | Meaning |
|----------|---------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 / 4647 | Logoff |
| 4672 | Special privileges assigned (admin) |
| 4720 | User account created |
| 4740 | Account locked out |
| 1102 | Security audit log cleared |
