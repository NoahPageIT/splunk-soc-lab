# 📊 Splunk SOC Lab — Windows Security Monitoring

A hands-on **Security Operations Center lab built on Splunk Enterprise**: ingest the Windows Security event log, detect attacker behavior with SPL searches mapped to **MITRE ATT&CK**, and visualize it all on a real-time **SOC Overview dashboard**.

Built to demonstrate practical SIEM skills — data onboarding, SPL detection searches, alert thinking, and dashboarding — the day-to-day work of a SOC analyst in the industry-standard tool.

> Companion to [Argus SIEM](https://github.com/NoahPageIT/argus-siem): the same brute-force attack is detected by a custom-built SIEM **and** reproduced here in Splunk — one attack, two SIEMs.

---

## The SOC Overview dashboard
A single pane of glass over Windows authentication activity (`dashboards/soc_overview.xml`):

**KPI row** — Failed Logons (24h, color-thresholded) · Successful Logons · Privileged Logons · Audit-Log-Cleared (red if non-zero)

**Detection panels:**
- **Failed Logon Trend** — column chart of failures over time (spikes = brute force)
- **Top Targeted Accounts** — which accounts are being hammered
- **Logon Activity: Success vs Failure** — baseline vs anomaly
- **Recent Failed Logons** — live triage table (time, account, logon type, source)

> Add a screenshot at `docs/dashboard.png` once you've populated it with data.

---

## Detections (see `searches.md`)
| Detection | Event ID(s) | MITRE ATT&CK |
|-----------|-------------|--------------|
| Brute-force logon (5+ failures / 5 min) | 4625 | **T1110** Brute Force |
| Password spray (1 source → many accounts) | 4625 | **T1110** |
| Cracked credential (success after failures) | 4625 → 4624 | **T1110 / T1078** |
| New account created | 4720 | **T1136** Create Account |
| Privileged logon | 4672 | **T1078.003** Valid Accounts |
| Audit log cleared | 1102 | **T1070.001** Indicator Removal |

---

## Setup
1. **Install Splunk Enterprise** (free trial → Splunk Free).
2. **Onboard the Windows Security log** — copy `inputs.conf` into `%SPLUNK_HOME%\etc\system\local\` and restart Splunk (or use **Settings → Add Data → Local Event Logs → Security**).
3. **Import the dashboard** — Splunk Web → **Dashboards → Create New → Source**, paste `dashboards/soc_overview.xml`. (Or `POST` it to `/servicesNS/<user>/search/data/ui/views`.)
4. Open **SOC Overview** and start hunting.

### Validate it
Generate real failed-logon events (e.g., with the [Argus](https://github.com/NoahPageIT/argus-siem) `simulate-attack.ps1`) and watch the **Failed Logon Trend** spike and the offending account climb the **Top Targeted Accounts** panel.

---

## Tech
- **Splunk Enterprise** + **SPL** (Search Processing Language)
- **Simple XML** dashboard
- Windows Security event log onboarding
- MITRE ATT&CK-aligned detections

*Defensive security / SOC training on a system I own.*
