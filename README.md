# NetSentinel

A lightweight network intrusion detection and response system using Snort, custom detection rules, Python-based threat analysis, and a web dashboard.

---

## Current Phase

**Phase 1 — Project Setup**

The project foundation has been established. All subsequent functionality will be implemented incrementally across the phases listed below.

---

## Planned Architecture

```
Network Traffic
      ↓
    Snort
      ↓
Detection Rules
      ↓
Alert Processing
      ↓
Threat Scoring
      ↓
Response Engine
      ↓
Security Dashboard
```

---

## Planned Technologies

- **Snort** — Network packet inspection and rule-based alerting
- **Python** — Core engine, alert processing, and threat scoring
- **Flask** — Backend API and dashboard server
- **SQLite** — Lightweight local database for alert storage
- **HTML / CSS / JavaScript** — Frontend dashboard
- **Chart.js** — Real-time data visualization

---

## Development Phases

| Phase | Description        | Status      |
|-------|--------------------|-------------|
| 1     | Project Setup      | ✅ Complete  |
| 2     | Snort Configuration| ✅ Complete  |
| 3     | Attack Simulation  | ⬜ Pending   |
| 4     | Alert Parser       | ⬜ Pending   |
| 5     | Threat Scoring     | ⬜ Pending   |
| 6     | Response Engine    | ⬜ Pending   |
| 7     | Dashboard          | ⬜ Pending   |
| 8     | Final Validation   | ⬜ Pending   |

---

## Project Structure

```
NetSentinel/
├── snort/
│   ├── rules/          # Snort detection rules (Phase 2)
│   └── config/         # Snort configuration files (Phase 2)
├── engine/             # Threat analysis engine (Phases 4–6)
├── backend/            # Flask API server
│   └── app.py          # Entry point — Phase 1 health check
├── database/           # SQLite schema and migrations (Phase 4)
├── dashboard/          # Frontend dashboard (Phase 7)
├── tests/              # Test suite (added incrementally)
├── README.md
└── requirements.txt
```

---

## Running the Backend (Phase 1)

```bash
pip install -r requirements.txt
python backend/app.py
```

Health check:

```bash
curl http://localhost:5000/health
```

Expected response:

```json
{
  "status": "ok",
  "service": "NetSentinel"
}
```

---

## Phase 2 — Snort Configuration

### Environment

| Item | Details |
|---|---|
| **OS** | Windows 11 Home (10.0.26200) |
| **Snort Version** | 2.9.20 |
| **Network Interface** | Wi-Fi — MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter |
| **Interface selected because** | Only active adapter on the machine (`Status: Up`) |

### Configuration Files Created

| File | Purpose |
|---|---|
| `snort/config/netsentinel.conf` | Main Snort configuration — sets HOME_NET, preprocessors, output plugins, and loads our rules |
| `snort/config/start_snort.ps1` | PowerShell helper script to start Snort or run in config-test mode |
| `snort/rules/netsentinel.rules` | Custom detection rules for Phase 2 |

### Custom Rules

| SID | Alert Message | Severity | Classtype |
|---|---|---|---|
| 9000001 | `[NetSentinel] ICMP Activity Detected` | LOW | `network-scan` |
| 9000002 | `[NetSentinel] Suspicious TCP Connection Attempt on Port 4444` | MEDIUM | `attempted-recon` |
| 9000003 | `[NetSentinel] Suspicious HTTP Test Pattern Detected` | HIGH | `web-application-attack` |

### Alert Logging

Alerts are written to two locations:

- `C:\Snort\log\netsentinel_alerts.txt` — Human-readable fast alert format (one line per alert)
- `C:\Snort\log\netsentinel_unified2.log` — Binary unified2 format (for future parser integration)

Each alert contains: timestamp, source IP/port, destination IP/port, protocol, alert message, and rule SID.

### Running Snort

**Test configuration (validate only, no live capture):**

```powershell
# Run as Administrator
.\snort\config\start_snort.ps1 -TestMode
```

**Start live monitoring:**

```powershell
# Run as Administrator
.\snort\config\start_snort.ps1
```

### Snort Installation (Windows)

Snort must be manually installed before running:

1. Download `Snort_2_9_20_Installer.x64.exe` from https://www.snort.org/downloads
2. Install to the default path `C:\Snort`
3. Install **Npcap** (packet capture driver) from https://npcap.com/
4. Run `start_snort.ps1` as Administrator

> **Note:** Snort on Windows requires Npcap (or WinPcap) to capture live traffic.

Expected response:

```json
{
  "status": "ok",
  "service": "NetSentinel"
}
```
