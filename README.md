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
| 3     | Attack Simulation  | ✅ Complete  |
| 4     | Alert Parser       | ✅ Complete  |
| 5     | Threat Scoring     | ✅ Complete  |
| 6     | Response Engine    | ✅ Complete  |
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

---

## Phase 3 — Controlled Attack Simulation

### Overview

NetSentinel Phase 3 verified that the Snort intrusion detection configuration accurately detects traffic matching all three custom rules (ICMP, TCP port 4444, and HTTP test pattern). All simulation traffic was generated safely against controlled local infrastructure (`127.0.0.1`).

### Test Suite Components

| File | Description |
|---|---|
| `tests/test_http_server.py` | Minimal local HTTP server on port `8080` for SID 9000003 testing |
| `tests/run_tests.ps1` | PowerShell test generator for safe local traffic simulation |
| `tests/attack_simulation.md` | Detailed attack simulation evidence log |

### Test Results

| Test Case | SID | Message | Traffic Type | Status |
|---|---|---|---|---|
| **ICMP Activity** | `9000001` | `[NetSentinel] ICMP Activity Detected` | Ping to `127.0.0.1` | ✅ PASS |
| **TCP Port 4444** | `9000002` | `[NetSentinel] Suspicious TCP Connection Attempt on Port 4444` | TCP connection to `127.0.0.1:4444` | ✅ PASS |
| **HTTP Test Pattern** | `9000003` | `[NetSentinel] Suspicious HTTP Test Pattern Detected` | HTTP GET `/netsentinel-test` to `127.0.0.1:8080` | ✅ PASS |

### How to Run Attack Simulation

1. Start Snort in live capture mode on loopback adapter:
   ```powershell
   & "C:\Snort\bin\snort.exe" -c "snort\config\netsentinel.conf" -i 8 -A fast -l "C:\Snort\log"
   ```
2. Start test HTTP server:
   ```powershell
   python tests/test_http_server.py 8080
   ```
3. Execute controlled attack simulation:
   ```powershell
   .\tests\run_tests.ps1 -Test All -TargetIP 127.0.0.1
   ```
4. Verify alert generation in `C:\Snort\log\netsentinel_alerts.txt`.

---

## Phase 4 — Alert Parser

### Overview

NetSentinel Phase 4 implements the Python Snort alert parsing module. It reads raw Snort `alert_fast` logs and converts them into structured Python objects for downstream threat analysis.

```text
Snort alert log
      ↓
alert_parser.py
      ↓
Structured alert objects
```

### Extracted Fields

Each parsed alert contains:
- **`timestamp`**: Capture timestamp string (e.g. `08/14-22:36:30.977554`)
- **`sid`**: Snort Rule ID integer (e.g. `9000001`)
- **`revision`**: Rule revision integer (e.g. `1`)
- **`message`**: Human-readable alert description
- **`classification`**: Snort classtype category
- **`priority`**: Severity priority integer (`1` = High, `2` = Medium, `3` = Low)
- **`protocol`**: Transport/network protocol (`ICMP`, `TCP`, `UDP`)
- **`source_ip`** & **`source_port`**: Originating IP and port (`None` for ICMP)
- **`destination_ip`** & **`destination_port`**: Target IP and port (`None` for ICMP)

### Key Files

- `engine/alert_parser.py` — Core regex parser and stateful log reader
- `engine/run_parser.py` — CLI demonstration script
- `tests/test_alert_parser.py` — Automated unit tests for ICMP, TCP, HTTP, and malformed inputs

### Running the Parser & Tests

```bash
# Run unit tests
python -m pytest tests/test_alert_parser.py -v

# Run alert parser demonstration
python engine/run_parser.py
```

---

## Phase 5 — Threat Scoring

### Overview

NetSentinel Phase 5 implements the deterministic Threat Scoring Engine. It calculates a 0–100 threat score, risk category, and plain-language explanation for every parsed alert.

```text
Snort Alert
    ↓
Alert Parser
    ↓
Base Score
    ↓
Context Modifiers
    ↓
Final Score
    ↓
Risk Level
```

### Risk Classification Matrix

| Score Range | Risk Level |
|:---:|:---:|
| 0 – 29 | **LOW** |
| 30 – 59 | **MEDIUM** |
| 60 – 79 | **HIGH** |
| 80 – 100 | **CRITICAL** |

### NetSentinel Rule Scoring Matrix

| SID | Alert Message | Calculation | Final Score | Risk Level |
|---|---|---|:---:|:---:|
| **9000001** | ICMP Activity Detected | Base `30` | `30` | **MEDIUM** |
| **9000002** | Suspicious TCP Connection (Port 4444) | Base `50` + Port 4444 (`+10`) | `60` | **HIGH** |
| **9000003** | Suspicious HTTP Test Pattern | Base `70` + HTTP TCP (`+5`) | `75` | **HIGH** |

### Key Files

- `engine/threat_score.py` — Core threat scoring and risk evaluation logic
- `engine/run_scoring.py` — CLI demonstration script
- `tests/test_threat_score.py` — Unit test suite for threat scoring rules & boundary clamping

### Running Threat Scoring & Tests

```bash
# Run all unit tests (Phases 4 & 5)
python -m pytest tests/ -v

# Run threat scoring demonstration
python engine/run_scoring.py
```

---

## Phase 6 — Response Engine

### Overview

NetSentinel Phase 6 implements the application-level Response Engine. It receives scored alerts from Phase 5 and executes deterministic, application-level responses (`LOG`, `FLAG`, `SUSPICIOUS`, `SIMULATED_BLOCK`, `ALREADY_BLOCKED`).

```text
Scored Alert
      ↓
Response Engine
      ↓
Risk Level
      ↓
Application-Level Response
```

> **Safety Notice:** NetSentinel currently uses an application-level simulated response mechanism. It does not modify the operating system firewall or perform real IP blocking.

### Response Policy Matrix

| Risk Level | Response Action | Status Code | Policy Description |
|:---:|:---:|:---:|---|
| **LOW** | `LOG` | `RECORDED` | Low-risk activity logged into history. |
| **MEDIUM** | `FLAG` | `FLAGGED` | Medium-risk activity flagged for monitoring. |
| **HIGH** | `SUSPICIOUS` | `MARKED_SUSPICIOUS` | Source IP added to in-memory `suspicious_ips` set. |
| **CRITICAL** | `SIMULATED_BLOCK` | `BLOCKED_SIMULATED` | Source IP added to in-memory `blocked_ips` set. |
| **CRITICAL** *(Duplicate)* | `ALREADY_BLOCKED` | `BLOCKED_SIMULATED` | Duplicate CRITICAL alert; source IP already in blocklist. |

### Key Features

- **In-Memory Tracking**: Maintains `suspicious_ips`, `blocked_ips`, and `response_history`.
- **Duplicate Suppression**: Prevents duplicate IP entries in `blocked_ips` set on repeated CRITICAL alerts.
- **Localhost Safety**: Loopback (`127.0.0.1`) alerts are safely recorded without system or network impact.

### Key Files

- `engine/response_engine.py` — Response engine class and in-memory IP tracker
- `engine/run_response.py` — Complete end-to-end pipeline demonstration script
- `tests/test_response_engine.py` — Unit test suite for response mapping, blocklists, and safety

### Running Response Engine & Complete Test Suite

```bash
# Run all unit tests (Phases 4, 5 & 6)
python -m pytest tests/ -v

# Run complete pipeline demonstration (Parser -> Scoring -> Response)
python engine/run_response.py
```




