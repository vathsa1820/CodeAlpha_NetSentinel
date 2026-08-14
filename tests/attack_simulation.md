# NetSentinel — Phase 3 Controlled Attack Simulation Report

This document records the controlled attack simulation tests performed for **NetSentinel Phase 3**.

---

## Environment

| Item | Details |
|---|---|
| **Target Infrastructure** | Localhost (`127.0.0.1`) / Controlled Local Test Target |
| **Snort Version** | 2.9.20-WIN64 |
| **Capture Adapter** | Npcap Loopback Adapter (`\Device\NPF_Loopback` - Index 8) |
| **Alert Log Location** | `C:\Snort\log\netsentinel_alerts.txt` |

---

## Test Results Summary

| Test | Target | SID | Classification | Priority / Severity | Status |
|---|---|---|---|---|---|
| **Test 1 — ICMP Detection** | `127.0.0.1` | `9000001` | `network-scan` | Priority 3 (LOW) | ✅ PASS |
| **Test 2 — TCP Detection** | `127.0.0.1:4444` | `9000002` | `attempted-recon` | Priority 2 (MEDIUM) | ✅ PASS |
| **Test 3 — HTTP Detection** | `127.0.0.1:8080` | `9000003` | `web-application-attack` | Priority 1 (HIGH) | ✅ PASS |

---

## Test Execution Details & Evidence

### Test 1 — ICMP Detection

- **Goal**: Generate ICMP echo requests to trigger baseline network monitoring alerts.
- **Traffic Command**: `ping.exe -n 4 127.0.0.1`
- **Expected SID**: `9000001`
- **Status**: **PASS**
- **Logged Alert Evidence**:
  ```text
  08/14-22:36:30.977554  [**] [1:9000001:1] [NetSentinel] ICMP Activity Detected [**] [Classification: Detection of a Network Scan] [Priority: 3] {ICMP} 127.0.0.1 -> 127.0.0.1
  ```

---

### Test 2 — TCP Detection

- **Goal**: Send a TCP SYN connection packet to port 4444 to simulate suspicious reconnaissance activity.
- **Traffic Command**: `[System.Net.Sockets.TcpClient]::new().Connect("127.0.0.1", 4444)`
- **Expected SID**: `9000002`
- **Status**: **PASS**
- **Logged Alert Evidence**:
  ```text
  08/14-22:36:37.072228  [**] [1:9000002:1] [NetSentinel] Suspicious TCP Connection Attempt on Port 4444 [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 127.0.0.1:55319 -> 127.0.0.1:4444
  ```

---

### Test 3 — HTTP Detection

- **Goal**: Send a benign HTTP GET request containing the test URI string `netsentinel-test` to the local test server.
- **Test Server**: `tests/test_http_server.py` running on `http://127.0.0.1:8080`
- **Traffic Command**: `Invoke-WebRequest -Uri "http://127.0.0.1:8080/netsentinel-test"`
- **Expected SID**: `9000003`
- **Status**: **PASS**
- **Logged Alert Evidence**:
  ```text
  08/14-22:36:39.154624  [**] [1:9000003:1] [NetSentinel] Suspicious HTTP Test Pattern Detected [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 127.0.0.1:55320 -> 127.0.0.1:8080
  ```

---

## Conclusion

All three controlled attack simulation tests succeeded. Snort accurately detected ICMP, TCP port 4444, and HTTP URI test traffic, writing structured alert entries containing timestamp, source/destination IP/ports, protocol, classification, and rule SID to `netsentinel_alerts.txt`.
