# sec-auditor — Defensive Network & Security Configuration Auditor

> **IBM Skills Build / IBM SkillsBuild Cybersecurity Submission**
> Submitted by: sec-auditor contributors | Version: 0.1.0 | Python 3.10+

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Objectives](#3-objectives)
4. [Technology Stack](#4-technology-stack)
5. [Architecture](#5-architecture)
6. [Module Descriptions](#6-module-descriptions)
7. [Features](#7-features)
8. [Installation](#8-installation)
9. [Usage — Command Line](#9-usage--command-line)
10. [Usage — Web Interface](#10-usage--web-interface)
11. [OWASP Security Headers Checked](#11-owasp-security-headers-checked)
12. [Test Suite](#12-test-suite)
13. [Project Structure](#13-project-structure)
14. [Sample Output](#14-sample-output)
15. [Security & Ethics Statement](#15-security--ethics-statement)
16. [Future Scope](#16-future-scope)
17. [References](#17-references)

---

## 1. Project Overview

**sec-auditor** is a lightweight, fully open-source, Python-based defensive security auditing tool designed to help system administrators, security engineers, and developers identify misconfigurations in their network infrastructure and web services.

The tool performs two core operations:

| Operation | Description |
|---|---|
| **TCP Port Discovery** | Concurrently probes a target host for open TCP ports using raw sockets, identifies services, and optionally grabs banners. |
| **HTTP Header Audit** | Fetches HTTP/HTTPS response headers and evaluates them against the OWASP Secure Headers Project baseline, reporting missing headers with actionable remediation guidance. |

Results are displayed in a colour-coded terminal view, a browser-based web UI, and optionally exported as a structured JSON artifact for integration with SIEM/ticketing systems.

---

## 2. Problem Statement

Modern organisations frequently deploy web services with incomplete HTTP security header configurations. According to OWASP research, a significant proportion of publicly accessible web applications lack one or more of the following critical protective headers:

- `Content-Security-Policy` (XSS mitigation)
- `Strict-Transport-Security` (HTTPS enforcement)
- `X-Frame-Options` (clickjacking prevention)
- `X-Content-Type-Options` (MIME-sniffing prevention)
- `Referrer-Policy` (information leakage control)
- `Permissions-Policy` (browser feature restriction)

Additionally, many systems expose their software versions through `Server` and `X-Powered-By` response headers, providing attackers with fingerprinting opportunities.

Existing enterprise scanning tools are expensive, heavyweight, and often require cloud connectivity. **sec-auditor** solves this by providing a fast, free, dependency-minimal tool that can be run in air-gapped lab environments.

---

## 3. Objectives

1. Build a **modular, testable** Python tool that performs TCP port discovery without elevated privileges.
2. Implement **OWASP-compliant HTTP security header auditing** with actionable remediation advice.
3. Provide both a **CLI interface** (for automation/scripting) and a **Web UI** (for interactive use).
4. Export scan results as **structured JSON** for downstream processing.
5. Achieve **100% test coverage** of all business logic with no external test dependencies.
6. Run entirely on the **Python standard library** (plus `colorama` for terminal colours and `flask` for the web UI).

---

## 4. Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Language | Python | ≥ 3.10 |
| Port scanning | `socket` (stdlib) | — |
| HTTP requests | `urllib.request` (stdlib) | — |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` (stdlib) | — |
| SSL handling | `ssl` (stdlib) | — |
| Web framework | Flask | ≥ 3.0 |
| Terminal colour | colorama | ≥ 0.4.6 |
| Testing | `unittest` + `unittest.mock` (stdlib) | — |
| Packaging | setuptools / pyproject.toml | — |

**No third-party scanning libraries** (nmap, scapy, requests) are used. The tool relies exclusively on Python's standard library for all network operations, making it portable and audit-friendly.

---

## 5. Architecture

```
┌──────────────────────────────────────────────────────────┐
│                        User Interface                     │
│   ┌─────────────────────┐    ┌────────────────────────┐  │
│   │   CLI (cli.py)      │    │  Web UI (web.py +      │  │
│   │   argparse-based    │    │  templates/index.html) │  │
│   └──────────┬──────────┘    └────────────┬───────────┘  │
└──────────────┼───────────────────────────┼───────────────┘
               │                           │
               ▼                           ▼
┌──────────────────────────────────────────────────────────┐
│                       Core Engine                         │
│  ┌──────────────────┐    ┌───────────────────────────┐   │
│  │  scanner.py      │    │  http_auditor.py          │   │
│  │  ┌────────────┐  │    │  ┌─────────────────────┐  │   │
│  │  │resolve_    │  │    │  │ audit_web_service()  │  │   │
│  │  │target()    │  │    │  │ BASELINE_HEADERS     │  │   │
│  │  │scan_target │  │    │  │ HeaderAuditResult    │  │   │
│  │  │()          │  │    │  └─────────────────────┘  │   │
│  │  └────────────┘  │    └───────────────────────────┘   │
│  └──────────────────┘                                     │
└──────────────────────────────────┬───────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────┐
│                      reporter.py                          │
│   format_terminal_report()  │  export_json()             │
│   print_scan_report()       │  http_report_to_json()     │
└──────────────────────────────────────────────────────────┘
```

**Data flow:**
1. User provides a `TARGET` (hostname, IP, or URL).
2. `resolve_target()` strips URL schemes and resolves to an IPv4 address.
3. `scan_target()` fans out up to 50 concurrent TCP probes via `ThreadPoolExecutor`.
4. For each open web port (80, 443, 8080, 8443), `audit_web_service()` fetches headers.
5. `format_terminal_report()` renders colour-coded output; `export_json()` saves the artifact.

---

## 6. Module Descriptions

### `sec_auditor/scanner.py`
Provides socket-based TCP port discovery without any third-party dependencies.

| Symbol | Type | Purpose |
|---|---|---|
| `PortScanResult` | dataclass | Typed result: port, service_name, is_open |
| `resolve_target()` | function | Strips URL schemes, resolves hostname → IPv4 |
| `scan_target()` | function | Concurrent TCP scan via `connect_ex` + ThreadPoolExecutor |
| `_SERVICE_NAMES` | dict | Maps 16 well-known ports to service names |

### `sec_auditor/http_auditor.py`
Performs OWASP-aligned HTTP security header evaluation.

| Symbol | Type | Purpose |
|---|---|---|
| `BASELINE_HEADERS` | list | 6 OWASP-required header names, severity-ordered |
| `HeaderAuditResult` | dataclass | present_headers, missing_headers, recommendations, server_banner |
| `audit_web_service()` | function | Fetches headers, evaluates against baseline, returns HeaderAuditResult |
| `_build_ssl_context()` | function | Unverified SSL context for self-signed cert lab environments |

### `sec_auditor/reporter.py`
Renders results to terminal (with ANSI colour) or JSON.

| Symbol | Type | Purpose |
|---|---|---|
| `format_terminal_report()` | function | ASCII port table + header audit + server warnings |
| `export_json()` | function | Writes full scan artifact as pretty-printed JSON |

### `sec_auditor/cli.py`
Single-command `argparse` interface.

| Argument | Default | Purpose |
|---|---|---|
| `TARGET` | required | Hostname, IP, or URL |
| `--ports` | 16 common ports | Comma-list or N-M ranges |
| `--threads` | 50 | Max concurrent probe threads |
| `--timeout` | 1.0s | Per-connection timeout |
| `--json-output` | None | Path to save JSON report |
| `--skip-http` | False | Skip HTTP header audit |

### `sec_auditor/web.py`
Flask web server with REST API.

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Serve the single-page web UI |
| `/api/scan` | POST | Run full audit, return JSON |

---

## 7. Features

### ✅ Implemented

- [x] **Concurrent TCP port scanner** — up to 200 threads, configurable timeout
- [x] **Service name detection** — 16 well-known ports mapped (FTP, SSH, HTTP, HTTPS, MySQL, etc.)
- [x] **Hostname/URL resolution** — strips `https://`, paths, query strings, port suffixes
- [x] **HTTP/HTTPS header audit** — supports self-signed certificates (lab-safe)
- [x] **6 OWASP baseline headers** checked with per-header remediation text
- [x] **Server version disclosure detection** — warns on `Server:` and `X-Powered-By:` headers
- [x] **Colour-coded terminal output** — green (pass), red (fail), yellow (warn)
- [x] **JSON export** — full structured artifact with version, IP, ports, audits
- [x] **Web UI** — dark-themed single-page app with 20 prototype quick-targets
- [x] **135 unit tests** — 100% pass, zero warnings, stdlib only

---

## 8. Installation

### Prerequisites
- Python 3.10 or higher
- pip

### Steps

```bash
# 1. Clone or download the project
cd sec-auditor

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Install as a command
pip install -e .
```

---

## 9. Usage — Command Line

```bash
# Basic audit (port scan + HTTP header check)
python -m sec_auditor.cli example.com

# Custom ports
python -m sec_auditor.cli 192.168.1.10 --ports 22,80,443,8000-8010

# Port scan only
python -m sec_auditor.cli example.com --skip-http

# Save JSON report
python -m sec_auditor.cli example.com --json-output report.json

# More threads, higher timeout
python -m sec_auditor.cli example.com --threads 100 --timeout 3.0

# Show help
python -m sec_auditor.cli --help
```

---

## 10. Usage — Web Interface

```bash
# Start the web server
python -m sec_auditor.web
```

Open browser: **http://127.0.0.1:5000**

Features of the web UI:
- 20 prototype quick-target IP chips (click to auto-fill)
- Configurable ports, threads, timeout
- Toggle to skip HTTP audit
- Colour-coded results table (open ports + header audit)
- One-click JSON export

---

## 11. OWASP Security Headers Checked

| Header | Severity | Risk Mitigated |
|---|---|---|
| `Content-Security-Policy` | HIGH | XSS and data-injection attacks |
| `Strict-Transport-Security` | HIGH | HTTPS downgrade and cookie hijacking |
| `X-Frame-Options` | MEDIUM | Clickjacking via iframe embedding |
| `X-Content-Type-Options` | MEDIUM | MIME-type sniffing attacks |
| `Referrer-Policy` | LOW | Navigation information leakage |
| `Permissions-Policy` | LOW | Unauthorised browser feature access |

**Discouraged headers** (presence triggers a warning):

| Header | Risk |
|---|---|
| `Server` | Software/version fingerprinting |
| `X-Powered-By` | Technology stack disclosure |

Reference: [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

---

## 12. Test Suite

```bash
python -m unittest discover -s tests -v
```

**Results: 135 tests | 0 failures | 0 errors | 0 warnings**

| Test File | Classes | Tests | Coverage Area |
|---|---|---|---|
| `test_scanner.py` | 8 | 68 | PortResult, ScanReport, _probe_port, _probe_port_ex, resolve_target, scan_target, connect_ex return codes, URL stripping scenarios |
| `test_http_auditor.py` | 12 | 67 | HSTS validation, X-Content-Type, X-Frame-Options, HeaderAuditResult, SSL context, scheme detection, audit_web_service, full-OWASP scenario, missing-HSTS/CSP scenario, server banner extraction |

All tests use **stdlib only** (`unittest` + `unittest.mock`) — no pytest, no network calls.

---

## 13. Project Structure

```
sec-auditor/
│
├── sec_auditor/                  # Main package
│   ├── __init__.py               # Version (0.1.0), package metadata
│   ├── cli.py                    # argparse CLI entry point
│   ├── scanner.py                # TCP port discovery engine
│   ├── http_auditor.py           # OWASP HTTP header auditor
│   ├── reporter.py               # Terminal + JSON output
│   ├── web.py                    # Flask web server + /api/scan
│   └── templates/
│       └── index.html            # Single-page browser UI
│
├── tests/                        # Unit test suite
│   ├── __init__.py
│   ├── test_scanner.py           # 68 scanner tests
│   └── test_http_auditor.py      # 67 HTTP auditor tests
│
├── pyproject.toml                # Build metadata + console script
├── requirements.txt              # Runtime dependencies
└── README.md                     # This file
```

---

## 14. Sample Output

### Terminal
```
─────────────────── Port Scan: example.com ───────────────────
  ┌────────┬──────────────────┬────────┐
  │  PORT  │  SERVICE         │ STATE  │
  ├────────┼──────────────────┼────────┤
  │ 80/tcp │ HTTP             │ OPEN   │
  │ 443/tcp│ HTTPS            │ OPEN   │
  └────────┴──────────────────┴────────┘
  2 open port(s) discovered.

───────────────── HTTP Security Header Audit ─────────────────
  Target: https://example.com:443/
    ✘ MISSING  Content-Security-Policy
               ↳ Add 'Content-Security-Policy: default-src 'self'' …
    ✔ PRESENT  X-Content-Type-Options: nosniff
    Summary: 1 present  5 missing
```

### JSON Artifact
```json
{
  "sec_auditor_version": "0.1.0",
  "target": "example.com",
  "resolved_ip": "93.184.216.34",
  "port_scan": [
    { "port": 80,  "service_name": "HTTP",  "is_open": true },
    { "port": 443, "service_name": "HTTPS", "is_open": true }
  ],
  "http_audits": [
    {
      "target_url": "https://example.com:443/",
      "server_banner": null,
      "present_headers": { "X-Content-Type-Options": "nosniff" },
      "missing_headers": ["Content-Security-Policy", "Strict-Transport-Security"],
      "recommendations": {
        "Content-Security-Policy": "Add 'Content-Security-Policy: default-src …"
      }
    }
  ]
}
```

---

## 15. Security & Ethics Statement

> ⚠️ **This tool is intended exclusively for defensive configuration auditing.**

- Only scan systems you **own** or have **explicit written authorisation** to test.
- All network operations use standard OS TCP connections — no raw packet injection, no ARP spoofing, no OS fingerprinting.
- The SSL context intentionally disables certificate verification **only** to allow auditing of misconfigured local lab servers. This is documented with a warning and is not used for any data exfiltration.
- No scan data is transmitted to any external server. All processing is local.
- Unauthorised scanning of third-party systems may violate computer crime laws including the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent legislation.

---

## 16. Future Scope

| Enhancement | Description |
|---|---|
| CVE lookup | Cross-reference open ports/banners with NVD CVE database |
| Scheduled scans | Cron-based recurring audits with diff reports |
| SIEM integration | Direct output to Splunk / IBM QRadar via syslog/CEF |
| Authenticated scans | SSH-based configuration file auditing |
| PDF reports | Branded PDF export for compliance documentation |
| IPv6 support | Extend scanner to AF_INET6 socket family |
| Docker image | Containerised deployment for CI/CD pipelines |
| IBM Cloud integration | Deploy web UI to IBM Code Engine / Cloud Foundry |

---

## 17. References

1. OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/
2. OWASP Top 10 — https://owasp.org/www-project-top-ten/
3. NIST SP 800-115: Technical Guide to Information Security Testing — https://csrc.nist.gov/publications/detail/sp/800-115/final
4. Python `socket` documentation — https://docs.python.org/3/library/socket.html
5. Python `ssl` documentation — https://docs.python.org/3/library/ssl.html
6. RFC 7230 — HTTP/1.1 Message Syntax and Routing
7. RFC 6797 — HTTP Strict Transport Security (HSTS)
8. Flask documentation — https://flask.palletsprojects.com/
9. IBM SkillsBuild Cybersecurity Learning Path — https://skillsbuild.org/

---

*Built with Python 3.10+ · Tested on Windows 10/11 and Ubuntu 22.04 · MIT License*
