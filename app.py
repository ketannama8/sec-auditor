"""
app.py — Single-file IBM Prototype Launcher for sec-auditor
============================================================
Run:
    python app.py

Then open:  http://127.0.0.1:5000

This file is a COMPLETE self-contained prototype that:
  - Works with a LIVE target (real scan)
  - Works in DEMO MODE (20 fake pre-built results, no network needed)
  - Shows a full dashboard with port table, header audit, charts, history
  - Runs with just:  pip install flask colorama
"""

from __future__ import annotations

import json
import os
import datetime
from flask import Flask, request, jsonify, Response

# ── Try importing the real scanner; fall back to demo mode if unavailable ──
try:
    from sec_auditor.scanner import resolve_target, scan_target
    from sec_auditor.http_auditor import audit_web_service
    REAL_SCAN_AVAILABLE = True
except ImportError:
    REAL_SCAN_AVAILABLE = False

app = Flask(__name__)

_WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})
_DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443"

# ── 20 Fake prototype scan results for demo mode ───────────────────────────
DEMO_RESULTS = {
    "10.0.0.1":      {"label": "Gateway",       "open": [22,80,443],        "missing": ["Content-Security-Policy","Permissions-Policy"],                                         "banner": None},
    "10.0.0.5":      {"label": "Web Server",    "open": [22,80,443,8080],   "missing": ["Strict-Transport-Security","Permissions-Policy","Referrer-Policy"],                     "banner": "nginx/1.24.0"},
    "10.0.0.10":     {"label": "DB Server",     "open": [22,3306,5432],     "missing": ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"], "banner": None},
    "10.0.0.15":     {"label": "Mail Server",   "open": [22,25,110,143,443],"missing": ["Content-Security-Policy","Permissions-Policy","Referrer-Policy"],                       "banner": "Apache/2.4.57"},
    "10.0.0.20":     {"label": "Dev Box",       "open": [22,80,8080,8443],  "missing": ["Strict-Transport-Security","X-Frame-Options"],                                          "banner": "Apache/2.4.51 (Ubuntu)"},
    "10.0.0.25":     {"label": "Staging",       "open": [22,80,443],        "missing": ["Content-Security-Policy","Referrer-Policy","Permissions-Policy"],                       "banner": "nginx/1.18.0"},
    "192.168.1.1":   {"label": "Router",        "open": [22,80,443],        "missing": ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"], "banner": "MikroTik/6.49"},
    "192.168.1.10":  {"label": "Firewall",      "open": [22,443,8443],      "missing": ["Content-Security-Policy","Permissions-Policy"],                                         "banner": None},
    "192.168.1.20":  {"label": "NAS",           "open": [22,80,443,5432],   "missing": ["Strict-Transport-Security","Content-Security-Policy","Referrer-Policy"],                "banner": "lighttpd/1.4.59"},
    "192.168.1.50":  {"label": "Printer",       "open": [80,443],           "missing": ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"], "banner": "HP-ChaiSOE/1.0"},
    "172.16.0.1":    {"label": "VPN Gateway",   "open": [22,443,1194],      "missing": ["Content-Security-Policy","Permissions-Policy"],                                         "banner": None},
    "172.16.0.5":    {"label": "AD Server",     "open": [22,80,443,3389],   "missing": ["Content-Security-Policy","Strict-Transport-Security","Permissions-Policy"],             "banner": "Microsoft-IIS/10.0"},
    "172.16.0.10":   {"label": "Backup Server", "open": [22,445],           "missing": ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"], "banner": None},
    "172.16.0.20":   {"label": "Monitor",       "open": [22,80,443,3000],   "missing": ["Permissions-Policy","Referrer-Policy"],                                                 "banner": "Grafana/9.5.2"},
    "192.168.10.1":  {"label": "DMZ Host",      "open": [22,80,443,8080],   "missing": ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options"],               "banner": "nginx/1.22.1"},
    "192.168.10.5":  {"label": "Proxy",         "open": [22,80,443,3128],   "missing": ["Content-Security-Policy","Permissions-Policy"],                                         "banner": "Squid/5.7"},
    "192.168.20.1":  {"label": "IoT Hub",       "open": [80,443,8883],      "missing": ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"], "banner": "Mongoose/7.0"},
    "10.10.0.1":     {"label": "Lab Gateway",   "open": [22,80,443],        "missing": ["Referrer-Policy","Permissions-Policy"],                                                 "banner": None},
    "10.10.0.50":    {"label": "Test Server",   "open": [22,80,8080,8443],  "missing": ["Content-Security-Policy","Strict-Transport-Security"],                                  "banner": "Werkzeug/2.3.6 Python/3.11.4"},
    "10.10.0.99":    {"label": "Honeypot",      "open": [21,22,23,25,80,443,3306], "missing": ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"], "banner": "Apache/2.2.34"},
}

SERVICE_MAP = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
               110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",1194:"OpenVPN",
               3000:"Grafana",3128:"Squid",3306:"MySQL",3389:"RDP",
               5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Proxy",
               8443:"HTTPS-Alt",8883:"MQTT"}

ALL_HEADERS = ["Content-Security-Policy","Strict-Transport-Security",
               "X-Frame-Options","X-Content-Type-Options",
               "Referrer-Policy","Permissions-Policy"]

RECOMMENDATIONS = {
    "Content-Security-Policy":   "Add 'Content-Security-Policy: default-src \\'self\\'' to mitigate XSS and data-injection attacks.",
    "Strict-Transport-Security": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
    "X-Frame-Options":           "Add 'X-Frame-Options: DENY' to prevent clickjacking attacks.",
    "X-Content-Type-Options":    "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks.",
    "Referrer-Policy":           "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit information leakage.",
    "Permissions-Policy":        "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()' to restrict browser features.",
}

scan_history: list[dict] = []


def _parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            p = token.split("-", 1)
            try:
                ports.update(x for x in range(int(p[0]), int(p[1])+1) if 1 <= x <= 65535)
            except ValueError:
                pass
        else:
            try:
                v = int(token)
                if 1 <= v <= 65535:
                    ports.add(v)
            except ValueError:
                pass
    return sorted(ports)


def _build_demo_result(target: str) -> dict:
    """Return a realistic fake scan result for demo mode."""
    info = DEMO_RESULTS.get(target, {
        "label": "Unknown Host", "open": [80, 443],
        "missing": ["Content-Security-Policy", "Strict-Transport-Security",
                    "Permissions-Policy", "Referrer-Policy"],
        "banner": None
    })
    open_set = set(info["open"])
    all_ports = sorted(set(_parse_ports(_DEFAULT_PORTS)) | open_set)

    ports_data = [
        {"port": p, "service_name": SERVICE_MAP.get(p, "Unknown"), "is_open": p in open_set}
        for p in all_ports
    ]

    missing = info["missing"]
    present = {h: "present" for h in ALL_HEADERS if h not in missing}
    recs     = {h: RECOMMENDATIONS[h] for h in missing}

    web_open = [p for p in info["open"] if p in _WEB_PORTS]
    audits = []
    for port in web_open:
        scheme = "https" if port == 443 else "http"
        audits.append({
            "target_url":      f"{scheme}://{target}:{port}/",
            "server_banner":   info["banner"],
            "present_headers": present,
            "missing_headers": missing,
            "recommendations": recs,
        })

    return {
        "ok": True, "mode": "demo",
        "target": target, "ip": target,
        "label": info["label"],
        "ports": ports_data,
        "http_audits": audits,
        "error": "",
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _build_live_result(target: str, ports_raw: str, threads: int,
                       timeout: float, skip_http: bool) -> dict:
    """Run a real live scan and return structured result."""
    try:
        ip = resolve_target(target)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    ports = _parse_ports(ports_raw or _DEFAULT_PORTS)
    if not ports:
        return {"ok": False, "error": "No valid ports specified."}

    scan_results = scan_target(ip=ip, ports=ports, max_workers=threads, timeout=timeout)
    ports_data = [{"port": r.port, "service_name": r.service_name, "is_open": r.is_open}
                  for r in scan_results]

    audits_data = []
    if not skip_http:
        for r in scan_results:
            if r.is_open and r.port in _WEB_PORTS:
                res = audit_web_service(target, r.port, timeout=timeout)
                audits_data.append({
                    "target_url":      res.target_url,
                    "server_banner":   res.server_banner,
                    "present_headers": res.present_headers,
                    "missing_headers": res.missing_headers,
                    "recommendations": res.recommendations,
                })

    return {
        "ok": True, "mode": "live",
        "target": target, "ip": ip,
        "label": target,
        "ports": ports_data,
        "http_audits": audits_data,
        "error": "",
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index() -> str:
    return HTML_PAGE


@app.route("/api/scan", methods=["POST"])
def api_scan() -> Response:
    body      = request.get_json(force=True, silent=True) or {}
    target    = (body.get("target") or "").strip()
    demo_mode = bool(body.get("demo", False))
    ports_raw = body.get("ports", _DEFAULT_PORTS)
    threads   = int(body.get("threads", 50))
    timeout   = float(body.get("timeout", 1.0))
    skip_http = bool(body.get("skip_http", False))

    if not target:
        return jsonify({"ok": False, "error": "No target specified."}), 400

    if demo_mode or not REAL_SCAN_AVAILABLE:
        result = _build_demo_result(target)
    else:
        result = _build_live_result(target, ports_raw, threads, timeout, skip_http)

    if result.get("ok"):
        scan_history.insert(0, {
            "target":     result["target"],
            "label":      result.get("label", target),
            "ip":         result.get("ip", ""),
            "mode":       result.get("mode", "live"),
            "open_ports": len([p for p in result.get("ports", []) if p["is_open"]]),
            "missing":    sum(len(a.get("missing_headers", [])) for a in result.get("http_audits", [])),
            "scanned_at": result.get("scanned_at", ""),
        })
        if len(scan_history) > 20:
            scan_history.pop()

    return jsonify(result)


@app.route("/api/history")
def api_history() -> Response:
    return jsonify(scan_history)


@app.route("/api/demo-targets")
def api_demo_targets() -> Response:
    return jsonify([
        {"ip": ip, "label": v["label"],
         "open_count": len(v["open"]),
         "missing_count": len(v["missing"]),
         "banner": v["banner"]}
        for ip, v in DEMO_RESULTS.items()
    ])


# ── Inline HTML (single-file, no template folder needed) ───────────────────

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>sec-auditor — IBM Prototype</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.6;background:#080c14;color:#e2e8f0;min-height:100vh}

/* Header */
header{background:linear-gradient(135deg,#0f1e3d 0%,#080c14 100%);border-bottom:1px solid #1e3a5f;padding:14px 28px;display:flex;align-items:center;gap:16px}
.logo-text{font-size:20px;font-weight:800;color:#38bdf8;letter-spacing:-0.5px}
.logo-sub{font-size:11px;color:#475569;margin-top:1px}
.ibm-badge{margin-left:auto;background:#0f3460;border:1px solid #1d6aad;color:#93c5fd;font-size:11px;font-weight:700;padding:4px 14px;border-radius:999px;letter-spacing:.05em}
.live-pill{background:#052e16;border:1px solid #166534;color:#4ade80;font-size:10px;font-weight:700;padding:3px 10px;border-radius:999px}
.demo-pill{background:#1c1407;border:1px solid #854d0e;color:#fbbf24;font-size:10px;font-weight:700;padding:3px 10px;border-radius:999px}

/* Layout */
.layout{display:grid;grid-template-columns:260px 1fr;min-height:calc(100vh - 55px)}

/* Sidebar */
aside{background:#0a1020;border-right:1px solid #1e3a5f;padding:20px 16px;display:flex;flex-direction:column;gap:18px;overflow-y:auto}
.sidebar-title{font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}

/* Quick targets */
.qt-item{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:7px;cursor:pointer;border:1px solid transparent;transition:.15s}
.qt-item:hover{background:#111827;border-color:#1e3a5f}
.qt-item.active{background:#0f2244;border-color:#3b82f6}
.qt-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot-open{background:#4ade80;box-shadow:0 0 5px #4ade8066}
.dot-warn{background:#f59e0b;box-shadow:0 0 5px #f59e0b66}
.qt-info{flex:1;min-width:0}
.qt-ip{font-family:monospace;font-size:12px;color:#93c5fd}
.qt-lbl{font-size:11px;color:#475569;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.qt-counts{font-size:10px;text-align:right;flex-shrink:0}
.qt-open{color:#4ade80}
.qt-miss{color:#f87171}

/* History */
.hist-item{padding:8px 10px;border-radius:6px;background:#0f172a;border:1px solid #1e3a5f;margin-bottom:6px;cursor:pointer}
.hist-item:hover{border-color:#3b82f6}
.hist-target{font-family:monospace;font-size:12px;color:#93c5fd}
.hist-meta{font-size:10px;color:#475569;margin-top:1px}

/* Main */
main{padding:24px 28px;overflow-y:auto}

/* Warning */
.warn-bar{background:#1c1407;border:1px solid #854d0e;border-left:4px solid #f59e0b;border-radius:6px;padding:9px 14px;margin-bottom:20px;color:#fde68a;font-size:12px}
.warn-bar strong{color:#f59e0b}

/* Scan card */
.card{background:#0f172a;border:1px solid #1e3a5f;border-radius:10px;padding:20px 24px;margin-bottom:20px}
.card h2{font-size:13px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid #1e3a5f}

/* Form */
.form-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px}
.fg{display:flex;flex-direction:column;gap:5px}
.fg.full{grid-column:1/-1}
label{font-size:11px;color:#64748b;font-weight:600}
input[type=text],input[type=number]{background:#080c14;border:1px solid #1e3a5f;border-radius:6px;color:#e2e8f0;font-size:13px;padding:8px 11px;outline:none;width:100%;transition:.15s}
input:focus{border-color:#3b82f6}
input::placeholder{color:#334155}

.toggle-row{display:flex;align-items:center;gap:10px;margin-top:4px}
.toggle{position:relative;width:36px;height:19px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.tslider{position:absolute;inset:0;background:#1e293b;border-radius:20px;cursor:pointer;transition:.2s}
.tslider::before{content:"";position:absolute;width:13px;height:13px;left:3px;bottom:3px;background:#475569;border-radius:50%;transition:.2s}
.toggle input:checked+.tslider{background:#2563eb}
.toggle input:checked+.tslider::before{transform:translateX(17px);background:#fff}
.tlabel{font-size:12px;color:#94a3b8}

/* Mode toggle */
.mode-row{display:flex;gap:10px;margin-bottom:16px}
.mode-btn{flex:1;padding:9px;border-radius:7px;border:1px solid #1e3a5f;background:#080c14;color:#64748b;font-size:13px;font-weight:600;cursor:pointer;transition:.15s;text-align:center}
.mode-btn.active.live{border-color:#22c55e;background:#052e16;color:#4ade80}
.mode-btn.active.demo{border-color:#f59e0b;background:#1c1407;color:#fbbf24}

/* Buttons */
.btn-row{display:flex;gap:10px;margin-top:16px}
button{display:inline-flex;align-items:center;gap:8px;border:none;border-radius:7px;cursor:pointer;font-size:13px;font-weight:700;padding:9px 20px;transition:.15s}
button:active{transform:scale(.97)}
.btn-primary{background:#2563eb;color:#fff}
.btn-primary:hover{background:#1d4ed8}
.btn-primary:disabled{opacity:.4;cursor:not-allowed}
.btn-sec{background:#1e3a5f;color:#93c5fd;border:1px solid #2563eb}
.btn-sec:hover{background:#1d3a5a}
.spinner{width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;display:none}
.loading .spinner{display:block}
.loading .btn-text{display:none}
@keyframes spin{to{transform:rotate(360deg)}}

/* Status */
#status{display:none;padding:9px 14px;border-radius:6px;margin-top:12px;font-size:12px}
#status.info{background:#0c1a3d;border:1px solid #1d4ed8;color:#93c5fd}
#status.success{background:#052e16;border:1px solid #16a34a;color:#86efac}
#status.error{background:#1c0a09;border:1px solid #b91c1c;color:#fca5a5}

/* Stats row */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.stat-card{background:#0f172a;border:1px solid #1e3a5f;border-radius:9px;padding:16px 18px}
.stat-num{font-size:28px;font-weight:800;line-height:1}
.stat-lbl{font-size:11px;color:#475569;margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.stat-open{color:#4ade80}
.stat-miss{color:#f87171}
.stat-warn{color:#f59e0b}
.stat-info{color:#38bdf8}

/* Port table */
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 12px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#475569;border-bottom:1px solid #1e3a5f}
td{padding:8px 12px;border-bottom:1px solid #080c14}
tr:hover td{background:rgba(255,255,255,.02)}
tr:last-child td{border-bottom:none}
.port-num{font-family:monospace;color:#93c5fd;font-size:12px}
.svc{color:#cbd5e1}
.badge-open{background:#052e16;color:#4ade80;border:1px solid #166534;padding:2px 9px;border-radius:999px;font-size:10px;font-weight:700}
.badge-closed{background:#0f172a;color:#334155;border:1px solid #1e293b;padding:2px 9px;border-radius:999px;font-size:10px}

/* Header audit */
.audit-block{margin-bottom:8px}
.audit-url-row{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.audit-url-row code{font-size:12px;color:#38bdf8;background:#080c14;padding:3px 9px;border-radius:5px;border:1px solid #1e3a5f}
.banner-tag{font-size:10px;background:#1c1407;border:1px solid #854d0e;color:#fbbf24;padding:2px 9px;border-radius:999px}
.hrow{display:flex;align-items:flex-start;gap:10px;padding:9px 0;border-bottom:1px solid #080c14}
.hrow:last-child{border-bottom:none}
.hicon{width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0;margin-top:1px}
.hicon.pass{background:#052e16;color:#4ade80;border:1px solid #166534}
.hicon.fail{background:#1c0a09;color:#f87171;border:1px solid #991b1b}
.hname{font-weight:700;font-size:12px}
.hname.fail{color:#f87171}
.hval{font-size:11px;color:#475569;margin-top:1px;word-break:break-all}
.rec{font-size:11px;color:#94a3b8;margin-top:5px;padding:5px 9px;background:#080c14;border-left:3px solid #f59e0b;border-radius:0 4px 4px 0}
.sum-row{display:flex;gap:14px;padding:10px 0 0;font-size:12px;font-weight:700}
.sum-p{color:#4ade80}
.sum-f{color:#f87171}

/* Results hidden by default */
#results{display:none}
#export-btn{display:none}

/* Responsive */
@media(max-width:700px){
  .layout{grid-template-columns:1fr}
  aside{display:none}
  .form-row{grid-template-columns:1fr}
  .stats-row{grid-template-columns:1fr 1fr}
}
</style>
</head>
<body>

<header>
  <div>
    <div class="logo-text">⚡ sec-auditor</div>
    <div class="logo-sub">Defensive Network &amp; Security Configuration Auditor</div>
  </div>
  <span id="mode-indicator" class="demo-pill">DEMO MODE</span>
  <div class="ibm-badge">IBM SkillsBuild · v0.1.0</div>
</header>

<div class="layout">

  <!-- Sidebar -->
  <aside>
    <div>
      <div class="sidebar-title">⚡ Quick Targets</div>
      <div id="qt-list"></div>
    </div>
    <div>
      <div class="sidebar-title">🕘 Scan History</div>
      <div id="hist-list"><div style="color:#334155;font-size:12px">No scans yet.</div></div>
    </div>
  </aside>

  <!-- Main content -->
  <main>

    <div class="warn-bar">
      <strong>⚠ Authorized Use Only</strong> —
      Only audit systems you own or have explicit written permission to test.
      Use <strong>Demo Mode</strong> to explore without a live network target.
    </div>

    <!-- Scan form -->
    <div class="card">
      <h2>🔍 New Audit</h2>

      <!-- Mode selector -->
      <div class="mode-row">
        <div class="mode-btn active demo" id="btn-demo" onclick="setMode('demo')">🎭 Demo Mode <span style="font-size:10px;font-weight:400">(fake data, no network)</span></div>
        <div class="mode-btn live" id="btn-live" onclick="setMode('live')">🌐 Live Mode <span style="font-size:10px;font-weight:400">(real scan)</span></div>
      </div>

      <div class="form-row">
        <div class="fg full">
          <label for="target">Target IP or Hostname</label>
          <input type="text" id="target" placeholder="e.g. 10.0.0.5  or  example.com" autocomplete="off"/>
        </div>
        <div class="fg">
          <label for="ports">Ports</label>
          <input type="text" id="ports" value="21,22,23,25,53,80,443,445,3306,8080,8443"/>
        </div>
        <div class="fg">
          <label for="timeout">Timeout (s)</label>
          <input type="number" id="timeout" value="1.0" min="0.1" max="10" step="0.1"/>
        </div>
        <div class="fg">
          <label for="threads">Threads</label>
          <input type="number" id="threads" value="50" min="1" max="200"/>
        </div>
      </div>

      <div class="toggle-row">
        <label class="toggle"><input type="checkbox" id="skip-http"><span class="tslider"></span></label>
        <span class="tlabel">Port scan only — skip HTTP header audit</span>
      </div>

      <div class="btn-row">
        <button class="btn-primary" id="scan-btn" onclick="runScan()">
          <div class="spinner"></div>
          <span class="btn-text">▶ Run Audit</span>
        </button>
        <button class="btn-sec" id="export-btn" onclick="exportJSON()">⬇ Export JSON</button>
      </div>

      <div id="status"></div>
    </div>

    <!-- Stats -->
    <div class="stats-row" id="stats-row" style="display:none">
      <div class="stat-card"><div class="stat-num stat-open" id="s-open">0</div><div class="stat-lbl">Open Ports</div></div>
      <div class="stat-card"><div class="stat-num stat-miss" id="s-miss">0</div><div class="stat-lbl">Missing Headers</div></div>
      <div class="stat-card"><div class="stat-num stat-warn" id="s-ban">0</div><div class="stat-lbl">Banner Disclosures</div></div>
      <div class="stat-card"><div class="stat-num stat-info" id="s-chk">0</div><div class="stat-lbl">Total Checks</div></div>
    </div>

    <!-- Results -->
    <div id="results">

      <div class="card">
        <h2>📡 Port Scan — <span id="res-target" style="color:#38bdf8;text-transform:none;font-size:14px"></span></h2>
        <table>
          <thead><tr><th>Port</th><th>Service</th><th>State</th></tr></thead>
          <tbody id="port-body"></tbody>
        </table>
      </div>

      <div id="http-section"></div>

    </div>
  </main>
</div>

<script>
let _mode = 'demo';
let _last = null;

// ── mode ──────────────────────────────────────────────────────────────────
function setMode(m) {
  _mode = m;
  document.getElementById('btn-demo').classList.toggle('active', m==='demo');
  document.getElementById('btn-live').classList.toggle('active', m==='live');
  document.getElementById('btn-demo').classList.toggle('demo',   m==='demo');
  document.getElementById('btn-live').classList.toggle('live',   m==='live');
  document.getElementById('mode-indicator').className = m==='demo' ? 'demo-pill' : 'live-pill';
  document.getElementById('mode-indicator').textContent = m==='demo' ? 'DEMO MODE' : 'LIVE MODE';
}

// ── helpers ───────────────────────────────────────────────────────────────
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function status(type,msg){const b=document.getElementById('status');b.className=type;b.style.display='flex';b.textContent=msg}
function clearStatus(){document.getElementById('status').style.display='none'}

// ── scan ──────────────────────────────────────────────────────────────────
async function runScan() {
  const target = document.getElementById('target').value.trim();
  if (!target){status('error','⚠ Please enter a target.');return}

  const btn = document.getElementById('scan-btn');
  btn.classList.add('loading'); btn.disabled=true;
  clearStatus(); _last=null;
  document.getElementById('results').style.display='none';
  document.getElementById('stats-row').style.display='none';
  document.getElementById('export-btn').style.display='none';
  status('info','⏳ Running audit on '+target+' …');

  try {
    const resp = await fetch('/api/scan', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        target,
        demo:     _mode==='demo',
        ports:    document.getElementById('ports').value,
        timeout:  parseFloat(document.getElementById('timeout').value)||1.0,
        threads:  parseInt(document.getElementById('threads').value)||50,
        skip_http:document.getElementById('skip-http').checked,
      })
    });
    const data = await resp.json();
    if (!data.ok){status('error','✘ '+data.error);return}
    _last = data;
    render(data);
    loadHistory();
    const open = data.ports.filter(p=>p.is_open).length;
    status('success','✔ Done — '+open+' open port(s) | '+data.ip+' | '+data.mode.toUpperCase()+' MODE');
    document.getElementById('export-btn').style.display='inline-flex';
  } catch(e) {
    status('error','✘ Request failed: '+e.message);
  } finally {
    btn.classList.remove('loading'); btn.disabled=false;
  }
}

// ── render ────────────────────────────────────────────────────────────────
function render(data) {
  const openPorts = data.ports.filter(p=>p.is_open);
  const totalMiss = data.http_audits.reduce((a,x)=>a+(x.missing_headers||[]).length,0);
  const banners   = data.http_audits.filter(x=>x.server_banner).length;
  const totalChk  = data.http_audits.reduce((a,x)=>a+(x.missing_headers||[]).length+(x.present_headers?Object.keys(x.present_headers).length:0),0);

  document.getElementById('s-open').textContent = openPorts.length;
  document.getElementById('s-miss').textContent = totalMiss;
  document.getElementById('s-ban').textContent  = banners;
  document.getElementById('s-chk').textContent  = totalChk;
  document.getElementById('stats-row').style.display='grid';

  document.getElementById('res-target').textContent = data.target + (data.label && data.label!==data.target ? ' ('+data.label+')' : '') + ' — ' + data.ip;

  // port table
  const tbody = document.getElementById('port-body');
  if (openPorts.length===0) {
    tbody.innerHTML='<tr><td colspan="3" style="text-align:center;color:#334155;padding:18px">No open ports found.</td></tr>';
  } else {
    tbody.innerHTML = openPorts.map(p=>`
      <tr>
        <td class="port-num">${esc(p.port)}/tcp</td>
        <td class="svc">${esc(p.service_name)}</td>
        <td><span class="badge-open">OPEN</span></td>
      </tr>`).join('');
  }

  // HTTP audits
  document.getElementById('http-section').innerHTML =
    (data.http_audits||[]).map(renderAudit).join('');

  document.getElementById('results').style.display='block';
}

function renderAudit(a) {
  const ALL = ['Content-Security-Policy','Strict-Transport-Security',
               'X-Frame-Options','X-Content-Type-Options',
               'Referrer-Policy','Permissions-Policy'];
  const rows = ALL.map(h => {
    if (a.present_headers && a.present_headers[h]!==undefined) {
      return `<div class="hrow">
        <div class="hicon pass">✓</div>
        <div><div class="hname">${esc(h)}</div>
        <div class="hval">${esc(a.present_headers[h])}</div></div></div>`;
    }
    const rec = (a.recommendations||{})[h]||'';
    return `<div class="hrow">
      <div class="hicon fail">✗</div>
      <div style="flex:1"><div class="hname fail">${esc(h)}</div>
      ${rec?`<div class="rec">${esc(rec)}</div>`:''}</div></div>`;
  }).join('');

  const banner = a.server_banner
    ? `<span class="banner-tag">⚠ Server: ${esc(a.server_banner)}</span>` : '';
  const p=Object.keys(a.present_headers||{}).length, f=(a.missing_headers||[]).length;

  return `<div class="card audit-block">
    <h2>🔒 HTTP Header Audit</h2>
    <div class="audit-url-row"><code>${esc(a.target_url)}</code>${banner}</div>
    ${rows}
    <div class="sum-row">
      <span class="sum-p">✔ ${p} present</span>
      <span class="sum-f">✗ ${f} missing</span>
      <span style="color:#334155">/ ${p+f} checks</span>
    </div></div>`;
}

// ── history ───────────────────────────────────────────────────────────────
async function loadHistory() {
  const r = await fetch('/api/history');
  const h = await r.json();
  const el = document.getElementById('hist-list');
  if (!h.length){el.innerHTML='<div style="color:#334155;font-size:12px">No scans yet.</div>';return}
  el.innerHTML = h.slice(0,8).map(x=>`
    <div class="hist-item" onclick="document.getElementById('target').value='${esc(x.target)}'">
      <div class="hist-target">${esc(x.target)}</div>
      <div class="hist-meta">${esc(x.label)} · ${x.open_ports} open · ${x.missing} missing · ${x.mode.toUpperCase()}</div>
      <div class="hist-meta">${esc(x.scanned_at)}</div>
    </div>`).join('');
}

// ── quick targets sidebar ─────────────────────────────────────────────────
async function loadQuickTargets() {
  const r = await fetch('/api/demo-targets');
  const targets = await r.json();
  const el = document.getElementById('qt-list');
  el.innerHTML = targets.map(t => {
    const dotClass = t.missing_count===0 ? 'dot-open' : (t.missing_count<=2 ? 'dot-open' : 'dot-warn');
    return `<div class="qt-item" id="qt-${t.ip.replace(/\./g,'-')}" onclick="pickTarget('${esc(t.ip)}')">
      <div class="qt-dot ${dotClass}"></div>
      <div class="qt-info">
        <div class="qt-ip">${esc(t.ip)}</div>
        <div class="qt-lbl">${esc(t.label)}</div>
      </div>
      <div class="qt-counts">
        <div class="qt-open">${t.open_count} open</div>
        <div class="qt-miss">${t.missing_count} miss</div>
      </div>
    </div>`;
  }).join('');
}

function pickTarget(ip) {
  document.getElementById('target').value = ip;
  document.querySelectorAll('.qt-item').forEach(e=>e.classList.remove('active'));
  const el = document.getElementById('qt-'+ip.replace(/\./g,'-'));
  if (el) el.classList.add('active');
  document.getElementById('scan-btn').focus();
}

// ── export ────────────────────────────────────────────────────────────────
function exportJSON() {
  if (!_last) return;
  const blob = new Blob([JSON.stringify(_last,null,2)],{type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `sec-audit-${_last.target}-${Date.now()}.json`;
  a.click(); URL.revokeObjectURL(a.href);
}

// ── keyboard shortcut ─────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key==='Enter' && document.activeElement.tagName==='INPUT') runScan();
});

// ── init ──────────────────────────────────────────────────────────────────
loadQuickTargets();
loadHistory();
</script>
</body>
</html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "="*55)
    print("  sec-auditor — IBM Prototype Launcher")
    print("="*55)
    print(f"  URL  →  http://127.0.0.1:{port}")
    print(f"  Mode →  {'LIVE + DEMO' if REAL_SCAN_AVAILABLE else 'DEMO ONLY (install sec_auditor package for live)'}")
    print("  Stop →  Ctrl+C")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
