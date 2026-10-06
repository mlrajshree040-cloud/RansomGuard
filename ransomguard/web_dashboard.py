import os
import threading
import time
from flask import Flask, render_template_string, jsonify, send_from_directory, request
from ransomguard import config, state, scanner_state
from ransomguard.scanner import SystemScanner
from ransomguard.screenshot import SCREENSHOT_FOLDER, get_capture

app = Flask(__name__)

HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RansomGuard — Enterprise Threat Console</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  html, body {
    height:100%;
    font-family:'Inter','Segoe UI',-apple-system,sans-serif;
    background:#05080f; color:#e6edf3;
    overflow:hidden;
    -webkit-font-smoothing:antialiased;
  }

  #bg {
    position:fixed; inset:0; z-index:0;
    background:
      radial-gradient(circle at 20% 30%, rgba(88,166,255,0.10), transparent 50%),
      radial-gradient(circle at 80% 70%, rgba(255,123,114,0.08), transparent 50%),
      radial-gradient(circle at 50% 50%, rgba(63,185,80,0.05), transparent 60%),
      #05080f;
  }
  #particles { position:fixed; inset:0; z-index:1; }

  .app {
    position:relative;
    z-index:2;
    height:100vh;
    display:grid;
    grid-template-columns: 300px 1fr;
    gap:20px;
    padding:20px;
    overflow:hidden;
  }

  .sidebar {
    background:rgba(13,17,23,0.75);
    backdrop-filter:blur(24px);
    border:1px solid #21262d;
    border-radius:18px;
    display:flex;
    flex-direction:column;
    overflow:hidden;
    animation:slideRight 0.6s ease;
  }
  @keyframes slideRight {
    from { opacity:0; transform:translateX(-20px); }
    to   { opacity:1; transform:translateX(0); }
  }

  .sidebar-brand {
    display:flex; align-items:center; gap:12px;
    padding:22px 20px; border-bottom:1px solid #21262d; flex-shrink:0;
  }
  .logo {
    width:44px; height:44px; border-radius:12px;
    background:linear-gradient(135deg,#1f6feb,#58a6ff);
    display:flex; align-items:center; justify-content:center;
    font-size:22px; box-shadow:0 0 24px rgba(88,166,255,0.45);
    flex-shrink:0; animation:float 4s ease-in-out infinite;
  }
  @keyframes float {
    0%,100% { transform:translateY(0); }
    50%     { transform:translateY(-3px); }
  }
  .brand-text h1 {
    font-size:15px; font-weight:700; letter-spacing:-0.2px;
    background:linear-gradient(90deg,#e6edf3,#8b949e);
    -webkit-background-clip:text; background-clip:text;
    -webkit-text-fill-color:transparent; white-space:nowrap;
  }
  .brand-text p {
    font-size:9.5px; color:#6e7681; margin-top:2px;
    letter-spacing:0.8px; text-transform:uppercase;
  }

  .nav { flex:1; overflow-y:auto; padding:0; }
  .nav::-webkit-scrollbar { width:4px; }
  .nav::-webkit-scrollbar-thumb { background:#30363d; border-radius:2px; }

  .nav-list { display:flex; flex-direction:column; gap:0; width:100%; }

  .nav-btn {
    display:flex; align-items:center; gap:12px;
    width:100%; padding:13px 18px;
    border:none; border-bottom:1px solid #161b22;
    background:transparent; color:#8b949e;
    font-size:13px; font-weight:500; cursor:pointer;
    transition:all 0.2s; text-align:left; font-family:inherit;
    position:relative;
  }
  .nav-btn:last-child { border-bottom:none; }
  .nav-btn:hover {
    background:rgba(255,255,255,0.04); color:#c9d1d9; padding-left:22px;
  }
  .nav-btn.active {
    background:linear-gradient(90deg,rgba(88,166,255,0.14),rgba(88,166,255,0.02));
    color:#79c0ff; font-weight:600;
  }
  .nav-btn.active::before {
    content:''; position:absolute; left:0; top:10px; bottom:10px;
    width:3px; background:#58a6ff; border-radius:0 3px 3px 0;
    box-shadow:0 0 12px #58a6ff;
  }
  .nav-btn .num {
    font-family:'JetBrains Mono',monospace;
    font-size:11px; font-weight:700; color:#484f58;
    width:16px; text-align:right; flex-shrink:0; transition:color 0.2s;
  }
  .nav-btn:hover .num { color:#6e7681; }
  .nav-btn.active .num { color:#58a6ff; }
  .nav-btn .icon { font-size:15px; width:20px; text-align:center; flex-shrink:0; }
  .nav-btn .label { flex:1; }
  .nav-btn .count {
    font-family:'JetBrains Mono',monospace;
    font-size:10px; font-weight:700;
    padding:2px 8px; border-radius:8px;
    background:rgba(139,148,158,0.15); color:#8b949e;
    min-width:24px; text-align:center; transition:all 0.3s;
  }
  .nav-btn.active .count { background:rgba(88,166,255,0.22); color:#79c0ff; }
  .nav-btn .count.red { background:rgba(248,81,73,0.15); color:#ff7b72; }
  .nav-btn .count.green { background:rgba(63,185,80,0.15); color:#3fb950; }
  .nav-btn .count.purple { background:rgba(163,113,247,0.15); color:#a371f7; }
  .nav-btn .count.yellow { background:rgba(210,153,34,0.15); color:#d29922; }
  .nav-btn .count.blue { background:rgba(88,166,255,0.15); color:#58a6ff; }

  .sidebar-foot {
    padding:16px 20px; border-top:1px solid #21262d;
    font-family:'JetBrains Mono',monospace; flex-shrink:0;
  }
  .clock-time { font-size:18px; font-weight:700; color:#e6edf3; letter-spacing:-0.3px; }
  .clock-date { font-size:10.5px; color:#6e7681; margin-top:3px; }

  .main {
    overflow-y:auto; padding-right:4px; animation:fadeIn 0.6s ease;
  }
  @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
  .main::-webkit-scrollbar { width:8px; }
  .main::-webkit-scrollbar-track { background:transparent; }
  .main::-webkit-scrollbar-thumb { background:#21262d; border-radius:4px; }

  .status {
    border-radius:16px; padding:24px 28px; margin-bottom:16px;
    display:flex; align-items:center; justify-content:space-between;
    border:1px solid; backdrop-filter:blur(20px);
    position:relative; overflow:hidden;
    transition:all 0.4s cubic-bezier(0.4,0,0.2,1);
    animation:fadeUp 0.5s ease;
  }
  .status::before {
    content:''; position:absolute; inset:0;
    background:linear-gradient(90deg,transparent,rgba(255,255,255,0.06),transparent);
    transform:translateX(-100%); animation:shimmer 3s infinite;
  }
  @keyframes shimmer { 100% { transform:translateX(100%); } }
  .status.safe {
    background:linear-gradient(135deg,rgba(35,134,54,0.12),rgba(35,134,54,0.02));
    border-color:rgba(63,185,80,0.35);
    box-shadow:0 0 30px rgba(35,134,54,0.1);
  }
  .status.threat {
    background:linear-gradient(135deg,rgba(248,81,73,0.15),rgba(248,81,73,0.03));
    border-color:rgba(248,81,73,0.5);
    animation:pulseRed 1.2s ease-in-out infinite;
  }
  .status.contained {
    background:linear-gradient(135deg,rgba(31,111,235,0.15),rgba(31,111,235,0.03));
    border-color:rgba(88,166,255,0.5);
  }
  @keyframes pulseRed {
    0%,100% { box-shadow:0 0 40px rgba(248,81,73,0.2); }
    50%     { box-shadow:0 0 60px rgba(248,81,73,0.45); }
  }
  .status-left { display:flex; align-items:center; gap:16px; z-index:1; }
  .status-icon {
    width:48px; height:48px; border-radius:12px;
    display:flex; align-items:center; justify-content:center;
    font-size:24px; flex-shrink:0;
    filter:drop-shadow(0 0 12px currentColor);
  }
  .status.safe .status-icon { color:#3fb950; }
  .status.threat .status-icon { color:#ff7b72; }
  .status.contained .status-icon { color:#79c0ff; }
  .status-title { font-size:17px; font-weight:700; letter-spacing:0.3px; }
  .status.safe .status-title { color:#3fb950; }
  .status.threat .status-title { color:#ff7b72; }
  .status.contained .status-title { color:#79c0ff; }
  .status-sub { font-size:12px; color:#8b949e; margin-top:4px; }
  .status-right { text-align:right; z-index:1; }
  .status-label { font-size:9.5px; color:#8b949e; letter-spacing:2px; text-transform:uppercase; }
  .status-value {
    font-family:'JetBrains Mono',monospace; font-size:28px; font-weight:700;
    line-height:1; margin-top:4px;
  }

  .metrics {
    display:grid; grid-template-columns:repeat(7,1fr); gap:10px;
    margin-bottom:16px; animation:fadeUp 0.6s ease;
  }
  .metric {
    background:rgba(22,27,34,0.6); border:1px solid #21262d;
    border-radius:12px; padding:13px 14px;
    backdrop-filter:blur(20px); transition:all 0.25s;
    position:relative; overflow:hidden;
  }
  .metric::before {
    content:''; position:absolute; top:0; left:0; right:0; height:2px;
    background:currentColor; opacity:0.6;
  }
  .metric:hover { border-color:#30363d; transform:translateY(-2px); box-shadow:0 8px 20px rgba(0,0,0,0.3); }
  .metric-label { font-size:9px; color:#8b949e; letter-spacing:1.2px; text-transform:uppercase; margin-bottom:5px; }
  .metric-value { font-family:'JetBrains Mono',monospace; font-size:20px; font-weight:700; line-height:1; }
  .metric.green { color:#3fb950; }
  .metric.green .metric-value { color:#3fb950; }
  .metric.blue { color:#58a6ff; }
  .metric.blue .metric-value { color:#58a6ff; }
  .metric.purple { color:#a371f7; }
  .metric.purple .metric-value { color:#a371f7; }
  .metric.yellow { color:#d29922; }
  .metric.yellow .metric-value { color:#d29922; }
  .metric.red { color:#ff7b72; }
  .metric.red .metric-value { color:#ff7b72; }

  .scan-bar {
    background:rgba(22,27,34,0.6); border:1px solid #21262d;
    border-radius:12px; padding:16px 20px; margin-bottom:16px;
    display:flex; align-items:center; gap:14px;
    backdrop-filter:blur(20px); animation:fadeUp 0.6s ease;
  }
  .scan-bar .icon {
    width:38px; height:38px; border-radius:10px;
    background:linear-gradient(135deg,#1f6feb,#58a6ff);
    display:flex; align-items:center; justify-content:center;
    font-size:17px; flex-shrink:0;
  }
  .scan-bar .info { flex:1; min-width:0; }
  .scan-bar .title { font-size:13px; font-weight:600; color:#c9d1d9; letter-spacing:0.3px; }
  .scan-bar .sub { font-size:11px; color:#6e7681; margin-top:2px; font-family:'JetBrains Mono',monospace; }
  .scan-btn {
    padding:10px 20px; border-radius:9px; border:none;
    font-size:11.5px; font-weight:600; letter-spacing:0.6px;
    cursor:pointer; transition:all 0.2s; text-transform:uppercase;
    font-family:inherit; flex-shrink:0;
  }
  .scan-btn.start {
    background:linear-gradient(135deg,#238636,#2ea043);
    color:white; box-shadow:0 4px 14px rgba(35,134,54,0.3);
  }
  .scan-btn.cancel {
    background:linear-gradient(135deg,#da3633,#f85149);
    color:white; box-shadow:0 4px 14px rgba(218,54,51,0.3);
  }
  .scan-btn:hover { transform:translateY(-1px); }

  .scan-progress-wrap {
    display:none; margin-bottom:16px;
    background:rgba(22,27,34,0.6); border:1px solid #21262d;
    border-radius:12px; padding:14px 18px; backdrop-filter:blur(20px);
  }
  .scan-progress-wrap.active { display:block; }
  .progress-bar {
    height:6px; background:#161b22; border-radius:3px;
    overflow:hidden; margin-bottom:8px;
  }
  .progress-fill {
    height:100%; width:0%;
    background:linear-gradient(90deg,#1f6feb,#58a6ff);
    border-radius:3px; transition:width 0.3s;
    position:relative; overflow:hidden;
  }
  .progress-fill::after {
    content:''; position:absolute; inset:0;
    background:linear-gradient(90deg,transparent,rgba(255,255,255,0.3),transparent);
    animation:shimmer 1.5s infinite;
  }
  .scan-meta {
    display:flex; justify-content:space-between;
    font-size:11px; color:#8b949e; font-family:'JetBrains Mono',monospace;
  }
  .scan-meta .val { color:#e6edf3; font-weight:600; }

  .panel {
    background:rgba(22,27,34,0.6); border:1px solid #21262d;
    border-radius:14px; backdrop-filter:blur(20px);
    overflow:hidden; animation:fadeUp 0.7s ease; min-height:320px;
  }
  .panel-head {
    padding:16px 22px; border-bottom:1px solid #21262d;
    display:flex; align-items:center; justify-content:space-between;
    background:rgba(13,17,23,0.4);
  }
  .panel-head-title {
    font-size:12.5px; font-weight:600; letter-spacing:1px;
    text-transform:uppercase; color:#c9d1d9;
    display:flex; align-items:center; gap:10px;
  }
  .panel-head-title .dot {
    width:8px; height:8px; border-radius:50%;
    background:#3fb950; box-shadow:0 0 10px #3fb950;
    animation:dotPulse 2s infinite;
  }
  @keyframes dotPulse {
    0%,100% { opacity:1; }
    50%     { opacity:0.35; }
  }
  .panel-head-count {
    font-size:10.5px; color:#6e7681;
    font-family:'JetBrains Mono',monospace;
  }
  .panel-body {
    padding:16px 22px; max-height:calc(100vh - 400px);
    overflow-y:auto;
  }
  .panel-body::-webkit-scrollbar { width:6px; }
  .panel-body::-webkit-scrollbar-thumb { background:#30363d; border-radius:3px; }

  .view { display:none; }
  .view.active { display:block; animation:fadeUp 0.35s ease; }

  .evt {
    display:grid; grid-template-columns:80px 100px 1fr; gap:14px;
    padding:10px 0; border-bottom:1px solid #161b22;
    font-size:12px; font-family:'JetBrains Mono',monospace;
    animation:slideIn 0.3s ease;
  }
  .evt:last-child { border-bottom:none; }
  .evt .t { color:#6e7681; }
  .evt .e { font-weight:600; }
  .evt .e.modified { color:#d29922; }
  .evt .e.created  { color:#58a6ff; }
  .evt .e.deleted  { color:#f85149; }
  .evt .e.moved    { color:#a371f7; }
  .evt .f { color:#c9d1d9; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }

  .integ-row {
    display:grid; grid-template-columns:24px 1fr; gap:12px;
    padding:12px 0; border-bottom:1px solid #161b22;
    font-size:12px; animation:slideIn 0.3s ease;
  }
  .integ-row:last-child { border-bottom:none; }
  .integ-icon {
    width:20px; height:20px; border-radius:50%;
    display:flex; align-items:center; justify-content:center;
    font-size:10px; font-weight:700;
  }
  .integ-icon.ok {
    background:rgba(63,185,80,0.15); color:#3fb950;
    box-shadow:0 0 10px rgba(63,185,80,0.25);
  }
  .integ-file { color:#e6edf3; font-weight:500; margin-bottom:3px; font-size:12.5px; }
  .integ-hash {
    font-family:'JetBrains Mono',monospace; font-size:10.5px;
    color:#6e7681; word-break:break-all; line-height:1.5;
  }
  .integ-hash .match { color:#3fb950; }

  .threat-item {
    padding:12px 14px; background:rgba(248,81,73,0.07);
    border-left:3px solid #f85149; border-radius:6px;
    margin-bottom:9px; font-size:12px; color:#ffa198;
    animation:slideIn 0.3s ease;
  }
  .empty {
    color:#6e7681; text-align:center; padding:60px 20px;
    font-size:12.5px; font-style:italic;
  }

  .ss-grid {
    display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr));
    gap:16px;
  }
  .ss-card {
    background:rgba(13,17,23,0.6); border:1px solid #21262d;
    border-radius:10px; overflow:hidden; transition:all 0.25s;
  }
  .ss-card:hover {
    border-color:#30363d; transform:translateY(-2px);
    box-shadow:0 8px 24px rgba(0,0,0,0.4);
  }
  .ss-head {
    padding:10px 12px; border-bottom:1px solid #21262d;
    background:rgba(13,17,23,0.5);
    display:flex; justify-content:space-between;
    font-size:11px; color:#8b949e; font-family:'JetBrains Mono',monospace;
  }
  .ss-thumb {
    padding:8px; background:#05080f; min-height:180px;
    display:flex; align-items:center; justify-content:center;
  }
  .ss-thumb img { width:100%; height:auto; border-radius:6px; display:block; }
  .ss-body { padding:10px 12px; }
  .ss-filename {
    font-family:'JetBrains Mono',monospace; font-size:10.5px;
    color:#6e7681; word-break:break-all; margin-bottom:6px;
  }
  .ss-reason { font-size:11.5px; color:#ffa198; line-height:1.4; }
  .ss-actions { margin-top:8px; display:flex; gap:8px; }
  .ss-btn {
    flex:1; padding:6px 10px; border-radius:6px;
    font-size:11px; text-align:center; text-decoration:none;
    font-weight:600; letter-spacing:0.5px; transition:all 0.2s;
  }
  .ss-btn.dl {
    background:rgba(88,166,255,0.15); color:#79c0ff;
    border:1px solid rgba(88,166,255,0.3);
  }
  .ss-btn.dl:hover { background:rgba(88,166,255,0.25); }
  .ss-btn.open {
    background:rgba(255,255,255,0.04); color:#c9d1d9;
    border:1px solid #30363d;
  }
  .ss-btn.open:hover { background:rgba(255,255,255,0.08); }

  .test-capture-btn {
    padding:6px 14px; border-radius:6px; border:none;
    background:linear-gradient(135deg,#1f6feb,#58a6ff);
    color:white; font-size:11px; font-weight:600;
    letter-spacing:0.5px; cursor:pointer;
    text-transform:uppercase; font-family:inherit;
    transition:all 0.2s;
  }
  .test-capture-btn:hover {
    transform:translateY(-1px);
    box-shadow:0 4px 12px rgba(88,166,255,0.4);
  }

  @keyframes fadeUp {
    from { opacity:0; transform:translateY(8px); }
    to   { opacity:1; transform:translateY(0); }
  }
  @keyframes slideIn {
    from { opacity:0; transform:translateX(-6px); }
    to   { opacity:1; transform:translateX(0); }
  }

  @media (max-width: 1400px) { .metrics { grid-template-columns:repeat(4,1fr); } }
  @media (max-width: 1200px) { .metrics { grid-template-columns:repeat(3,1fr); } }
  @media (max-width: 900px) {
    .app { grid-template-columns:1fr; padding:14px; }
    .sidebar { display:none; }
    .metrics { grid-template-columns:repeat(2,1fr); }
  }
</style>
</head>
<body>

<canvas id="particles"></canvas>
<div id="bg"></div>

<div class="app">

  <aside class="sidebar">
    <div class="sidebar-brand">
      <div class="logo">🛡️</div>
      <div class="brand-text">
        <h1>RansomGuard</h1>
        <p>Threat Console v3.0</p>
      </div>
    </div>

    <nav class="nav">
      <div class="nav-list">

        <button class="nav-btn active" data-tab="overview" onclick="showTab('overview')">
          <span class="num">1</span>
          <span class="icon">📊</span>
          <span class="label">Overview</span>
        </button>

        <button class="nav-btn" data-tab="events" onclick="showTab('events')">
          <span class="num">2</span>
          <span class="icon">📄</span>
          <span class="label">Events</span>
          <span class="count" id="nav-count-events">0</span>
        </button>

        <button class="nav-btn" data-tab="integrity" onclick="showTab('integrity')">
          <span class="num">3</span>
          <span class="icon">🔐</span>
          <span class="label">Integrity</span>
          <span class="count green" id="nav-count-integrity">0</span>
        </button>

        <button class="nav-btn" data-tab="threat" onclick="showTab('threat')">
          <span class="num">4</span>
          <span class="icon">🚨</span>
          <span class="label">Threat</span>
          <span class="count red" id="nav-count-threat">0</span>
        </button>

        <button class="nav-btn" data-tab="yara" onclick="showTab('yara')">
          <span class="num">5</span>
          <span class="icon">🛡️</span>
          <span class="label">YARA</span>
          <span class="count purple" id="nav-count-yara">0</span>
        </button>

        <button class="nav-btn" data-tab="selfdefense" onclick="showTab('selfdefense')">
          <span class="num">6</span>
          <span class="icon">🔒</span>
          <span class="label">Defense</span>
          <span class="count yellow" id="nav-count-tamper">0</span>
        </button>

        <button class="nav-btn" data-tab="screenshots" onclick="showTab('screenshots')">
          <span class="num">7</span>
          <span class="icon">📸</span>
          <span class="label">Screenshots</span>
          <span class="count blue" id="nav-count-screenshots">0</span>
        </button>

        <button class="nav-btn" data-tab="sandbox" onclick="showTab('sandbox')">
          <span class="num">8</span>
          <span class="icon">🧪</span>
          <span class="label">Sandbox</span>
          <span class="count red" id="nav-count-sandbox">0</span>
        </button>

      </div>
    </nav>

    <div class="sidebar-foot">
      <div class="clock-time" id="clock">--:--:--</div>
      <div class="clock-date" id="date">----</div>
    </div>
  </aside>

  <main class="main">

    <div id="status-banner" class="status safe">
      <div class="status-left">
        <div class="status-icon" id="status-icon">🛡️</div>
        <div>
          <div class="status-title" id="status-title">SYSTEM SAFE</div>
          <div class="status-sub" id="status-sub">All protected files verified · No threats detected</div>
        </div>
      </div>
      <div class="status-right">
        <div class="status-label">Integrity</div>
        <div class="status-value" id="status-value" style="color:#3fb950;">100%</div>
      </div>
    </div>

    <div class="metrics">
      <div class="metric green">
        <div class="metric-label">Files Protected</div>
        <div class="metric-value" id="stat-files">0</div>
      </div>
      <div class="metric blue">
        <div class="metric-label">Decoy Files</div>
        <div class="metric-value" id="stat-decoys">0</div>
      </div>
      <div class="metric purple">
        <div class="metric-label">Honeypot</div>
        <div class="metric-value" id="stat-honeypot">4</div>
      </div>
      <div class="metric yellow">
        <div class="metric-label">Quarantine</div>
        <div class="metric-value" id="stat-quarantine">0</div>
      </div>
      <div class="metric red">
        <div class="metric-label">YARA</div>
        <div class="metric-value" id="stat-yara">0</div>
      </div>
      <div class="metric purple">
        <div class="metric-label">Tamper</div>
        <div class="metric-value" id="stat-tamper">0</div>
      </div>
      <div class="metric blue">
        <div class="metric-label">Screenshots</div>
        <div class="metric-value" id="stat-screenshots">0</div>
      </div>
    </div>

    <div class="scan-bar">
      <div class="icon">🔍</div>
      <div class="info">
        <div class="title">Full System Scanner</div>
        <div class="sub" id="scan-status-text">Ready to scan your entire system</div>
      </div>
      <button id="scan-btn" class="scan-btn start" onclick="toggleScan()">Start Scan</button>
    </div>

    <div id="scan-progress-wrap" class="scan-progress-wrap">
      <div class="progress-bar">
        <div id="progress-fill" class="progress-fill"></div>
      </div>
      <div class="scan-meta">
        <span>Scanned: <span class="val" id="scan-scanned">0</span></span>
        <span>Threats: <span class="val" id="scan-threats-count" style="color:#ff7b72;">0</span></span>
        <span>Duration: <span class="val" id="scan-time">0s</span></span>
      </div>
      <div id="scan-current" style="font-size:10.5px;color:#6e7681;font-family:monospace;margin-top:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">Preparing…</div>
    </div>

    <div id="scan-results-wrap" style="display:none;margin-bottom:16px;">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-head-title">
            <span class="dot" style="background:#58a6ff;box-shadow:0 0 10px #58a6ff;"></span>
            Scan Results
          </div>
          <div class="panel-head-count" id="scan-result-count">0 files scanned</div>
        </div>
        <div class="panel-body" style="max-height:280px;">
          <div id="scan-result-body"></div>
        </div>
      </div>
    </div>

    <div class="view active" id="view-overview">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-head-title">
            <span class="dot"></span> System Overview
          </div>
        </div>
        <div class="panel-body" style="max-height:400px;">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
            <div>
              <div style="font-size:10.5px;color:#8b949e;letter-spacing:1.2px;text-transform:uppercase;margin-bottom:10px;">Active Protection Layers</div>
              <div style="display:flex;flex-direction:column;gap:9px;font-size:12.5px;">
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> Real-time File Monitor</div>
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> Decoy Tripwires</div>
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> Honeypot Shares</div>
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> YARA Signature Engine</div>
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> ML Classifier (Random Forest)</div>
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> SHA-256 Vault &amp; Auto-Rollback</div>
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> Self-Defense / Anti-Tamper</div>
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> Quarantine System</div>
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> Forensic Screenshot Capture</div>
                <div style="display:flex;align-items:center;gap:10px;"><span style="color:#3fb950;">●</span> Sandbox Detonation</div>
              </div>
            </div>
            <div>
              <div style="font-size:10.5px;color:#8b949e;letter-spacing:1.2px;text-transform:uppercase;margin-bottom:10px;">Detection Signals</div>
              <div style="display:flex;flex-direction:column;gap:10px;font-size:12px;">
                <div style="display:flex;justify-content:space-between;"><span>Honeypot Touch</span><b style="color:#3fb950;">200</b></div>
                <div style="display:flex;justify-content:space-between;"><span>Decoy Touch</span><b style="color:#3fb950;">100</b></div>
                <div style="display:flex;justify-content:space-between;"><span>YARA Match</span><b style="color:#a371f7;">80</b></div>
                <div style="display:flex;justify-content:space-between;"><span>Ransomware Ext</span><b style="color:#d29922;">60</b></div>
                <div style="display:flex;justify-content:space-between;"><span>ML Ransomware</span><b style="color:#58a6ff;">50</b></div>
                <div style="display:flex;justify-content:space-between;"><span>Mass File Ops</span><b style="color:#d29922;">40</b></div>
                <div style="display:flex;justify-content:space-between;"><span>High Entropy</span><b style="color:#8b949e;">30</b></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="view" id="view-events">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-head-title"><span class="dot"></span> Recent File Events</div>
          <div class="panel-head-count" id="event-count">0 events</div>
        </div>
        <div class="panel-body" id="events-body">
          <div class="empty">No events yet…</div>
        </div>
      </div>
    </div>

    <div class="view" id="view-integrity">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-head-title"><span class="dot" style="background:#58a6ff;box-shadow:0 0 10px #58a6ff;"></span> File Integrity (SHA-256)</div>
          <div class="panel-head-count" id="integ-count">0 files</div>
        </div>
        <div class="panel-body" id="integrity-body">
          <div class="empty">No files in vault yet…</div>
        </div>
      </div>
    </div>

    <div class="view" id="view-threat">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-head-title"><span class="dot" style="background:#f85149;box-shadow:0 0 10px #f85149;"></span> Threat &amp; Recovery Log</div>
        </div>
        <div class="panel-body" id="threat-body">
          <div class="empty">No active threat. System is monitoring.</div>
        </div>
      </div>
    </div>

    <div class="view" id="view-yara">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-head-title"><span class="dot" style="background:#a371f7;box-shadow:0 0 10px #a371f7;"></span> YARA Rule Hits</div>
          <div class="panel-head-count" id="yara-count-label">0 matches</div>
        </div>
        <div class="panel-body" id="yara-body">
          <div class="empty">No YARA matches yet. Signature engine is armed.</div>
        </div>
      </div>
    </div>

    <div class="view" id="view-selfdefense">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-head-title"><span class="dot" style="background:#d29922;box-shadow:0 0 10px #d29922;"></span> Self-Defense Log</div>
          <div class="panel-head-count" id="tamper-status">🟢 Protected</div>
        </div>
        <div class="panel-body" id="tamper-body">
          <div class="empty">No tamper attempts. Defender is intact.</div>
        </div>
      </div>
    </div>

    <div class="view" id="view-screenshots">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-head-title">
            <span class="dot" style="background:#58a6ff;box-shadow:0 0 10px #58a6ff;"></span>
            Screenshot Evidence
          </div>
          <div style="display:flex;gap:10px;align-items:center;">
            <div class="panel-head-count" id="screenshot-count-label">0 captures</div>
            <button class="test-capture-btn" onclick="testCapture()">📸 Test Capture</button>
          </div>
        </div>
        <div class="panel-body" id="screenshots-body">
          <div class="empty">No screenshots yet. Click "Test Capture" or trigger an attack.</div>
        </div>
      </div>
    </div>

    <div class="view" id="view-sandbox">
      <div class="panel">
        <div class="panel-head">
          <div class="panel-head-title">
            <span class="dot" style="background:#f85149;box-shadow:0 0 10px #f85149;"></span>
            Sandbox Detonation
          </div>
          <div style="display:flex;gap:10px;align-items:center;">
            <div class="panel-head-count" id="sandbox-count-label">0 detonations</div>
            <button class="test-capture-btn" onclick="runSandboxTest()">🧪 Test Detonation</button>
          </div>
        </div>
        <div class="panel-body" id="sandbox-body">
          <div class="empty">No detonations yet. Click "Test Detonation" to try.</div>
        </div>
      </div>
    </div>

  </main>
</div>

<script>
// ===== Particle background =====
const canvas = document.getElementById('particles');
const ctx = canvas.getContext('2d');
let W, H, particles = [];
const PCOUNT = 55;
function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
resize();
window.addEventListener('resize', resize);
for (let i=0;i<PCOUNT;i++) {
  particles.push({
    x: Math.random()*W, y: Math.random()*H,
    vx: (Math.random()-0.5)*0.35, vy: (Math.random()-0.5)*0.35,
    r: Math.random()*1.6+0.6,
  });
}
function draw() {
  ctx.clearRect(0,0,W,H);
  for (let i=0;i<particles.length;i++) {
    for (let j=i+1;j<particles.length;j++) {
      const dx = particles[i].x - particles[j].x;
      const dy = particles[i].y - particles[j].y;
      const d = Math.sqrt(dx*dx + dy*dy);
      if (d < 130) {
        ctx.strokeStyle = `rgba(88,166,255,${(1 - d/130) * 0.12})`;
        ctx.lineWidth = 0.6;
        ctx.beginPath();
        ctx.moveTo(particles[i].x, particles[i].y);
        ctx.lineTo(particles[j].x, particles[j].y);
        ctx.stroke();
      }
    }
  }
  for (const p of particles) {
    p.x += p.vx; p.y += p.vy;
    if (p.x < 0 || p.x > W) p.vx *= -1;
    if (p.y < 0 || p.y > H) p.vy *= -1;
    ctx.fillStyle = 'rgba(88,166,255,0.55)';
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
    ctx.fill();
  }
  requestAnimationFrame(draw);
}
draw();

// ===== Clock =====
function tick() {
  const d = new Date();
  const pad = n => String(n).padStart(2,'0');
  document.getElementById('clock').textContent =
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  document.getElementById('date').textContent =
    d.toLocaleDateString(undefined,{weekday:'short',day:'numeric',month:'short',year:'numeric'});
}
setInterval(tick, 1000);
tick();

// ===== Tab switching =====
function showTab(tabName) {
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const btn = document.querySelector(`.nav-btn[data-tab="${tabName}"]`);
  if (btn) btn.classList.add('active');
  const view = document.getElementById(`view-${tabName}`);
  if (view) view.classList.add('active');
}

// ===== Render state =====
let threatCount = 0;
let lastStatus = '';

function renderState(d) {
  const banner = document.getElementById('status-banner');
  if (d.status !== lastStatus) {
    banner.classList.remove('safe','threat','contained');
    banner.classList.add(d.status.toLowerCase());
    lastStatus = d.status;
  }
  const icon = document.getElementById('status-icon');
  const title = document.getElementById('status-title');
  const sub = document.getElementById('status-sub');
  const val = document.getElementById('status-value');

  if (d.status === 'SAFE') {
    icon.textContent = '🛡️';
    title.textContent = 'SYSTEM SAFE';
    sub.textContent = 'All protected files verified · No threats detected';
    val.style.color = '#3fb950';
    val.textContent = '100%';
  } else if (d.status === 'THREAT') {
    icon.textContent = '🚨';
    title.textContent = 'THREAT DETECTED — CONTAINING';
    sub.textContent = (d.threat && d.threat.reasons ? d.threat.reasons[0] : 'Analyzing…');
    val.style.color = '#ff7b72';
    val.textContent = (d.threat ? d.threat.severity : 0);
    if (lastStatus !== 'THREAT') threatCount++;
  } else if (d.status === 'CONTAINED') {
    icon.textContent = '✅';
    title.textContent = 'ATTACK CONTAINED — FILES RECOVERED';
    const rb = d.rollback || {};
    sub.textContent = `Restored ${rb.restored||0} · Removed ${rb.removed_rogue||0} rogue files`;
    val.style.color = '#79c0ff';
    val.textContent = '✓';
  }

  document.getElementById('stat-files').textContent = d.vault_files || 0;
  document.getElementById('stat-decoys').textContent = d.decoys || 0;
  document.getElementById('stat-honeypot').textContent = d.honeypot_shares || 4;
  document.getElementById('stat-quarantine').textContent = d.quarantine_count || 0;
  document.getElementById('stat-yara').textContent = d.yara_count || 0;
  document.getElementById('stat-tamper').textContent = d.tamper_count || 0;
  document.getElementById('stat-screenshots').textContent = d.screenshot_count || 0;

  const sdStatus = document.getElementById('tamper-status');
  if (sdStatus) sdStatus.textContent = d.selfdefense_active ? '🟢 Protected' : '🔴 Inactive';

  let intact = 0, total = 0;
  for (const [f, h] of Object.entries(d.integrity || {})) {
    total++;
    if (h && h.length === 64) intact++;
  }
  const pct = total ? Math.round((intact/total)*100) : 100;
  if (d.status === 'SAFE') {
    document.getElementById('status-value').textContent = pct + '%';
  }

  const events = d.events || [];
  document.getElementById('event-count').textContent = events.length + ' events';
  document.getElementById('nav-count-events').textContent = events.length;
  document.getElementById('events-body').innerHTML = events.length === 0
    ? '<div class="empty">No events yet…</div>'
    : events.map(e => `
        <div class="evt">
          <span class="t">${e.time}</span>
          <span class="e ${e.type}">${e.type}</span>
          <span class="f" title="${e.path}">${e.path}</span>
        </div>`).join('');

  const integ = d.integrity || {};
  const files = Object.keys(integ);
  document.getElementById('integ-count').textContent = files.length + ' files';
  document.getElementById('nav-count-integrity').textContent = files.length;
  document.getElementById('integrity-body').innerHTML = files.length === 0
    ? '<div class="empty">No files in vault yet…</div>'
    : files.map(f => {
        const h = integ[f];
        return `
          <div class="integ-row">
            <div class="integ-icon ok">✓</div>
            <div>
              <div class="integ-file">${f}</div>
              <div class="integ-hash">
                <span class="match">${h.substring(0,32)}</span>${h.substring(32)}
              </div>
            </div>
          </div>`;
      }).join('');

  const threatBody = document.getElementById('threat-body');
  const navCountThreat = document.getElementById('nav-count-threat');
  if (d.threat) {
    let html = `<div style="margin-bottom:12px;font-size:12.5px;color:#8b949e;">
      Detected at severity <b style="color:#ff7b72;">${d.threat.severity}</b></div>`;
    html += d.threat.reasons.map(r => `<div class="threat-item">⚠ ${r}</div>`).join('');
    if (d.rollback) {
      html += `<div style="margin-top:14px;padding:11px 13px;background:rgba(31,111,235,0.08);
                        border-left:3px solid #58a6ff;border-radius:6px;font-size:12px;color:#79c0ff;">
        ✓ Recovery complete — ${d.rollback.restored} files restored,
        ${d.rollback.removed_rogue} rogue files removed,
        ${d.rollback.failed} failed</div>`;
    }
    threatBody.innerHTML = html;
    navCountThreat.textContent = d.threat.reasons.length;
  } else {
    threatBody.innerHTML = '<div class="empty">No active threat. System is monitoring.</div>';
    navCountThreat.textContent = '0';
  }

  const ym = d.yara_matches || [];
  document.getElementById('yara-count-label').textContent = (d.yara_count || 0) + ' matches';
  document.getElementById('nav-count-yara').textContent = d.yara_count || 0;
  document.getElementById('yara-body').innerHTML = ym.length === 0
    ? '<div class="empty">No YARA matches yet. Signature engine is armed.</div>'
    : ym.map(m => {
        const sev = (m.severity || '').toLowerCase();
        let sevColor = '#3fb950';
        if (sev === 'critical' || sev === 'high' || sev === '10') sevColor = '#ff7b72';
        else if (sev === 'medium') sevColor = '#d29922';
        return `
          <div class="integ-row" style="grid-template-columns:30px 1fr;">
            <div class="integ-icon" style="background:rgba(163,113,247,0.15);color:#a371f7;width:22px;height:22px;">🛡️</div>
            <div>
              <div class="integ-file" style="display:flex;justify-content:space-between;">
                <span><b style="color:#e6edf3;">${m.rule}</b></span>
                <span style="font-size:10px;color:#6e7681;font-family:monospace;">${m.time}</span>
              </div>
              <div style="font-size:11px;color:#8b949e;margin-top:2px;">
                File: <span style="color:#c9d1d9;font-family:monospace;">${m.file}</span>
              </div>
              <div style="font-size:10.5px;color:#a371f7;margin-top:4px;">
                family: <b>${m.family}</b> · severity: <b style="color:${sevColor};">${m.severity}</b>
              </div>
            </div>
          </div>`;
      }).join('');

  const te = d.tamper_events || [];
  document.getElementById('nav-count-tamper').textContent = d.tamper_count || 0;
  document.getElementById('tamper-body').innerHTML = te.length === 0
    ? '<div class="empty">No tamper attempts. Defender is intact.</div>'
    : te.map(t => `
        <div class="threat-item" style="border-left-color:#d29922;background:rgba(210,153,34,0.07);color:#f0c674;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
            <b>⚠ ${t.kind}</b>
            <span style="font-size:10px;color:#6e7681;font-family:monospace;">${t.time}</span>
          </div>
          <div style="font-size:11.5px;color:#c9d1d9;">${t.target}</div>
          <div style="font-size:11px;color:#8b949e;margin-top:4px;">${t.detail}</div>
        </div>`).join('');

  const ss = d.screenshots || [];
  const ssBody = document.getElementById('screenshots-body');
  const ssLabel = document.getElementById('screenshot-count-label');
  const navCountSS = document.getElementById('nav-count-screenshots');
  if (ssBody) {
    ssLabel.textContent = (d.screenshot_count || 0) + ' captures';
    if (navCountSS) navCountSS.textContent = d.screenshot_count || 0;

    if (ss.length === 0) {
      ssBody.innerHTML = '<div class="empty">No screenshots yet. Click "Test Capture" or trigger an attack.</div>';
    } else {
      ssBody.innerHTML = `
        <div class="ss-grid">
          ${ss.map(s => `
            <div class="ss-card">
              <div class="ss-head">
                <span>🕐 ${s.time}</span>
                <span style="color:#58a6ff;">PNG</span>
              </div>
              <div class="ss-thumb">
                <img src="/api/screenshot/${encodeURIComponent(s.filename)}"
                     alt="${s.filename}"
                     onerror="this.style.display='none';this.parentElement.innerHTML='<div style=&quot;color:#6e7681;font-size:11px;padding:20px;text-align:center;&quot;>Preview unavailable</div>';">
              </div>
              <div class="ss-body">
                <div class="ss-filename">${s.filename}</div>
                <div class="ss-reason">⚠ ${s.reason}</div>
                <div class="ss-actions">
                  <a class="ss-btn dl" href="/api/screenshot/${encodeURIComponent(s.filename)}" download>⬇ Download</a>
                  <a class="ss-btn open" href="/api/screenshot/${encodeURIComponent(s.filename)}" target="_blank">🔍 Full Size</a>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      `;
    }
  }

  // ===== Sandbox =====
  const sbBody = document.getElementById('sandbox-body');
  const sbLabel = document.getElementById('sandbox-count-label');
  const navCountSB = document.getElementById('nav-count-sandbox');
  if (sbBody) {
    sbLabel.textContent = (d.sandbox_count || 0) + ' detonations';
    if (navCountSB) navCountSB.textContent = d.sandbox_count || 0;

    const hist = d.sandbox_history || [];
    if (hist.length === 0) {
      sbBody.innerHTML = '<div class="empty">No detonations yet. Click "Test Detonation" to try.</div>';
    } else {
      sbBody.innerHTML = hist.map(r => {
        let verdictColor = '#3fb950';
        if (r.verdict === 'MALICIOUS') verdictColor = '#ff7b72';
        else if (r.verdict === 'SUSPICIOUS') verdictColor = '#d29922';
        else if (r.verdict === 'SUSPECTED') verdictColor = '#a371f7';

        return `
          <div class="ss-card" style="margin-bottom:16px;">
            <div class="ss-head">
              <span>🧪 ${r.time || '--:--:--'}</span>
              <span style="color:${verdictColor};font-weight:700;">${r.verdict}</span>
            </div>
            <div class="ss-body">
              <div class="ss-filename">${r.file_path}</div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px;font-size:12px;">
                <div>⏱️ Duration: <b style="color:#79c0ff;">${r.duration}s</b></div>
                <div>📁 Files created: <b style="color:#d29922;">${(r.files_created||[]).length}</b></div>
                <div>✏️ Files modified: <b style="color:#d29922;">${(r.files_modified||[]).length}</b></div>
                <div>🗑️ Files deleted: <b style="color:#ff7b72;">${(r.files_deleted||[]).length}</b></div>
                <div>⚙️ Processes spawned: <b style="color:#a371f7;">${(r.processes_spawned||[]).length}</b></div>
                <div>🌐 Network: <b style="color:#ff7b72;">${r.network_attempts||0}</b></div>
              </div>
              <div style="margin-top:8px;font-size:12px;color:#8b949e;">
                <b style="color:${verdictColor};">Score: ${r.score}</b>
                ${r.timed_out ? ' · <span style="color:#d29922;">timed out</span>' : ''}
                ${r.error ? ` · <span style="color:#ff7b72;">${r.error}</span>` : ''}
              </div>
              ${r.notes && r.notes.length ? `
                <div style="margin-top:8px;padding:8px;background:rgba(248,81,73,0.05);border-radius:6px;font-size:11px;color:#ffa198;">
                  ${r.notes.map(n => `• ${n}`).join('<br>')}
                </div>
              ` : ''}
            </div>
          </div>
        `;
      }).join('');
    }
  }
}

async function refresh() {
  try {
    const r = await fetch('/api/state');
    const d = await r.json();
    renderState(d);
  } catch(e) {}
}
setInterval(refresh, 1000);
refresh();

async function testCapture() {
  try {
    const r = await fetch('/api/screenshot/test', { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      refresh();
    } else {
      alert('Capture failed: ' + (d.error || 'unknown'));
    }
  } catch(e) {
    alert('Request failed: ' + e.message);
  }
}

async function runSandboxTest() {
  try {
    const r = await fetch('/api/sandbox/test', { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      refresh();
    } else {
      alert('Sandbox failed: ' + (d.error || 'unknown'));
    }
  } catch(e) {
    alert('Request failed: ' + e.message);
  }
}

let scanRunning = false;
let scanStartedAt = 0;

async function toggleScan() {
  if (scanRunning) {
    await fetch('/api/scan/cancel');
    return;
  }
  await fetch('/api/scan/start', { method: 'POST' });
}

async function pollScan() {
  try {
    const r = await fetch('/api/scan/state');
    const s = await r.json();
    if (s.running) {
      scanRunning = true;
      if (!scanStartedAt) scanStartedAt = Date.now();
      document.getElementById('scan-btn').textContent = 'Cancel';
      document.getElementById('scan-btn').classList.remove('start');
      document.getElementById('scan-btn').classList.add('cancel');
      document.getElementById('scan-progress-wrap').classList.add('active');
      document.getElementById('scan-status-text').textContent = 'Scan in progress…';
      document.getElementById('scan-results-wrap').style.display = 'none';

      const scanned = s.scanned || 0;
      const threats = s.threats || 0;
      const elapsed = ((Date.now() - scanStartedAt) / 1000).toFixed(0);
      document.getElementById('scan-scanned').textContent = scanned;
      document.getElementById('scan-threats-count').textContent = threats;
      document.getElementById('scan-time').textContent = elapsed + 's';
      document.getElementById('scan-current').textContent =
        '📄 ' + (s.current || 'walking directories…').split('\\\\').pop();
      document.getElementById('progress-fill').style.width =
        Math.min(95, (scanned / 3000) * 100) + '%';
    } else {
      if (scanRunning) {
        scanRunning = false;
        scanStartedAt = 0;
        document.getElementById('scan-btn').textContent = 'Start Scan';
        document.getElementById('scan-btn').classList.remove('cancel');
        document.getElementById('scan-btn').classList.add('start');
        document.getElementById('progress-fill').style.width = '100%';
        document.getElementById('scan-status-text').textContent = 'Scan complete';
        if (s.result) {
          document.getElementById('scan-results-wrap').style.display = 'block';
          document.getElementById('scan-result-count').textContent =
            s.result.scanned + ' files scanned';
          const list = document.getElementById('scan-result-body');
          if (!s.result.threat_list || s.result.threat_list.length === 0) {
            list.innerHTML = '<div class="empty">✅ No threats detected. System is clean.</div>';
          } else {
            list.innerHTML = s.result.threat_list.map(t => `
              <div class="threat-item" style="margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
                  <b style="color:#ff7b72;">[${t.verdict}] ${t.name}</b>
                  <span style="font-size:10px;color:#6e7681;font-family:monospace;">
                    ${(t.size/1024).toFixed(1)} KB · entropy ${t.entropy}
                  </span>
                </div>
                <div style="font-size:11px;color:#8b949e;margin-bottom:6px;font-family:monospace;word-break:break-all;">
                  ${t.path}
                </div>
                ${t.reasons.map(r => `<div style="font-size:11.5px;color:#ffa198;">• ${r}</div>`).join('')}
              </div>
            `).join('');
          }
        }
      }
    }
  } catch(e) {}
}
setInterval(pollScan, 800);
pollScan();

document.addEventListener('keydown', e => {
  if (e.key === 'r' || e.key === 'R') {
    if (e.target.tagName === 'INPUT') return;
    fetch('/api/reset').then(() => refresh());
  }
});
</script>
</body>
</html>
"""


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/state")
def api_state():
    return jsonify(state.snapshot())


@app.route("/api/reset", methods=["POST", "GET"])
def api_reset():
    state.clear_threat()
    return {"ok": True}


@app.route("/api/screenshot/test", methods=["POST", "GET"])
def api_screenshot_test():
    import os as _os
    import time as _time
    try:
        cap = get_capture()
        path = cap.capture(tag="test")
        if path:
            filename = _os.path.basename(path)
            state.push_screenshot({
                "filename": filename,
                "path": path,
                "time": _time.strftime("%H:%M:%S"),
                "reason": "Manual test capture",
            })
            return {"ok": True, "path": path}
        return {"ok": False, "error": "capture returned None"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.route("/api/screenshot/<path:filename>")
def api_screenshot(filename):
    return send_from_directory(SCREENSHOT_FOLDER, filename)


@app.route("/api/sandbox/test", methods=["POST", "GET"])
def api_sandbox_test():
    import os as _os
    import time as _time
    try:
        from ransomguard.sandbox import SANDBOX_ROOT, get_sandbox
        test_path = _os.path.join(SANDBOX_ROOT, "sandbox_test.txt")
        with open(test_path, "w") as f:
            f.write("This is a harmless test file.\n")

        sb = get_sandbox()
        result = sb.detonate(test_path, timeout=3)
        d = result.to_dict()

        state.push_sandbox_result({
            **d,
            "time": _time.strftime("%H:%M:%S"),
        })

        try:
            _os.remove(test_path)
        except Exception:
            pass

        return {"ok": True, "result": d}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.route("/api/sandbox/detonate", methods=["POST"])
def api_sandbox_detonate():
    import os as _os
    import time as _time
    try:
        data = request.get_json() or {}
        path = data.get("path", "").strip()
        if not path or not _os.path.exists(path):
            return {"ok": False, "error": "File not found"}

        from ransomguard.sandbox import get_sandbox
        sb = get_sandbox()
        result = sb.detonate(path, timeout=5)
        d = result.to_dict()

        state.push_sandbox_result({
            **d,
            "time": _time.strftime("%H:%M:%S"),
        })

        return {"ok": True, "result": d}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.route("/api/scan/start", methods=["POST", "GET"])
def api_scan_start():
    if scanner_state.get_state()["running"]:
        return {"ok": False, "error": "Scan already running"}

    def run_scan():
        scanner = SystemScanner()
        scanner_state.start_scan(scanner.root_paths)
        def progress(scanned, threats, current):
            scanner_state.update_progress(scanned, threats, current)
        try:
            result = scanner.scan(progress_callback=progress)
            scanner_state.finish_scan(result)
        except Exception as e:
            import traceback
            traceback.print_exc()
            scanner_state.finish_scan({
                "scanned": 0, "threats": 0, "skipped": 0,
                "duration": 0, "threat_list": [],
                "roots": [], "timestamp": "", "error": str(e),
            })

    threading.Thread(target=run_scan, daemon=True).start()
    return {"ok": True, "message": "Scan started"}


@app.route("/api/scan/state")
def api_scan_state():
    return jsonify(scanner_state.get_state())


@app.route("/api/scan/cancel", methods=["POST", "GET"])
def api_scan_cancel():
    scanner_state.cancel_scan()
    return {"ok": True}


def start_dashboard(port=None):
    port = port or config.DASHBOARD_PORT
    t = threading.Thread(
        target=lambda: app.run(
            host="0.0.0.0", port=port,
            debug=False, use_reloader=False,
        ),
        daemon=True,
    )
    t.start()
    print(f"[Dashboard] Live at http://localhost:{port}") 