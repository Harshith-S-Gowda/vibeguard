// ShipSafe - Frontend Application Logic
let embeddedDataset = {};
let latestScanResult = null;

document.addEventListener("DOMContentLoaded", async () => {
  initEventListeners();
  await loadEmbeddedDataset();
  await runEmbeddedBenchmark();
});

function initEventListeners() {
  const sampleSelect = document.getElementById("sampleSelect");
  if (sampleSelect) {
    sampleSelect.addEventListener("change", (e) => {
      loadSelectedSample(e.target.value);
    });
  }

  const btnScan = document.getElementById("btnScanEmbedded");
  if (btnScan) {
    btnScan.addEventListener("click", runEmbeddedScan);
  }

  const btnRunBenchmarkTop = document.getElementById("btnRunBenchmarkTop");
  if (btnRunBenchmarkTop) {
    btnRunBenchmarkTop.addEventListener("click", runEmbeddedBenchmark);
  }

  const btnRefreshBenchmark = document.getElementById("btnRefreshBenchmark");
  if (btnRefreshBenchmark) {
    btnRefreshBenchmark.addEventListener("click", runEmbeddedBenchmark);
  }
}

async function loadEmbeddedDataset() {
  try {
    const res = await fetch("/api/embedded-dataset");
    const data = await res.json();
    embeddedDataset = {};
    if (data.dataset) {
      data.dataset.forEach(item => {
        embeddedDataset[item.id] = item;
      });
      // Default to EMB-06 (Arduin0Json)
      loadSelectedSample("EMB-06");
    }
  } catch (err) {
    console.error("Failed to load embedded dataset:", err);
  }
}

function loadSelectedSample(sampleId) {
  const item = embeddedDataset[sampleId];
  if (!item) return;

  document.getElementById("inputPkgName").value = item.pkg_name;
  document.getElementById("inputPublisher").value = item.publisher;
  document.getElementById("codeEditor").value = item.code.trim();

  const devProf = item.device_profile || {};
  if (devProf.device_type) {
    document.getElementById("targetBoardSelect").value = devProf.device_type;
  }
  if (devProf.library_purpose) {
    document.getElementById("libraryPurposeSelect").value = devProf.library_purpose;
  }
  document.getElementById("allowNetworkToggle").checked = !!devProf.allow_network;

  updateEditorStatusBadge("Loaded: " + item.pkg_name, "badge-neutral");
  runEmbeddedScan();
}

async function runEmbeddedScan() {
  const pkgName = document.getElementById("inputPkgName").value.trim();
  const publisher = document.getElementById("inputPublisher").value.trim();
  const board = document.getElementById("targetBoardSelect").value;
  const purpose = document.getElementById("libraryPurposeSelect").value;
  const allowNetwork = document.getElementById("allowNetworkToggle").checked;
  const code = document.getElementById("codeEditor").value;

  const diagnostics = document.getElementById("diagnosticsContent");
  const latencyBadge = document.getElementById("scanLatencyBadge");

  latencyBadge.innerText = "Scanning...";

  const payload = {
    pkg_name: pkgName,
    publisher: publisher,
    code: code,
    device_profile: {
      device_type: board,
      library_purpose: purpose,
      allow_network: allowNetwork
    }
  };

  try {
    const res = await fetch("/api/scan-embedded", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    latestScanResult = data;

    latencyBadge.innerText = `${data.latency_ms.toFixed(2)} ms`;

    renderEmbeddedDiagnostics(data, diagnostics);
  } catch (err) {
    console.error("Embedded scan failed:", err);
    diagnostics.innerHTML = `<div class="empty-state"><p style="color: #f43f5e;">Scan error: ${err.message}</p></div>`;
  }
}

function renderEmbeddedDiagnostics(data, container) {
  const isSuspicious = data.deterministic_verdict === "SUSPICIOUS" || data.rf_classification.verdict === "SUSPICIOUS";
  updateEditorStatusBadge(isSuspicious ? "SUSPICIOUS PACKAGE" : "LEGITIMATE LIBRARY", isSuspicious ? "badge-danger" : "badge-safe");

  const riskScore = data.risk_score;
  const barColor = riskScore >= 60 ? "#e11d48" : (riskScore >= 20 ? "#ea580c" : "#10b981");

  const rf = data.rf_classification;
  const rfProbPercent = (rf.prob_suspicious * 100).toFixed(1);

  let html = `
    <!-- Deterministic Rule Risk Score -->
    <div class="risk-meter-box">
      <div class="risk-header">
        <span class="risk-title">ENGINE A: DETERMINISTIC RISK SCORE</span>
        <span class="risk-score-badge" style="color: ${barColor};">${riskScore} / 100 (${data.risk_level})</span>
      </div>
      <div class="risk-bar-container">
        <div class="risk-bar-fill" style="width: ${riskScore}%; background: ${barColor};"></div>
      </div>
      <div style="font-size: 0.82rem; color: #94a3b8;">
        Verdict: <strong style="color: ${barColor};">${data.deterministic_verdict}</strong>
      </div>
    </div>

    <!-- Random Forest Experimental Classifier -->
    <div class="rf-box">
      <div class="rf-header">
        <span class="rf-title">ENGINE B: EXPERIMENTAL RANDOM FOREST</span>
        <span class="rf-prob">${rf.verdict} (P: ${rfProbPercent}%)</span>
      </div>
      <div class="risk-bar-container" style="background: rgba(139, 92, 246, 0.2);">
        <div class="risk-bar-fill" style="width: ${rfProbPercent}%; background: #a78bfa;"></div>
      </div>
      <div class="rf-sub">
        Classifies structured multi-dimensional feature vector to support human investigation.
      </div>
    </div>
  `;

  if (!data.evidence || data.evidence.length === 0) {
    html += `
      <div class="evidence-card" style="border-left-color: #10b981; border-color: rgba(16, 185, 129, 0.3);">
        <div class="ev-header">
          <span class="ev-dim" style="color: #34d399;">✓ Clean Verification</span>
          <span class="ev-sev sev-low">PASSED</span>
        </div>
        <div class="ev-msg">
          No lookalike patterns, unverified publisher anomalies, unexpected socket calls, or strapping pin tamperings were found. Verified legitimate library.
        </div>
      </div>
    `;
  } else {
    html += `<h4 style="font-size: 0.85rem; font-weight: 700; color: #94a3b8; margin: 1rem 0 0.5rem 0;">EXPLAINABLE EVIDENCE (${data.evidence.length} MATCHES)</h4>`;
    data.evidence.forEach(ev => {
      const sevClass = ev.severity === "CRITICAL" ? "sev-critical" : (ev.severity === "HIGH" ? "sev-high" : (ev.severity === "MEDIUM" ? "sev-medium" : "sev-low"));
      html += `
        <div class="evidence-card">
          <div class="ev-header">
            <span class="ev-dim">${escapeHtml(ev.dimension)}</span>
            <span class="ev-sev ${sevClass}">${escapeHtml(ev.severity)}</span>
          </div>
          <div class="ev-msg">${escapeHtml(ev.message)}</div>
        </div>
      `;
    });
  }

  container.innerHTML = html;
}

async function runEmbeddedBenchmark() {
  const tableBody = document.getElementById("benchmarkTableBody");
  const btnTop = document.getElementById("btnRunBenchmarkTop");
  const btnRefresh = document.getElementById("btnRefreshBenchmark");

  if (btnTop) btnTop.innerHTML = `<span>⏳</span> Evaluating...`;
  if (btnRefresh) btnRefresh.innerHTML = `<span>⏳</span> Running...`;

  try {
    const res = await fetch("/api/embedded-benchmark");
    const data = await res.json();

    // Update KPIs
    const shipsafe = data.summary.shipsafe;
    const baseline = data.summary.baseline;

    document.getElementById("kpiRecall").innerText = `${shipsafe.recall}%`;
    document.getElementById("kpiPrecision").innerText = `${shipsafe.precision}%`;
    document.getElementById("kpiF1").innerText = `${shipsafe.f1_score}%`;
    document.getElementById("kpiFPR").innerText = `${shipsafe.false_positive_rate}%`;
    document.getElementById("kpiLatency").innerText = `${shipsafe.avg_latency_ms.toFixed(2)} ms`;

    // Populate Table
    let tableHtml = "";
    data.results.forEach(tr => {
      const isGroundTruthSuspicious = tr.is_suspicious_ground_truth;
      const groundTruthBadge = isGroundTruthSuspicious ?
        `<span class="badge badge-danger-tag">SUSPICIOUS</span>` :
        `<span class="badge badge-success">CLEAN / SAFE</span>`;

      // Baseline verdict (Name only)
      const baselineDetected = (tr.pkg_name.toLowerCase().includes("0") || tr.pkg_name.toLowerCase().includes("1") || tr.pkg_name.toLowerCase().includes("cllient"));
      const baselineBadge = baselineDetected ?
        `<span class="badge badge-danger-tag">FLAGGED</span>` :
        `<span class="badge badge-neutral">PASSED</span>`;

      const shipsafeBadge = tr.detected_suspicious ?
        `<span class="badge badge-danger-tag">✓ CAUGHT</span>` :
        `<span class="badge badge-success">✓ CLEAN</span>`;

      const rfProb = (tr.rf_prob_suspicious * 100).toFixed(1) + "%";

      tableHtml += `
        <tr>
          <td><strong>${tr.id}</strong></td>
          <td><code>${escapeHtml(tr.pkg_name)}</code></td>
          <td><span style="font-size: 0.8rem; color: #cbd5e1;">${escapeHtml(tr.publisher)}</span></td>
          <td>${groundTruthBadge}</td>
          <td>${baselineBadge}</td>
          <td>${shipsafeBadge}</td>
          <td><strong style="font-family: monospace;">${tr.rule_risk_score}/100</strong></td>
          <td><code style="color: #a78bfa;">${rfProb}</code></td>
          <td>
            <button class="btn btn-xs btn-outline" onclick="loadBenchmarkItem('${tr.id}')">Load in Studio</button>
          </td>
        </tr>
      `;
    });
    tableBody.innerHTML = tableHtml;
  } catch (err) {
    console.error("Benchmark failed:", err);
  } finally {
    if (btnTop) btnTop.innerHTML = `<span>⚡</span> Run Baseline Benchmark`;
    if (btnRefresh) btnRefresh.innerHTML = `<span>↻</span> Re-evaluate Dataset`;
  }
}

window.loadBenchmarkItem = function(sampleId) {
  const select = document.getElementById("sampleSelect");
  if (select) {
    select.value = sampleId;
    loadSelectedSample(sampleId);
    document.getElementById("studio").scrollIntoView({ behavior: "smooth" });
  }
};

function updateEditorStatusBadge(text, className) {
  const badge = document.getElementById("editorStatus");
  if (badge) {
    badge.className = `pane-badge ${className}`;
    badge.innerText = text;
  }
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
