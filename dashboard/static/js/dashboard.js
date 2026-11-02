/**
 * Intelligent Campus Cyber Security Threat Detection - SOC Dashboard Controller
 */

let streamInterval = null;
let isStreaming = false;
let threatDonutChart = null;
let subnetBarChart = null;
let benchmarkChart = null;

// Metrics accumulator
let stats = {
  totalFlows: 0,
  threatsDetected: 0,
  criticalCount: 0,
  threatCounts: {
    Benign: 0,
    DDoS_Flood: 0,
    Brute_Force: 0,
    Port_Scan: 0,
    Web_Attack: 0,
    Botnet_C2: 0,
    Data_Exfiltration: 0
  },
  subnetCounts: {
    dorms: 0,
    labs: 0,
    admin: 0,
    server_farm: 0,
    guest_wifi: 0,
    external: 0
  }
};

// Attack Preset Templates
const PRESETS = {
  benign: {
    duration: 14.5,
    protocol_type: "TCP",
    service: "HTTPS",
    conn_state: "SF",
    src_bytes: 5200,
    dst_bytes: 18400,
    src_pkts: 32,
    dst_pkts: 48,
    pkt_rate: 5.5,
    byte_rate: 1627.0,
    avg_pkt_size: 295.0,
    failed_logins: 0,
    port_entropy: 0.12,
    payload_entropy: 4.1,
    syn_flag_count: 1,
    rst_flag_count: 0,
    ack_flag_count: 46,
    src_subnet: "dorms",
    dst_subnet: "server_farm",
    is_guest_network: 0
  },
  ddos: {
    duration: 0.12,
    protocol_type: "TCP",
    service: "HTTPS",
    conn_state: "S0",
    src_bytes: 280000,
    dst_bytes: 108,
    src_pkts: 4200,
    dst_pkts: 2,
    pkt_rate: 35000.0,
    byte_rate: 2333000.0,
    avg_pkt_size: 66.0,
    failed_logins: 0,
    port_entropy: 0.25,
    payload_entropy: 1.8,
    syn_flag_count: 4200,
    rst_flag_count: 0,
    ack_flag_count: 2,
    src_subnet: "external",
    dst_subnet: "server_farm",
    is_guest_network: 0
  },
  bruteforce: {
    duration: 3.4,
    protocol_type: "TCP",
    service: "SSH",
    conn_state: "REJ",
    src_bytes: 4200,
    dst_bytes: 1800,
    src_pkts: 180,
    dst_pkts: 150,
    pkt_rate: 97.0,
    byte_rate: 1764.0,
    avg_pkt_size: 180.0,
    failed_logins: 16,
    port_entropy: 0.08,
    payload_entropy: 4.5,
    syn_flag_count: 16,
    rst_flag_count: 5,
    ack_flag_count: 140,
    src_subnet: "guest_wifi",
    dst_subnet: "admin",
    is_guest_network: 1
  },
  portscan: {
    duration: 0.005,
    protocol_type: "TCP",
    service: "OTHER",
    conn_state: "S0",
    src_bytes: 160,
    dst_bytes: 0,
    src_pkts: 3,
    dst_pkts: 0,
    pkt_rate: 600.0,
    byte_rate: 32000.0,
    avg_pkt_size: 53.0,
    failed_logins: 0,
    port_entropy: 0.96,
    payload_entropy: 1.1,
    syn_flag_count: 3,
    rst_flag_count: 0,
    ack_flag_count: 0,
    src_subnet: "dorms",
    dst_subnet: "labs",
    is_guest_network: 0
  },
  webattack: {
    duration: 1.8,
    protocol_type: "TCP",
    service: "HTTPS",
    conn_state: "SF",
    src_bytes: 18500,
    dst_bytes: 3200,
    src_pkts: 24,
    dst_pkts: 18,
    pkt_rate: 23.3,
    byte_rate: 12055.0,
    avg_pkt_size: 516.0,
    failed_logins: 1,
    port_entropy: 0.14,
    payload_entropy: 7.45,
    syn_flag_count: 1,
    rst_flag_count: 0,
    ack_flag_count: 22,
    src_subnet: "external",
    dst_subnet: "server_farm",
    is_guest_network: 0
  },
  exfiltration: {
    duration: 95.0,
    protocol_type: "TCP",
    service: "HTTPS",
    conn_state: "SF",
    src_bytes: 18500000,
    dst_bytes: 84000,
    src_pkts: 13200,
    dst_pkts: 1400,
    pkt_rate: 153.6,
    byte_rate: 195600.0,
    avg_pkt_size: 1270.0,
    failed_logins: 0,
    port_entropy: 0.04,
    payload_entropy: 7.82,
    syn_flag_count: 1,
    rst_flag_count: 0,
    ack_flag_count: 12500,
    src_subnet: "admin",
    dst_subnet: "external",
    is_guest_network: 0
  }
};

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initCharts();
  loadSystemMetrics();
  loadMitigationPlan("DDoS_Flood");

  // Start live stream automatically
  toggleStream();

  // Attach Predict Form
  document.getElementById("predict-form").addEventListener("submit", handlePredict);
  
  // Preset scenario buttons
  document.querySelectorAll(".preset-chip").forEach(btn => {
    btn.addEventListener("click", () => {
      const p = btn.dataset.preset;
      if (PRESETS[p]) loadPreset(PRESETS[p]);
    });
  });

  // Mitigation select dropdown
  document.getElementById("mitigation-select").addEventListener("change", (e) => {
    loadMitigationPlan(e.target.value);
  });
});

/* Tabs Switching */
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      
      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });
}

/* Charts Initialization */
function initCharts() {
  const donutCtx = document.getElementById("threatDonutChart").getContext("2d");
  threatDonutChart = new Chart(donutCtx, {
    type: "doughnut",
    data: {
      labels: ["Benign", "DDoS", "Brute Force", "Port Scan", "Web Attack", "Botnet C2", "Exfiltration"],
      datasets: [{
        data: [1, 0, 0, 0, 0, 0, 0],
        backgroundColor: [
          "#10b981", "#ef4444", "#f59e0b", "#8b5cf6", "#ec4899", "#3b82f6", "#f97316"
        ],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { color: "#9ca3af", font: { size: 11 } } }
      },
      cutout: "70%"
    }
  });

  const barCtx = document.getElementById("subnetBarChart").getContext("2d");
  subnetBarChart = new Chart(barCtx, {
    type: "bar",
    data: {
      labels: ["Dorms", "CS Labs", "Admin", "Data Center", "Guest Wi-Fi", "External"],
      datasets: [{
        label: "Threats by Subnet",
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: "rgba(59, 130, 246, 0.75)",
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#9ca3af" }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#9ca3af" }, grid: { color: "rgba(255,255,255,0.05)" }, beginAtZero: true }
      },
      plugins: { legend: { display: false } }
    }
  });
}

/* Toggle Live Telemetry Stream */
function toggleStream() {
  const btn = document.getElementById("stream-toggle-btn");
  if (isStreaming) {
    clearInterval(streamInterval);
    isStreaming = false;
    btn.innerHTML = `<span>▶</span> Resume Stream`;
    btn.classList.remove("btn-danger");
    btn.classList.add("btn-secondary");
  } else {
    streamInterval = setInterval(fetchStreamBatch, 2500);
    isStreaming = true;
    btn.innerHTML = `<span>⏸</span> Pause Stream`;
    btn.classList.remove("btn-secondary");
    btn.classList.add("btn-danger");
    fetchStreamBatch();
  }
}

async function fetchStreamBatch() {
  try {
    const res = await fetch("/api/simulate-stream?count=4");
    const data = await res.json();
    if (data.events && data.events.length > 0) {
      data.events.forEach(addStreamRow);
      updateDashboardStats();
    }
  } catch (err) {
    console.error("Stream fetch error:", err);
  }
}

function addStreamRow(event) {
  stats.totalFlows++;
  const label = event.prediction;
  stats.threatCounts[label] = (stats.threatCounts[label] || 0) + 1;

  if (event.is_threat) {
    stats.threatsDetected++;
    if (event.advisory.severity === "Critical") stats.criticalCount++;
    const srcSub = event.flow_data.src_subnet;
    if (stats.subnetCounts[srcSub] !== undefined) {
      stats.subnetCounts[srcSub]++;
    }
  }

  const tbody = document.getElementById("stream-tbody");
  const tr = document.createElement("tr");

  const badgeClass = getBadgeClass(event.advisory.severity);
  const timeStr = event.timestamp.split("T")[1].substring(0, 8);

  tr.innerHTML = `
    <td>${timeStr}</td>
    <td><span style="color:#60a5fa">${event.src_ip}</span> <span style="color:#6b7280">(${event.flow_data.src_subnet})</span></td>
    <td><span style="color:#e2e8f0">${event.dst_ip}</span> <span style="color:#6b7280">(${event.flow_data.dst_subnet})</span></td>
    <td>${event.flow_data.service} / ${event.flow_data.protocol_type}</td>
    <td><span class="badge ${badgeClass}">${label}</span></td>
    <td>${(event.confidence * 100).toFixed(1)}%</td>
    <td><span class="badge ${badgeClass}">${event.advisory.severity}</span></td>
  `;

  tr.addEventListener("click", () => showDetailModal(event));

  tbody.insertBefore(tr, tbody.firstChild);

  // Keep table size manageable
  if (tbody.children.length > 50) {
    tbody.removeChild(tbody.lastChild);
  }
}

function getBadgeClass(severity) {
  switch (severity.toLowerCase()) {
    case "critical": return "badge-critical";
    case "high": return "badge-high";
    case "medium": return "badge-medium";
    case "info": return "badge-benign";
    default: return "badge-info";
  }
}

function updateDashboardStats() {
  document.getElementById("stat-total-flows").innerText = stats.totalFlows.toLocaleString();
  document.getElementById("stat-threats").innerText = stats.threatsDetected.toLocaleString();
  document.getElementById("stat-critical").innerText = stats.criticalCount.toLocaleString();

  const threatPct = stats.totalFlows > 0 ? ((stats.threatsDetected / stats.totalFlows) * 100).toFixed(1) : 0;
  document.getElementById("stat-threat-pct").innerText = `${threatPct}% of traffic`;

  // Update Donut
  threatDonutChart.data.datasets[0].data = [
    stats.threatCounts.Benign || 0,
    stats.threatCounts.DDoS_Flood || 0,
    stats.threatCounts.Brute_Force || 0,
    stats.threatCounts.Port_Scan || 0,
    stats.threatCounts.Web_Attack || 0,
    stats.threatCounts.Botnet_C2 || 0,
    stats.threatCounts.Data_Exfiltration || 0
  ];
  threatDonutChart.update("none");

  // Update Bar
  subnetBarChart.data.datasets[0].data = [
    stats.subnetCounts.dorms,
    stats.subnetCounts.labs,
    stats.subnetCounts.admin,
    stats.subnetCounts.server_farm,
    stats.subnetCounts.guest_wifi,
    stats.subnetCounts.external
  ];
  subnetBarChart.update("none");
}

/* Preset Loader */
function loadPreset(preset) {
  for (const [key, val] of Object.entries(preset)) {
    const input = document.getElementById(`input-${key}`);
    if (input) input.value = val;
  }
}

/* Single Predict Handler */
async function handlePredict(e) {
  e.preventDefault();
  const payload = {
    duration: parseFloat(document.getElementById("input-duration").value),
    protocol_type: document.getElementById("input-protocol_type").value,
    service: document.getElementById("input-service").value,
    conn_state: document.getElementById("input-conn_state").value,
    src_bytes: parseInt(document.getElementById("input-src_bytes").value),
    dst_bytes: parseInt(document.getElementById("input-dst_bytes").value),
    src_pkts: parseInt(document.getElementById("input-src_pkts").value),
    dst_pkts: parseInt(document.getElementById("input-dst_pkts").value),
    pkt_rate: parseFloat(document.getElementById("input-pkt_rate").value),
    byte_rate: parseFloat(document.getElementById("input-byte_rate").value),
    avg_pkt_size: parseFloat(document.getElementById("input-avg_pkt_size").value),
    failed_logins: parseInt(document.getElementById("input-failed_logins").value),
    port_entropy: parseFloat(document.getElementById("input-port_entropy").value),
    payload_entropy: parseFloat(document.getElementById("input-payload_entropy").value),
    syn_flag_count: parseInt(document.getElementById("input-syn_flag_count").value),
    rst_flag_count: parseInt(document.getElementById("input-rst_flag_count").value),
    ack_flag_count: parseInt(document.getElementById("input-ack_flag_count").value),
    src_subnet: document.getElementById("input-src_subnet").value,
    dst_subnet: document.getElementById("input-dst_subnet").value,
    is_guest_network: parseInt(document.getElementById("input-is_guest_network").value)
  };

  const resultBox = document.getElementById("predict-result-box");
  resultBox.innerHTML = `<div style="text-align:center; padding: 2rem;">Analyzing network flow...</div>`;

  try {
    const res = await fetch("/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const result = await res.json();
    renderPredictionResult(result);
  } catch (err) {
    resultBox.innerHTML = `<div style="color:#ef4444;">Inference error: ${err.message}</div>`;
  }
}

function renderPredictionResult(result) {
  const badgeClass = getBadgeClass(result.advisory.severity);
  const resultBox = document.getElementById("predict-result-box");

  let probBars = "";
  for (const [cls, prob] of Object.entries(result.probabilities)) {
    const pct = (prob * 100).toFixed(1);
    probBars += `
      <div style="margin-bottom: 0.4rem;">
        <div style="display:flex; justify-content:space-between; font-size:0.75rem; margin-bottom:2px;">
          <span>${cls}</span>
          <span>${pct}%</span>
        </div>
        <div style="background:rgba(255,255,255,0.1); height:6px; border-radius:3px; overflow:hidden;">
          <div style="background:var(--accent-blue); width:${pct}%; height:100%;"></div>
        </div>
      </div>
    `;
  }

  resultBox.innerHTML = `
    <div style="border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem; background: rgba(31, 41, 55, 0.4);">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
        <div>
          <span style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase;">Predicted Verdict</span>
          <h2 style="font-size:1.4rem; font-weight:700;">${result.prediction}</h2>
        </div>
        <div style="text-align:right;">
          <span class="badge ${badgeClass}" style="font-size:0.85rem; padding: 0.35rem 0.8rem;">${result.advisory.severity} SEVERITY</span>
          <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">Confidence: ${(result.confidence * 100).toFixed(2)}%</div>
        </div>
      </div>

      <div style="margin-bottom: 1rem;">
        <div style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase; margin-bottom:0.2rem;">MITRE ATT&CK Classification</div>
        <div style="font-family:var(--font-mono); font-size:0.85rem; color:var(--accent-cyan);">${result.advisory.mitre_id} - ${result.advisory.mitre_name}</div>
        <p style="font-size:0.82rem; color:var(--text-muted); margin-top:0.25rem;">${result.advisory.description}</p>
      </div>

      <div style="margin-bottom: 1rem;">
        <div style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase; margin-bottom:0.4rem;">Class Probability Breakdown</div>
        ${probBars}
      </div>

      <div>
        <div style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase; margin-bottom:0.2rem;">Remediation & Firewall Rule</div>
        <pre class="code-box">${result.advisory.firewall_rule}</pre>
      </div>
    </div>
  `;
}

/* Load Benchmark Metrics */
async function loadSystemMetrics() {
  try {
    const res = await fetch("/api/metrics");
    const data = await res.json();

    document.getElementById("champion-model-name").innerText = data.champion_model;
    document.getElementById("champion-acc").innerText = (data.best_model_metrics.accuracy * 100).toFixed(2) + "%";
    document.getElementById("champion-f1").innerText = data.best_model_metrics.f1_macro.toFixed(4);

    // Populate comparison table
    const tbody = document.getElementById("benchmark-tbody");
    tbody.innerHTML = "";
    for (const [mName, m] of Object.entries(data.benchmark_results)) {
      const isChamp = mName === data.champion_model;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="font-weight:${isChamp ? '700' : '400'}; color:${isChamp ? 'var(--accent-cyan)' : 'inherit'}">
          ${mName} ${isChamp ? '<span class="badge badge-benign" style="font-size:0.65rem;">BEST</span>' : ''}
        </td>
        <td>${(m.accuracy * 100).toFixed(2)}%</td>
        <td>${(m.precision_macro * 100).toFixed(2)}%</td>
        <td>${(m.recall_macro * 100).toFixed(2)}%</td>
        <td>${m.f1_macro.toFixed(4)}</td>
      `;
      tbody.appendChild(tr);
    }

    // Populate Feature Importance
    const featDiv = document.getElementById("feature-importance-list");
    featDiv.innerHTML = "";
    (data.best_model_metrics.feature_importance || []).slice(0, 8).forEach(item => {
      const pct = (item.importance * 100).toFixed(1);
      featDiv.innerHTML += `
        <div style="margin-bottom:0.5rem;">
          <div style="display:flex; justify-content:space-between; font-size:0.75rem; margin-bottom:2px;">
            <span style="font-family:var(--font-mono);">${item.feature}</span>
            <span>${pct}%</span>
          </div>
          <div style="background:rgba(255,255,255,0.08); height:6px; border-radius:3px;">
            <div style="background:var(--accent-cyan); width:${pct * 4}%; max-width:100%; height:100%; border-radius:3px;"></div>
          </div>
        </div>
      `;
    });

  } catch (err) {
    console.error("Failed to load metrics:", err);
  }
}

/* Mitigation Plan Viewer */
async function loadMitigationPlan(threat) {
  try {
    const res = await fetch(`/api/mitigation/${threat}`);
    const data = await res.json();

    document.getElementById("mitigation-title").innerText = threat.replace("_", " ");
    document.getElementById("mitigation-mitre").innerText = `${data.mitre_id} - ${data.mitre_name}`;
    document.getElementById("mitigation-desc").innerText = data.description;
    document.getElementById("mitigation-action").innerText = data.recommended_action;
    document.getElementById("mitigation-tier").innerText = data.containment_tier;
    document.getElementById("mitigation-rules").innerText = data.firewall_rule;
  } catch (err) {
    console.error("Failed to load mitigation plan:", err);
  }
}

function copyMitigationRule() {
  const code = document.getElementById("mitigation-rules").innerText;
  navigator.clipboard.writeText(code).then(() => {
    alert("Firewall rule copied to clipboard!");
  });
}
