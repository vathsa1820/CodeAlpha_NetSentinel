/**
 * NetSentinel — Security Dashboard JavaScript Logic
 * Phase 7 — Security Dashboard
 *
 * Handles API data polling, Chart.js rendering, and DOM updates.
 */

// Global Chart Instances
let threatDistributionChart = null;
let attackActivityChart = null;

// Polling interval in ms (5000 ms = 5s)
const REFRESH_INTERVAL_MS = 5000;

document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  fetchDashboardData();
  setInterval(fetchDashboardData, REFRESH_INTERVAL_MS);
});

/**
 * Initialize Chart.js instances with default empty data.
 */
function initCharts() {
  // 1. Threat Distribution Doughnut Chart
  const threatCtx = document.getElementById('threatDistributionChart').getContext('2d');
  threatDistributionChart = new Chart(threatCtx, {
    type: 'doughnut',
    data: {
      labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#a855f7'],
        borderColor: '#111827',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#9ca3af', font: { family: 'Inter', size: 12 } }
        }
      }
    }
  });

  // 2. Attack Activity Bar Chart
  const attackCtx = document.getElementById('attackActivityChart').getContext('2d');
  attackActivityChart = new Chart(attackCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Alert Count',
        data: [],
        backgroundColor: '#06b6d4',
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: '#9ca3af', font: { family: 'Inter', size: 11 } },
          grid: { display: false }
        },
        y: {
          ticks: { color: '#9ca3af', stepSize: 1 },
          grid: { color: '#1f2937' },
          beginAtZero: true
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

/**
 * Fetch stats, alerts, and responses from Flask REST API endpoints.
 */
async function fetchDashboardData() {
  const statusElem = document.getElementById('status-indicator');

  try {
    const [statsRes, alertsRes, responsesRes] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/alerts'),
      fetch('/api/responses')
    ]);

    if (!statsRes.ok || !alertsRes.ok || !responsesRes.ok) {
      throw new Error('API server returned error status');
    }

    const stats = await statsRes.json();
    const alerts = await alertsRes.json();
    const responses = await responsesRes.json();

    // Mark status badge
    const subTitleElem = document.querySelector('.header-subtitle');
    if (stats.mode === 'demo') {
      statusElem.className = 'status-badge status-demo';
      statusElem.innerHTML = '<span class="status-dot">●</span> DEMO MODE';
      if (subTitleElem) subTitleElem.textContent = 'Controlled Demonstration Data';
    } else {
      statusElem.className = 'status-badge status-active';
      statusElem.innerHTML = '<span class="status-dot">●</span> SYSTEM ACTIVE';
      if (subTitleElem) subTitleElem.textContent = 'Network Intrusion Detection & Response System';
    }

    // Update DOM sections
    updateMetrics(stats);
    updateThreatChart(stats);
    updateAttackChart(alerts);
    updateAlertsTable(alerts);
    updateTrackedIPs(stats);
    updateResponsesTable(responses);

  } catch (err) {
    console.warn('[NetSentinel Dashboard Warning] Failed to fetch API data:', err);
    statusElem.className = 'status-badge status-offline';
    statusElem.innerHTML = '<span class="status-dot">●</span> BACKEND OFFLINE';
  }
}

/**
 * Update metric card values.
 */
function updateMetrics(stats) {
  document.getElementById('val-total-alerts').textContent = stats.total_alerts || 0;
  document.getElementById('val-medium-risk').textContent = stats.medium || 0;
  document.getElementById('val-high-risk').textContent = stats.high || 0;
  document.getElementById('val-critical-blocks').textContent = stats.simulated_blocked_ips || 0;
}

/**
 * Update Doughnut chart dataset.
 */
function updateThreatChart(stats) {
  threatDistributionChart.data.datasets[0].data = [
    stats.low || 0,
    stats.medium || 0,
    stats.high || 0,
    stats.critical || 0
  ];
  threatDistributionChart.update();
}

/**
 * Aggregate alerts by attack description / SID and update Bar chart.
 */
function updateAttackChart(alerts) {
  const counts = {};
  alerts.forEach(a => {
    let name = a.message.replace('[NetSentinel] ', '').trim();
    counts[name] = (counts[name] || 0) + 1;
  });

  const labels = Object.keys(counts);
  const data = Object.values(counts);

  attackActivityChart.data.labels = labels;
  attackActivityChart.data.datasets[0].data = data;
  attackActivityChart.update();
}

/**
 * Render recent alerts table rows.
 */
function updateAlertsTable(alerts) {
  const tbody = document.getElementById('alerts-table-body');
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-muted text-center">No alerts logged yet.</td></tr>';
    return;
  }

  tbody.innerHTML = alerts.map(a => {
    const src = a.source_port ? `${a.source_ip}:${a.source_port}` : a.source_ip;
    const dst = a.destination_port ? `${a.destination_ip}:${a.destination_port}` : a.destination_ip;
    const riskClass = `badge-${(a.risk_level || 'LOW').toLowerCase()}`;
    const cleanMsg = a.message.replace('[NetSentinel] ', '');

    return `
      <tr>
        <td><code>${a.timestamp}</code></td>
        <td><code>${a.sid}</code></td>
        <td><strong>${cleanMsg}</strong></td>
        <td><code>${a.protocol}</code></td>
        <td><code>${src}</code></td>
        <td><code>${dst}</code></td>
        <td><strong>${a.score}</strong></td>
        <td><span class="badge-risk ${riskClass}">${a.risk_level}</span></td>
      </tr>
    `;
  }).join('');
}

/**
 * Render suspicious IPs and simulated blocked IPs tags.
 */
function updateTrackedIPs(stats) {
  const suspContainer = document.getElementById('suspicious-ip-list');
  const blockContainer = document.getElementById('blocked-ip-list');

  const suspIPs = stats.suspicious_ip_list || [];
  const blockedIPs = stats.simulated_blocked_ip_list || [];

  if (suspIPs.length === 0) {
    suspContainer.innerHTML = '<span class="tag tag-empty">No suspicious IPs detected</span>';
  } else {
    suspContainer.innerHTML = suspIPs.map(ip => `<span class="tag tag-suspicious">${ip}</span>`).join('');
  }

  if (blockedIPs.length === 0) {
    blockContainer.innerHTML = '<span class="tag tag-empty">No simulated blocks</span>';
  } else {
    blockContainer.innerHTML = blockedIPs.map(ip => `<span class="tag tag-blocked">${ip}</span>`).join('');
  }
}

/**
 * Render Response Engine activity table rows.
 */
function updateResponsesTable(responses) {
  const tbody = document.getElementById('responses-table-body');
  if (!responses || responses.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted text-center">No response actions recorded.</td></tr>';
    return;
  }

  tbody.innerHTML = responses.map(r => {
    const riskClass = `badge-${(r.risk_level || 'LOW').toLowerCase()}`;
    let actionClass = 'action-log';
    if (r.action === 'FLAG') actionClass = 'action-flag';
    if (r.action === 'SUSPICIOUS') actionClass = 'action-suspicious';
    if (r.action.includes('BLOCK')) actionClass = 'action-block';

    return `
      <tr>
        <td><code>${r.timestamp}</code></td>
        <td><code>${r.source_ip}</code></td>
        <td><code>${r.sid}</code></td>
        <td><span class="badge-risk ${riskClass}">${r.risk_level}</span></td>
        <td><span class="badge-action ${actionClass}">${r.action}</span></td>
        <td><code>${r.status}</code></td>
      </tr>
    `;
  }).join('');
}
