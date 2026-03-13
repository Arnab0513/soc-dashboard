/* ============================================================
   script.js — Security Monitoring Dashboard
   ============================================================ */

/* ── 1. Tab switching ──────────────────────────────────────────
   Called by onclick="switchTab('analytics', this)" in HTML
   Must be defined at top level so onclick can find it          */
function switchTab(name, btn) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  if (name === 'analytics') refreshCharts();
  if (name === 'blocked')   refreshBlocked();
}

/* ── 2. Live stat counters ─────────────────────────────────────
   Seeded from values already rendered by Flask/Jinja           */
const counts = {
  total:  parseInt(document.getElementById('statTotal').textContent)  || 0,
  HIGH:   parseInt(document.getElementById('statHigh').textContent)   || 0,
  MEDIUM: parseInt(document.getElementById('statMedium').textContent) || 0,
  NORMAL: parseInt(document.getElementById('statNormal').textContent) || 0
};

function bumpStat(el, value) {
  el.textContent = value;
  el.style.transform = 'scale(1.2)';
  setTimeout(() => { el.style.transform = 'scale(1)'; }, 220);
}

function updateStats() {
  bumpStat(document.getElementById('statTotal'),  counts.total);
  bumpStat(document.getElementById('statHigh'),   counts.HIGH);
  bumpStat(document.getElementById('statMedium'), counts.MEDIUM);
  bumpStat(document.getElementById('statNormal'), counts.NORMAL);
}

/* ── 3. Table filter ───────────────────────────────────────────
   Filters rows by search text AND severity dropdown            */
function filterTable() {
  const query    = document.getElementById('searchInput').value.toLowerCase();
  const severity = document.getElementById('severityFilter').value;
  document.querySelectorAll('#logBody tr').forEach(row => {
    const textMatch     = !query    || row.textContent.toLowerCase().includes(query);
    const severityMatch = !severity || row.className.includes(severity);
    row.style.display   = (textMatch && severityMatch) ? '' : 'none';
  });
}

/* ── 4. Prepend new log row ────────────────────────────────────
   Called when SSE pushes a new event                          */
function prependRow(log) {
  const tbody = document.getElementById('logBody');
  // Remove empty-state placeholder if present
  const placeholder = tbody.querySelector('td[colspan]');
  if (placeholder) placeholder.closest('tr').remove();

  const tr = document.createElement('tr');
  tr.className = log.severity + ' new-row';
  tr.innerHTML = `
    <td class="time-cell">${log.time}</td>
    <td>${log.device}</td>
    <td class="ip-cell">${log.ip}</td>
    <td class="file-cell">${log.file}</td>
    <td class="action-cell">${log.action}</td>
    <td><span class="sev-badge sev-${log.severity}">${log.severity}</span></td>
  `;
  tbody.prepend(tr);
  // Remove animation class after it completes so severity bg-colour stays
  setTimeout(() => tr.classList.remove('new-row'), 1600);
}

/* ── 5. Toast alert notifications ─────────────────────────────
   Shows a pop-up for HIGH and MEDIUM events only              */
function showToast(log) {
  if (log.severity === 'NORMAL') return;
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${log.severity}`;
  toast.innerHTML = `
    <div class="toast-header">
      <span class="toast-title">⚠ ${log.severity} ALERT</span>
      <button class="toast-close" onclick="this.closest('.toast').remove()">×</button>
    </div>
    <div class="toast-body">
      Device: <span>${log.device}</span> &nbsp;|&nbsp; File: <span>${log.file}</span><br/>
      Action: <span>${log.action}</span> &nbsp;|&nbsp; IP: <span>${log.ip}</span>
    </div>
  `;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 8000);
}

/* ── 6. Clear all logs ─────────────────────────────────────────
   Calls POST /clear on the server, then reloads the page      */
function clearLogs() {
  if (!confirm('Clear all security logs? This cannot be undone.')) return;
  fetch('/clear', { method: 'POST' })
    .then(() => location.reload())
    .catch(() => alert('Failed to clear logs. Is the server running?'));
}

/* ── 7. Charts ─────────────────────────────────────────────────
   Bar + Doughnut + Line — fetches fresh data from /stats & /logs */
let barChart, doughnutChart, lineChart;

const axisStyle = {
  ticks:  { color: '#4a6070', font: { family: 'Share Tech Mono', size: 11 } },
  grid:   { color: 'rgba(30,45,61,.8)' },
  border: { color: '#1e2d3d' }
};

async function refreshCharts() {
  try {
    const [sRes, lRes] = await Promise.all([fetch('/stats'), fetch('/logs')]);
    const { counts: c } = await sRes.json();
    const logs = await lRes.json();

    // --- Bar chart (colour-coded by severity) ---
    if (barChart) barChart.destroy();
    barChart = new Chart(document.getElementById('barChart'), {
      type: 'bar',
      data: {
        labels: ['HIGH', 'MEDIUM', 'NORMAL'],
        datasets: [{
          label: 'Events',
          data: [c.HIGH || 0, c.MEDIUM || 0, c.NORMAL || 0],
          backgroundColor: [
            'rgba(255,59,59,.6)',
            'rgba(255,176,32,.6)',
            'rgba(0,230,118,.5)'
          ],
          borderColor: ['#ff3b3b', '#ffb020', '#00e676'],
          borderWidth: 1,
          borderRadius: 5
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: axisStyle,
          y: { ...axisStyle, beginAtZero: true, ticks: { ...axisStyle.ticks, stepSize: 1 } }
        }
      }
    });

    // --- Doughnut chart ---
    if (doughnutChart) doughnutChart.destroy();
    doughnutChart = new Chart(document.getElementById('doughnutChart'), {
      type: 'doughnut',
      data: {
        labels: ['HIGH', 'MEDIUM', 'NORMAL'],
        datasets: [{
          data: [c.HIGH || 0, c.MEDIUM || 0, c.NORMAL || 0],
          backgroundColor: [
            'rgba(255,59,59,.7)',
            'rgba(255,176,32,.7)',
            'rgba(0,230,118,.6)'
          ],
          borderColor: ['#ff3b3b', '#ffb020', '#00e676'],
          borderWidth: 1,
          hoverOffset: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '58%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#c9d1d9',
              font: { family: 'Rajdhani', size: 13, weight: '600' },
              padding: 14
            }
          }
        }
      }
    });

    // --- Line chart (events per hour) ---
    const buckets = {};
    logs.forEach(l => {
      const h = l.time.substring(0, 13) + ':00';
      buckets[h] = (buckets[h] || 0) + 1;
    });
    const hours = Object.keys(buckets).sort();

    if (lineChart) lineChart.destroy();
    lineChart = new Chart(document.getElementById('lineChart'), {
      type: 'line',
      data: {
        labels: hours.map(h => h.substring(11)),
        datasets: [{
          label: 'Events/hr',
          data: hours.map(h => buckets[h]),
          borderColor: '#00d4ff',
          backgroundColor: 'rgba(0,212,255,.08)',
          pointBackgroundColor: '#00d4ff',
          pointRadius: 4,
          tension: 0.4,
          fill: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: axisStyle,
          y: { ...axisStyle, beginAtZero: true, ticks: { ...axisStyle.ticks, stepSize: 1 } }
        }
      }
    });

  } catch (err) {
    console.error('Chart refresh failed:', err);
  }
}

/* ── 8. Blocked Devices panel ─────────────────────────────────
   Shows blocked device names (not IPs) because in local testing
   all devices share 127.0.0.1 — blocking by device name works  */
async function refreshBlocked() {
  try {
    const data = await fetch('/stats').then(r => r.json());
    const list = document.getElementById('blockedList');
    const devices = data.blocked_devices || [];
    list.innerHTML = devices.length
      ? devices.map(d => `
          <div class="blocked-card">
            <span class="blocked-icon">🚫</span>
            <div class="blocked-info">
              <span class="blocked-name">${d}</span>
              <span class="blocked-label">DEVICE BLOCKED</span>
            </div>
            <button class="unblock-btn" onclick="unblockDevice('${d}')">UNBLOCK</button>
          </div>`).join('')
      : '<span class="empty-text">No devices blocked in this session.</span>';
  } catch (err) {
    console.error('Failed to load blocked devices:', err);
  }
}

async function unblockDevice(device) {
  try {
    const res = await fetch('/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device })
    });
    const data = await res.json();
    if (data.status === 'unblocked') {
      refreshBlocked();  // re-render the list
    } else {
      alert('Could not unblock: ' + (data.error || 'unknown error'));
    }
  } catch (err) {
    console.error('Unblock failed:', err);
  }
}

/* ── 9. SSE — Server-Sent Events ───────────────────────────────
   3 visual states: CONNECTING (yellow glow) → LIVE (green glow)
                    → OFFLINE/RECONNECTING (red glow)
   Auto-reloads the page when server comes back online          */
const liveDot    = document.getElementById('liveDot');
const liveStatus = document.getElementById('liveStatus');
const liveBadge  = document.getElementById('liveBadge');

let wasEverConnected = false;  // did we have a live connection before?

function setLiveState(state) {
  liveBadge.classList.remove('connected', 'offline');
  liveDot.classList.remove('connected', 'offline', 'connecting');

  if (state === 'connecting') {
    liveDot.classList.add('connecting');
    liveStatus.textContent = 'CONNECTING...';

  } else if (state === 'live') {
    liveBadge.classList.add('connected');
    liveDot.classList.add('connected');
    liveStatus.textContent = 'LIVE';

  } else if (state === 'offline') {
    liveBadge.classList.add('offline');
    liveDot.classList.add('offline');
    liveStatus.textContent = 'OFFLINE';

  } else if (state === 'reconnecting') {
    liveBadge.classList.add('offline');
    liveDot.classList.add('connecting');
    liveStatus.textContent = 'RECONNECTING...';
  }
}

function connectSSE() {
  setLiveState('connecting');
  const es = new EventSource('/stream');

  es.onopen = () => {
    if (wasEverConnected) {
      // Server came back online — reload page to get latest logs
      location.reload();
      return;
    }
    wasEverConnected = true;
    setLiveState('live');
  };

  es.onmessage = (event) => {
    const log = JSON.parse(event.data);

    // Handle server-sent clear signal
    if (log.type === 'clear') {
      document.getElementById('logBody').innerHTML =
        '<tr><td colspan="6" class="empty-state">No security events recorded.</td></tr>';
      counts.total = counts.HIGH = counts.MEDIUM = counts.NORMAL = 0;
      updateStats();
      return;
    }

    // Update counters and UI
    counts.total++;
    counts[log.severity] = (counts[log.severity] || 0) + 1;
    updateStats();
    prependRow(log);
    showToast(log);
  };

  es.onerror = () => {
    setLiveState(wasEverConnected ? 'reconnecting' : 'offline');
    es.close();
    setTimeout(connectSSE, 3000); // retry every 3s
  };
}

/* ── Boot ──────────────────────────────────────────────────────
   Start the live stream when the page loads                   */
connectSSE();