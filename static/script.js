/* ═══════════════════════════════════════════════════════════
   NEXUS SOC Dashboard — script.js
   ═══════════════════════════════════════════════════════════ */

let barChart, doughnutChart, lineChart;
let wasConnected = false;

/* ── Clock ────────────────────────────────────────────────── */
function updateClock() {
  const now = new Date();
  const h = String(now.getHours()).padStart(2,'0');
  const m = String(now.getMinutes()).padStart(2,'0');
  const s = String(now.getSeconds()).padStart(2,'0');
  const el = document.getElementById('clockTime');
  if (el) el.textContent = h + ':' + m + ':' + s;
}
setInterval(updateClock, 1000);
updateClock();

/* ── Tab switching ────────────────────────────────────────── */
function switchTab(name, btn) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));

  const panel = document.getElementById('tab-' + name);
  if (panel) panel.classList.add('active');
  if (btn)   btn.classList.add('active');

  const titles = { logs: 'EVENT LOG', analytics: 'ANALYTICS', blocked: 'BLOCKED DEVICES' };
  const el = document.getElementById('tabTitle');
  if (el) el.textContent = titles[name] || name.toUpperCase();

  if (name === 'analytics') refreshCharts();
  if (name === 'blocked')   refreshBlocked();
}

/* ── Live state ───────────────────────────────────────────── */
function setLiveState(state) {
  const badge  = document.getElementById('liveBadge');
  const dot    = document.getElementById('liveDot');
  const text   = document.getElementById('liveStatus');
  const badgeTxt = document.getElementById('liveBadgeText');

  badge.className = 'live-badge';
  dot.className   = 'status-dot';

  if (state === 'live') {
    badge.classList.add('connected');
    dot.classList.add('connected');
    if (text)     text.textContent = 'LIVE';
    if (badgeTxt) badgeTxt.textContent = '● LIVE';
  } else if (state === 'offline' || state === 'reconnecting') {
    badge.classList.add('offline');
    dot.classList.add('offline');
    if (text)     text.textContent = state === 'reconnecting' ? 'RECONNECTING' : 'OFFLINE';
    if (badgeTxt) badgeTxt.textContent = state === 'reconnecting' ? '⟳ RECONNECTING' : '✕ OFFLINE';
  } else {
    if (text)     text.textContent = 'CONNECTING';
    if (badgeTxt) badgeTxt.textContent = '◌ CONNECTING...';
  }
}

/* ── SSE Connection ───────────────────────────────────────── */
function connectSSE() {
  setLiveState('connecting');
  const evtSource = new EventSource('/stream');

  evtSource.onopen = () => {
    setLiveState('live');
    if (wasConnected) {
      location.reload();
    }
    wasConnected = true;
  };

  evtSource.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.type === 'clear') { location.reload(); return; }
      addRow(data);
      updateStats();
      if (data.severity === 'HIGH' || data.severity === 'MEDIUM') {
        showToast(data);
      }
    } catch (err) { console.error(err); }
  };

  evtSource.onerror = () => {
    evtSource.close();
    setLiveState('reconnecting');
    setTimeout(connectSSE, 3000);
  };
}

/* ── Add table row ────────────────────────────────────────── */
function addRow(log) {
  const tbody = document.getElementById('logBody');
  if (!tbody) return;

  const tr = document.createElement('tr');
  tr.className = log.severity;
  tr.innerHTML = `
    <td class="td-time">${log.time}</td>
    <td class="td-device"><span class="device-icon">⬡</span>${log.device}</td>
    <td class="td-ip">${log.ip}</td>
    <td class="td-file">${log.file}</td>
    <td class="td-action">${log.action}</td>
    <td class="td-sev"><span class="sev-badge sev-${log.severity.toLowerCase()}">${log.severity}</span></td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
}

/* ── Update stats ─────────────────────────────────────────── */
async function updateStats() {
  try {
    const data = await fetch('/stats').then(r => r.json());
    document.getElementById('statTotal').textContent  = data.total  || 0;
    document.getElementById('statHigh').textContent   = data.counts?.HIGH   || 0;
    document.getElementById('statMedium').textContent = data.counts?.MEDIUM || 0;
    document.getElementById('statNormal').textContent = data.counts?.NORMAL || 0;

    const navBadge = document.getElementById('navBadge');
    if (navBadge) navBadge.textContent = data.total || 0;

    const blockedBadge = document.getElementById('blockedBadge');
    if (blockedBadge) blockedBadge.textContent = (data.blocked_devices || []).length;

    // Update stat bars
    const total = data.total || 1;
    const highPct   = ((data.counts?.HIGH   || 0) / total * 100).toFixed(0);
    const medPct    = ((data.counts?.MEDIUM || 0) / total * 100).toFixed(0);
    const normPct   = ((data.counts?.NORMAL || 0) / total * 100).toFixed(0);

    const hf = document.querySelector('.high-fill');
    const mf = document.querySelector('.medium-fill');
    const nf = document.querySelector('.normal-fill');
    const tf = document.querySelector('.total-fill');
    if (hf) hf.style.width = highPct + '%';
    if (mf) mf.style.width = medPct + '%';
    if (nf) nf.style.width = normPct + '%';
    if (tf) tf.style.width = '100%';

  } catch(e) { console.error(e); }
}

/* ── Charts ───────────────────────────────────────────────── */
Chart.defaults.color = '#4a5568';
Chart.defaults.borderColor = 'rgba(255,255,255,0.05)';
Chart.defaults.font.family = "'Share Tech Mono', monospace";

async function refreshCharts() {
  try {
    const [stats, logs] = await Promise.all([
      fetch('/stats').then(r => r.json()),
      fetch('/logs').then(r => r.json())
    ]);

    const HIGH   = stats.counts?.HIGH   || 0;
    const MEDIUM = stats.counts?.MEDIUM || 0;
    const NORMAL = stats.counts?.NORMAL || 0;

    // Doughnut
    const dCtx = document.getElementById('doughnutChart')?.getContext('2d');
    if (dCtx) {
      if (doughnutChart) doughnutChart.destroy();
      doughnutChart = new Chart(dCtx, {
        type: 'doughnut',
        data: {
          labels: ['HIGH', 'MEDIUM', 'NORMAL'],
          datasets: [{
            data: [HIGH, MEDIUM, NORMAL],
            backgroundColor: ['rgba(255,68,102,0.8)', 'rgba(255,170,0,0.8)', 'rgba(0,245,160,0.8)'],
            borderColor: ['#ff4466', '#ffaa00', '#00f5a0'],
            borderWidth: 1,
            hoverOffset: 6
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: true,
          cutout: '70%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: { padding: 16, font: { size: 10 }, color: '#8892a4' }
            }
          }
        }
      });
    }

    // Bar
    const bCtx = document.getElementById('barChart')?.getContext('2d');
    if (bCtx) {
      if (barChart) barChart.destroy();
      barChart = new Chart(bCtx, {
        type: 'bar',
        data: {
          labels: ['HIGH', 'MEDIUM', 'NORMAL'],
          datasets: [{
            label: 'Events',
            data: [HIGH, MEDIUM, NORMAL],
            backgroundColor: ['rgba(255,68,102,0.3)', 'rgba(255,170,0,0.3)', 'rgba(0,245,160,0.3)'],
            borderColor: ['#ff4466', '#ffaa00', '#00f5a0'],
            borderWidth: 1,
            borderRadius: 4
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: true,
          plugins: { legend: { display: false } },
          scales: {
            y: { beginAtZero: true, ticks: { stepSize: 1, color: '#4a5568', font: { size: 10 } } },
            x: { ticks: { color: '#4a5568', font: { size: 10 } } }
          }
        }
      });
    }

    // Line — last 20 events timeline
    const lCtx = document.getElementById('lineChart')?.getContext('2d');
    if (lCtx) {
      if (lineChart) lineChart.destroy();
      const recent = logs.slice(0, 20).reverse();
      const labels  = recent.map(l => l.time ? l.time.split(' ')[1] : '');
      const highD   = recent.map(l => l.severity === 'HIGH'   ? 1 : 0);
      const medD    = recent.map(l => l.severity === 'MEDIUM' ? 1 : 0);
      const normD   = recent.map(l => l.severity === 'NORMAL' ? 1 : 0);

      lineChart = new Chart(lCtx, {
        type: 'line',
        data: {
          labels,
          datasets: [
            {
              label: 'HIGH', data: highD,
              borderColor: '#ff4466', backgroundColor: 'rgba(255,68,102,0.1)',
              borderWidth: 2, pointRadius: 4, pointBackgroundColor: '#ff4466',
              tension: 0.4, fill: true
            },
            {
              label: 'MEDIUM', data: medD,
              borderColor: '#ffaa00', backgroundColor: 'rgba(255,170,0,0.1)',
              borderWidth: 2, pointRadius: 4, pointBackgroundColor: '#ffaa00',
              tension: 0.4, fill: true
            },
            {
              label: 'NORMAL', data: normD,
              borderColor: '#00f5a0', backgroundColor: 'rgba(0,245,160,0.1)',
              borderWidth: 2, pointRadius: 4, pointBackgroundColor: '#00f5a0',
              tension: 0.4, fill: true
            }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: '#8892a4', font: { size: 10 }, padding: 16 }
            }
          },
          scales: {
            y: { beginAtZero: true, ticks: { stepSize: 1, color: '#4a5568', font: { size: 10 } } },
            x: { ticks: { color: '#4a5568', font: { size: 10 }, maxRotation: 45 } }
          }
        }
      });
    }
  } catch(e) { console.error(e); }
}

/* ── Blocked devices ──────────────────────────────────────── */
async function refreshBlocked() {
  try {
    const data = await fetch('/stats').then(r => r.json());
    const list = document.getElementById('blockedList');
    const devices = data.blocked_devices || [];

    list.innerHTML = devices.length
      ? devices.map(d => `
          <div class="blocked-card">
            <div class="blocked-avatar">🚫</div>
            <div class="blocked-info">
              <span class="blocked-name">${d}</span>
              <span class="blocked-label">DEVICE BLOCKED</span>
            </div>
            <button class="unblock-btn" onclick="unblockDevice('${d}')">UNBLOCK</button>
          </div>`).join('')
      : '<span class="empty-text">// NO BLOCKED DEVICES IN THIS SESSION</span>';
  } catch(e) { console.error(e); }
}

async function unblockDevice(device) {
  try {
    const res = await fetch('/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device })
    });
    const data = await res.json();
    if (data.status === 'unblocked') refreshBlocked();
  } catch(e) { console.error(e); }
}

/* ── Filter table ─────────────────────────────────────────── */
function filterTable() {
  const search = document.getElementById('searchInput')?.value.toLowerCase() || '';
  const sev    = document.getElementById('severityFilter')?.value || '';
  document.querySelectorAll('#logBody tr').forEach(tr => {
    const text  = tr.textContent.toLowerCase();
    const rowSev = tr.className;
    const matchS = !search || text.includes(search);
    const matchV = !sev    || rowSev === sev;
    tr.style.display = (matchS && matchV) ? '' : 'none';
  });
}

/* ── Clear logs ───────────────────────────────────────────── */
async function clearLogs() {
  if (!confirm('Clear all security logs?')) return;
  await fetch('/clear', { method: 'POST' });
  location.reload();
}

/* ── Toast notifications ──────────────────────────────────── */
function showToast(log) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast ' + log.severity;

  const icon  = log.severity === 'HIGH' ? '🔴' : '🟡';
  const title = log.severity === 'HIGH' ? 'INTRUSION DETECTED' : 'SUSPICIOUS ACTIVITY';

  toast.innerHTML = `
    <div class="toast-icon">${icon}</div>
    <div>
      <div class="toast-title">${title}</div>
      <div class="toast-body">
        <b>${log.device}</b> → ${log.file}<br/>
        ${log.action} · <span style="color:#4a5568">${log.ip}</span>
      </div>
    </div>
    <button class="toast-close" onclick="this.parentElement.remove()">×</button>
  `;

  container.appendChild(toast);
  setTimeout(() => toast.remove(), 8000);
}

/* ── Init ─────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  updateStats();
  connectSSE();
});