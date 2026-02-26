/* ── SentinelNet Dashboard JS ── */

// ── State ──────────────────────────────────────────────────────────
let paused      = false;
let alertCount  = 0;
let startedAt   = null;
const NORMAL_COLOR = 'rgba(16,185,129,0.7)';
const ATTACK_COLOR = 'rgba(239,68,68,0.8)';
const GRID_COLOR   = 'rgba(30,42,69,0.6)';

// ── Traffic Chart ──────────────────────────────────────────────────
const trafficCtx = document.getElementById('trafficChart').getContext('2d');
const trafficData = {
  labels:   Array(60).fill(''),
  datasets: [
    {
      label: 'Normal',
      data:  Array(60).fill(0),
      borderColor: 'rgba(16,185,129,1)',
      backgroundColor: 'rgba(16,185,129,0.1)',
      fill: true,
      tension: 0.4,
      pointRadius: 0,
      borderWidth: 1.5,
    },
    {
      label: 'Attacks',
      data:  Array(60).fill(0),
      borderColor: 'rgba(239,68,68,1)',
      backgroundColor: 'rgba(239,68,68,0.15)',
      fill: true,
      tension: 0.4,
      pointRadius: 0,
      borderWidth: 1.5,
    },
  ],
};

const trafficChart = new Chart(trafficCtx, {
  type: 'line',
  data: trafficData,
  options: {
    responsive: true,
    animation: false,
    plugins: { legend: { labels: { color: '#64748b', font: { size: 11 } } } },
    scales: {
      x: { ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: GRID_COLOR } },
      y: { ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: GRID_COLOR }, beginAtZero: true },
    },
  },
});

// ── Attack Type Chart ──────────────────────────────────────────────
const attackCtx  = document.getElementById('attackChart').getContext('2d');
const attackChart = new Chart(attackCtx, {
  type: 'doughnut',
  data: {
    labels:   ['DoS/DDoS', 'Port Scan', 'Brute-Force', 'Anomaly'],
    datasets: [{
      data: [0, 0, 0, 0],
      backgroundColor: ['#ef4444','#f59e0b','#8b5cf6','#06b6d4'],
      borderColor: '#0f1420',
      borderWidth: 2,
    }],
  },
  options: {
    responsive: true,
    plugins: {
      legend: { position: 'bottom', labels: { color: '#64748b', font: { size: 10 }, padding: 8 } },
    },
    cutout: '65%',
  },
});

// ── SSE Connection ─────────────────────────────────────────────────
function connect() {
  const es = new EventSource('/api/stream');

  es.onopen = () => {
    setBadge('live', '● LIVE');
  };

  es.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (!paused) {
      updateStats(data.stats);
      updateFeed(data.packets);
      updateAlerts(data.alerts);
      pushChartPoint(data.packets);
    }
    updateAttackChart(data.stats.attack_types || {});
  };

  es.onerror = () => {
    setBadge('dead', '● DISCONNECTED');
    es.close();
    setTimeout(connect, 3000);
  };
}

// ── Stats ──────────────────────────────────────────────────────────
function updateStats(stats) {
  setText('stat-total',    stats.total.toLocaleString());
  setText('stat-attacks',  stats.attacks.toLocaleString());
  setText('stat-learned',  (stats.model_samples || 0).toLocaleString());
  setText('model-ver',     stats.model_version || 1);
  setText('footer-samples', (stats.model_samples || 0).toLocaleString());

  const rate = stats.total > 0
    ? ((stats.attacks / stats.total) * 100).toFixed(1) + '%'
    : '0%';
  setText('stat-rate', rate);

  if (stats.model_accuracy) {
    setText('stat-accuracy', stats.model_accuracy + '%');
  }

  if (stats.started_at && !startedAt) {
    startedAt = new Date(stats.started_at);
  }
  updateUptime();
}

function updateUptime() {
  if (!startedAt) return;
  const secs = Math.floor((Date.now() - startedAt) / 1000);
  const h = String(Math.floor(secs / 3600)).padStart(2, '0');
  const m = String(Math.floor((secs % 3600) / 60)).padStart(2, '0');
  const s = String(secs % 60).padStart(2, '0');
  setText('uptime-label', `Uptime: ${h}:${m}:${s}`);
}
setInterval(updateUptime, 1000);

// ── Chart ──────────────────────────────────────────────────────────
let normalCount = 0, attackCount = 0;
const WINDOW = 60;

function pushChartPoint(packets) {
  let n = 0, a = 0;
  (packets || []).forEach(p => { p.is_attack ? a++ : n++; });

  const now = new Date().toLocaleTimeString('en-GB', { hour12: false });
  trafficData.labels.push(now);
  trafficData.labels.shift();
  trafficData.datasets[0].data.push(n);
  trafficData.datasets[0].data.shift();
  trafficData.datasets[1].data.push(a);
  trafficData.datasets[1].data.shift();
  trafficChart.update();
}

function updateAttackChart(types) {
  const labels = ['DoS/DDoS', 'Port Scan', 'Brute-Force', 'Anomaly'];
  attackChart.data.datasets[0].data = labels.map(l => types[l] || 0);
  attackChart.update();
}

// ── Feed ───────────────────────────────────────────────────────────
const MAX_ROWS = 50;
let feedRows   = 0;

function updateFeed(packets) {
  if (!packets || packets.length === 0) return;
  const tbody = document.getElementById('feed-body');

  packets.slice().reverse().forEach(pkt => {
    const tr = document.createElement('tr');
    if (pkt.is_attack) tr.classList.add('attack');

    const conf = pkt.confidence || 0;
    const barW = Math.round(conf * 0.5);
    const labelClass = pkt.is_attack ? 'label-attack' : 'label-normal';
    const labelText  = pkt.is_attack ? `⚠ ${pkt.label}` : '✓ Normal';

    tr.innerHTML = `
      <td>${pkt.timestamp}</td>
      <td>${pkt.src_ip}</td>
      <td>${pkt.dst_ip}</td>
      <td>${pkt.dst_port || '-'}</td>
      <td>${pkt.protocol || '-'}</td>
      <td class="${labelClass}">${labelText}</td>
      <td><span class="conf-bar" style="width:${barW}px"></span>${conf}%</td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
    feedRows++;
  });

  // Trim old rows
  while (feedRows > MAX_ROWS) {
    tbody.removeChild(tbody.lastChild);
    feedRows--;
  }
}

// ── Alerts ─────────────────────────────────────────────────────────
const shownAlerts = new Set();

function updateAlerts(alerts) {
  if (!alerts || alerts.length === 0) return;
  const list = document.getElementById('alerts-list');

  // Remove empty state
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  alerts.forEach(a => {
    const key = `${a.timestamp}-${a.src_ip}-${a.attack_type}`;
    if (shownAlerts.has(key)) return;
    shownAlerts.add(key);
    alertCount++;

    const div = document.createElement('div');
    div.className = `alert-item ${a.severity}`;
    div.innerHTML = `
      <div>
        <div class="alert-type">⚠ ${a.attack_type}</div>
        <div class="alert-meta">${a.src_ip} → ${a.dst_ip}:${a.dst_port} &nbsp;[${a.protocol}]</div>
        <div class="alert-meta">${a.timestamp}</div>
      </div>
      <div class="alert-conf">${a.confidence}%<br><small>${a.severity}</small></div>
    `;
    list.insertBefore(div, list.firstChild);
  });

  setText('alert-count', alertCount);

  // Keep list trimmed
  while (list.children.length > 20) {
    list.removeChild(list.lastChild);
  }
}

// ── Helpers ────────────────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setBadge(cls, text) {
  const b = document.getElementById('status-badge');
  b.className = `badge ${cls}`;
  b.textContent = text;
}

function togglePause() {
  paused = !paused;
  document.getElementById('pause-btn').textContent = paused ? '▶ Resume' : '⏸ Pause';
}

// ── Boot ───────────────────────────────────────────────────────────
connect();
