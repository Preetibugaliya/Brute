/**
 * BruteShield — Frontend Application Logic
 * ==========================================
 * Handles:
 *  - JWT Authentication flow
 *  - WebSocket real-time log streaming
 *  - Chart.js visualizations (live updates)
 *  - Log table rendering & filtering
 *  - Alert system with sound & toast notifications
 *  - Simulation controls
 *  - Configuration management
 *  - IP blocking/unblocking
 *  - CSV export
 */

'use strict';

// ─────────────────────────────────────────────────────
// Constants & State
// ─────────────────────────────────────────────────────
const API_BASE = window.location.origin;
const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_URL = `${protocol}//${window.location.host}/ws/logs`;

const state = {
    token: null,
    adminName: 'admin',
    ws: null,
    wsConnected: false,
    logsPaused: false,
    soundEnabled: true,
    allLogs: [],          // Full log buffer (newest first)
    displayedLogCount: 0,
    alerts: [],
    charts: {},
    autoRefresh: null,
    logOffset: 0,
};

const ipGeoCache = {};
let map;
let markerLayer;

async function getGeo(ip) {
    if (ipGeoCache[ip]) return ipGeoCache[ip];
    try {
        const res = await fetch(`https://get.geojs.io/v1/ip/geo/${ip}.json`);
        const data = await res.json();
        ipGeoCache[ip] = data;
        return data;
    } catch (e) {
        return null; // fallback
    }
}

function initMap() {
    const mapEl = document.getElementById('threat-map');
    if (!mapEl) return;
    map = L.map('threat-map', { zoomControl: false, attributionControl: false }).setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(map);
    markerLayer = L.layerGroup().addTo(map);
}

async function addAttackToMap(ip, risk_score) {
    if (!map) return;
    const geo = await getGeo(ip);
    if (geo && geo.latitude && geo.longitude) {
        const isHigh = risk_score >= 60;
        const color = isHigh ? 'var(--neon-red)' : 'var(--neon-orange)';
        const iconHtml = `<div class="pulse-dot" style="background:${color}; box-shadow: 0 0 10px ${color}"></div>`;
        const icon = L.divIcon({ html: iconHtml, className: '', iconSize: [14, 14] });
        const marker = L.marker([geo.latitude, geo.longitude], { icon }).addTo(markerLayer);

        // Remove after 15s to not bloat the map visually
        setTimeout(() => { if (markerLayer.hasLayer(marker)) markerLayer.removeLayer(marker); }, 15000);
    }
}

// ─────────────────────────────────────────────────────
// Audio Alerts (Web Audio API — no files needed)
// ─────────────────────────────────────────────────────
const AudioCtx = window.AudioContext || window.webkitAudioContext;
let audioCtx = null;

function playAlert(type = 'warning') {
    if (!state.soundEnabled) return;
    try {
        if (!audioCtx) audioCtx = new AudioCtx();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);

        if (type === 'danger') {
            osc.frequency.setValueAtTime(880, audioCtx.currentTime);
            osc.frequency.setValueAtTime(440, audioCtx.currentTime + 0.1);
            osc.frequency.setValueAtTime(880, audioCtx.currentTime + 0.2);
        } else {
            osc.frequency.setValueAtTime(660, audioCtx.currentTime);
            osc.frequency.setValueAtTime(440, audioCtx.currentTime + 0.15);
        }
        gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.35);
        osc.start(audioCtx.currentTime);
        osc.stop(audioCtx.currentTime + 0.35);
    } catch (e) { /* Ignore audio errors */ }
}

// ─────────────────────────────────────────────────────
// API Helper
// ─────────────────────────────────────────────────────
async function api(path, options = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (state.token) headers['Authorization'] = `Bearer ${state.token}`;
    const res = await fetch(`${API_BASE}${path}`, { headers, ...options });
    if (res.status === 401) { logout(); return null; }
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
}

async function apiRaw(path, options = {}) {
    const headers = {};
    if (state.token) headers['Authorization'] = `Bearer ${state.token}`;
    return fetch(`${API_BASE}${path}`, { headers, ...options });
}

// ─────────────────────────────────────────────────────
// Authentication
// ─────────────────────────────────────────────────────
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value.trim();
    const btn = document.getElementById('login-btn');
    const errEl = document.getElementById('login-error');

    btn.disabled = true;
    btn.querySelector('.btn-text').textContent = 'Authenticating...';
    errEl.textContent = '';

    try {
        const form = new URLSearchParams();
        form.append('username', username);
        form.append('password', password);

        const res = await fetch(`${API_BASE}/api/auth/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: form,
        });

        if (!res.ok) {
            const d = await res.json().catch(() => ({}));
            throw new Error(d.detail || 'Invalid credentials');
        }

        const data = await res.json();
        state.token = data.access_token;
        state.adminName = username;

        // Store token in sessionStorage (clears on tab close)
        sessionStorage.setItem('bf_token', state.token);
        sessionStorage.setItem('bf_admin', username);

        showApp();
    } catch (err) {
        errEl.textContent = `❌ ${err.message}`;
    } finally {
        btn.disabled = false;
        btn.querySelector('.btn-text').textContent = 'Access Dashboard';
    }
});

function showApp() {
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('app').classList.remove('hidden');
    document.getElementById('admin-name').textContent = state.adminName;
    initApp();
}

function logout() {
    state.token = null;
    sessionStorage.removeItem('bf_token');
    sessionStorage.removeItem('bf_admin');
    if (state.ws) state.ws.close();
    if (state.autoRefresh) clearInterval(state.autoRefresh);
    document.getElementById('app').classList.add('hidden');
    document.getElementById('login-screen').classList.remove('hidden');
}

document.getElementById('logout-btn').addEventListener('click', logout);

// Auto-login if token exists in sessionStorage
(function checkStoredAuth() {
    const token = sessionStorage.getItem('bf_token');
    const admin = sessionStorage.getItem('bf_admin');
    if (token) {
        state.token = token;
        state.adminName = admin || 'admin';
        showApp();
    }
})();

// ─────────────────────────────────────────────────────
// App Initialisation
// ─────────────────────────────────────────────────────
function initApp() {
    initCharts();
    initMap();
    connectWebSocket();
    loadDashboardStats();
    loadLogs();
    loadBlockedIPs();
    loadConfig();
    startClock();

    // Auto-refresh stats every 2 seconds for faster UI updates
    state.autoRefresh = setInterval(() => {
        loadDashboardStats();
        updateBadges();
    }, 2000);

    // Sound toggle
    document.getElementById('sound-toggle-cb').addEventListener('change', (e) => {
        state.soundEnabled = e.target.checked;
    });

    // Sidebar toggle for mobile
    document.getElementById('sidebar-toggle').addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
    });
}

// ─────────────────────────────────────────────────────
// Clock
// ─────────────────────────────────────────────────────
function startClock() {
    const el = document.getElementById('topbar-time');
    function tick() {
        el.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
    }
    tick();
    setInterval(tick, 1000);
}

// ─────────────────────────────────────────────────────
// Section Navigation
// ─────────────────────────────────────────────────────
const UI = {
    switchSection(name) {
        document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

        const section = document.getElementById(`section-${name}`);
        const link = document.getElementById(`nav-${name}`);
        if (section) section.classList.add('active');
        if (link) link.classList.add('active');

        const titles = {
            dashboard: 'Dashboard',
            logs: 'Live Logs',
            alerts: 'Security Alerts',
            simulate: 'Attack Simulator',
            config: 'Configuration',
        };
        document.getElementById('page-title').textContent = titles[name] || name;

        // Close mobile sidebar on nav
        document.getElementById('sidebar').classList.remove('open');

        if (name === 'logs') renderLogTable(state.allLogs.slice(0, 100));
        if (name === 'alerts') renderAlertsFull();
    }
};

// Wire up sidebar nav
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        UI.switchSection(link.dataset.section);
    });
});

// ─────────────────────────────────────────────────────
// WebSocket — Real-time Log Stream
// ─────────────────────────────────────────────────────
function connectWebSocket() {
    if (state.ws) state.ws.close();

    state.ws = new WebSocket(WS_URL);

    state.ws.onopen = () => {
        state.wsConnected = true;
        updateWsStatus(true);
        console.log('[WS] Connected');
        state.ws.send('ping');
    };

    state.ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'pong') return;

        if (msg.type === 'log') {
            handleNewLog(msg.data);
        } else if (msg.type === 'alert') {
            handleNewAlert(msg.data);
        } else if (msg.type === 'ping') {
            state.ws.send(JSON.stringify({ type: 'pong' }));
        }
    };

    state.ws.onclose = () => {
        state.wsConnected = false;
        updateWsStatus(false);
        console.log('[WS] Disconnected. Reconnecting in 3s...');
        setTimeout(connectWebSocket, 3000);
    };

    state.ws.onerror = (err) => {
        console.error('[WS] Error:', err);
        state.ws.close();
    };
}

function updateWsStatus(connected) {
    const dot = document.getElementById('ws-dot');
    const label = document.getElementById('ws-label');
    dot.className = `status-dot ${connected ? 'connected' : 'disconnected'}`;
    label.textContent = connected ? 'Live Stream' : 'Reconnecting...';
}

// ─────────────────────────────────────────────────────
// Log Handling
// ─────────────────────────────────────────────────────
function handleNewLog(log) {
    // Deduplicate by id
    if (state.allLogs.find(l => l.id === log.id)) return;

    state.allLogs.unshift(log);          // Newest first
    if (state.allLogs.length > 1000) state.allLogs.pop();

    updateBadges();

    // Update live table if on logs section and not paused
    if (!state.logsPaused && document.getElementById('section-logs').classList.contains('active')) {
        prependLogRow(log);
    }

    // Update metric cards
    updateMetricCardsIncremental(log);

    // Map feature update
    if (!log.success) {
        addAttackToMap(log.ip, log.risk_score || 0);
    }
}

function handleNewAlert(alert) {
    if (state.alerts.find(a => a.id === alert.id)) return;
    state.alerts.unshift(alert);

    // Show toast
    showToast(alert);

    // Sound
    const isHigh = alert.risk_label === 'High Risk Attack';
    playAlert(isHigh ? 'danger' : 'warning');

    // Update alerts badge
    document.getElementById('alerts-badge').textContent = state.alerts.length;

    // Re-render alerts section if active
    if (document.getElementById('section-alerts').classList.contains('active')) {
        renderAlertsFull();
    }

    // Update dashboard alerts
    renderDashboardAlerts(state.alerts.slice(0, 5));
}

function updateBadges() {
    document.getElementById('logs-badge').textContent = state.allLogs.length;
    document.getElementById('alerts-badge').textContent = state.alerts.length;
}

function toggleLogPause() {
    state.logsPaused = !state.logsPaused;
    document.getElementById('pause-icon').className = state.logsPaused ? 'fas fa-play' : 'fas fa-pause';
    document.getElementById('pause-label').textContent = state.logsPaused ? 'Resume' : 'Pause';
}

// ─────────────────────────────────────────────────────
// Dashboard Stats
// ─────────────────────────────────────────────────────
async function loadDashboardStats() {
    try {
        const stats = await api('/api/dashboard/stats');
        if (!stats) return;
        updateMetricCards(stats);
        updateCharts(stats);
        if (stats.recent_alerts.length > 0) {
            stats.recent_alerts.forEach(a => {
                if (!state.alerts.find(x => x.id === a.id)) {
                    state.alerts.unshift(a);
                }
            });
            renderDashboardAlerts(state.alerts.slice(0, 5));
            renderAlertsFull();
            document.getElementById('alerts-badge').textContent = state.alerts.length;
        }
    } catch (e) {
        console.error('Stats error:', e);
    }
}

function updateMetricCards(stats) {
    animateCount('m-total', stats.total_requests);
    animateCount('m-failed', stats.failed_logins);
    animateCount('m-attacks', stats.active_attacks);
    animateCount('m-blocked', stats.blocked_ips);

    document.getElementById('m-success-rate').textContent = `${stats.success_rate}%`;
    document.getElementById('m-total-rate').textContent = `${stats.total_requests} total`;

    const attackCard = document.getElementById('card-attacks');
    if (stats.active_attacks > 0) {
        attackCard.classList.add('has-attacks');
        document.getElementById('m-attack-label').textContent = '⚠ THREAT DETECTED';
    } else {
        attackCard.classList.remove('has-attacks');
        document.getElementById('m-attack-label').textContent = 'Monitoring...';
    }
}

function updateMetricCardsIncremental(log) {
    const total = parseInt(document.getElementById('m-total').textContent) || 0;
    const failed = parseInt(document.getElementById('m-failed').textContent) || 0;
    document.getElementById('m-total').textContent = total + 1;
    if (!log.success) document.getElementById('m-failed').textContent = failed + 1;
}

function animateCount(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseInt(el.textContent) || 0;
    if (current === target) return;
    const step = Math.ceil(Math.abs(target - current) / 20);
    let val = current;
    const timer = setInterval(() => {
        val = val < target ? Math.min(val + step, target) : Math.max(val - step, target);
        el.textContent = val;
        if (val === target) clearInterval(timer);
    }, 30);
}

// ─────────────────────────────────────────────────────
// Charts
// ─────────────────────────────────────────────────────
function initCharts() {
    // Set Chart.js global defaults for dark theme
    Chart.defaults.color = '#00cc33';
    Chart.defaults.borderColor = 'rgba(0,255,65,0.1)';
    Chart.defaults.font.family = "'JetBrains Mono', 'Courier New', Courier, monospace";

    // ── Timeline Chart (Line) ────────────────────────
    state.charts.timeline = new Chart(
        document.getElementById('timelineChart').getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Failed Logins',
                data: [],
                borderColor: '#00ff41',
                backgroundColor: 'rgba(0,255,65,0.08)',
                borderWidth: 2.5,
                pointRadius: 3,
                pointBackgroundColor: '#00ff41',
                tension: 0.4,
                fill: true,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            animation: { duration: 500 },
            plugins: { legend: { display: false }, tooltip: tooltipConfig() },
            scales: {
                x: {
                    grid: { color: 'rgba(0,255,65,0.05)' },
                    ticks: { maxTicksLimit: 12, font: { size: 10 } }
                },
                y: {
                    grid: { color: 'rgba(0,255,65,0.05)' },
                    ticks: { font: { size: 10 }, stepSize: 1 },
                    beginAtZero: true,
                }
            }
        }
    });

    // ── Risk Distribution (Doughnut) ─────────────────
    state.charts.risk = new Chart(
        document.getElementById('riskChart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'Suspicious', 'High Risk'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(0,255,65,0.7)',
                    'rgba(255,140,0,0.7)',
                    'rgba(255,0,60,0.7)',
                ],
                borderColor: ['#00ff41', '#ff8c00', '#ff003c'],
                borderWidth: 2,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            animation: { duration: 600 },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { padding: 16, usePointStyle: true, pointStyleWidth: 10 }
                },
                tooltip: tooltipConfig()
            },
            cutout: '65%',
        }
    });

    // ── Top IPs Chart (Bar) ──────────────────────────
    state.charts.topIps = new Chart(
        document.getElementById('topIpsChart').getContext('2d'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Failed Attempts',
                data: [],
                backgroundColor: 'rgba(255,0,60,0.4)',
                borderColor: '#ff003c',
                borderWidth: 2,
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            animation: { duration: 500 },
            indexAxis: 'y',  // Horizontal bar
            plugins: { legend: { display: false }, tooltip: tooltipConfig() },
            scales: {
                x: {
                    grid: { color: 'rgba(255,0,60,0.05)' },
                    ticks: { font: { size: 10 } },
                    beginAtZero: true,
                },
                y: { grid: { display: false }, ticks: { font: { size: 10, family: "'JetBrains Mono', monospace" } } },
            }
        }
    });
}

function tooltipConfig() {
    return {
        backgroundColor: 'rgba(0,10,0,0.95)',
        borderColor: 'rgba(0,255,65,0.3)',
        borderWidth: 1,
        titleColor: '#00ff41',
        bodyColor: '#00cc33',
        padding: 10,
        cornerRadius: 8,
    };
}

function updateCharts(stats) {
    // Timeline
    const ts = stats.time_series.slice(-30);  // Last 30 min
    state.charts.timeline.data.labels = ts.map(t => `${t.minute}m`);
    state.charts.timeline.data.datasets[0].data = ts.map(t => t.count);
    state.charts.timeline.update('none');

    // Risk distribution
    const rd = stats.risk_distribution;
    state.charts.risk.data.datasets[0].data = [
        rd['Normal Activity'] || 0,
        rd['Suspicious'] || 0,
        rd['High Risk Attack'] || 0,
    ];
    state.charts.risk.update('none');

    // Top IPs
    const ips = stats.top_attacking_ips.slice(0, 8);
    state.charts.topIps.data.labels = ips.map(i => i.ip);
    state.charts.topIps.data.datasets[0].data = ips.map(i => i.count);
    state.charts.topIps.update('none');

    // Heatmap
    updateHeatmap(stats.top_attacking_ips);
}

// ─────────────────────────────────────────────────────
// Heatmap
// ─────────────────────────────────────────────────────
function updateHeatmap(ipData) {
    const container = document.getElementById('heatmap-container');
    if (!ipData || ipData.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-check-circle"></i> No threat data</div>';
        return;
    }
    const maxCount = Math.max(...ipData.map(d => d.count), 1);
    let html = '';

    // Build heatmap-like grid from all logs' risk scores
    const recentLogs = state.allLogs.slice(0, 60);
    if (recentLogs.length > 0) {
        recentLogs.forEach(log => {
            const score = log.risk_score || 0;
            const [r, g, b] = getHeatColor(score);
            const opacity = 0.3 + (score / 100) * 0.7;
            html += `<div class="heatmap-cell" style="background:rgba(${r},${g},${b},${opacity})"
                         title="${log.ip} | Score: ${score}">${Math.round(score)}</div>`;
        });
    } else {
        ipData.forEach(({ ip, count }) => {
            const ratio = count / maxCount;
            const score = Math.round(ratio * 100);
            const [r, g, b] = getHeatColor(score);
            const opacity = 0.2 + ratio * 0.8;
            html += `<div class="heatmap-cell" style="background:rgba(${r},${g},${b},${opacity})"
                         title="${ip} | ${count} attempts">${count}</div>`;
        });
    }

    container.innerHTML = html;
}

function getHeatColor(score) {
    if (score < 40) return [0, 255, 65];     // matrix green
    if (score < 70) return [255, 140, 0];    // orange
    return [255, 0, 60];                     // red
}

// ─────────────────────────────────────────────────────
// Log Table
// ─────────────────────────────────────────────────────
async function loadLogs() {
    try {
        const data = await api('/api/dashboard/logs?limit=100');
        if (!data) return;
        state.allLogs = data.logs;
        document.getElementById('log-count').textContent = `${data.total} records`;
        renderLogTable(state.allLogs);
    } catch (e) { console.error('Logs error:', e); }
}

function renderLogTable(logs) {
    const tbody = document.getElementById('log-tbody');
    if (!logs || logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" class="empty-state">
            <i class="fas fa-satellite-dish"></i> No logs yet — trigger a simulation!
        </td></tr>`;
        return;
    }

    tbody.innerHTML = logs.map(log => buildLogRow(log)).join('');
    document.getElementById('log-count').textContent = `${state.allLogs.length} records`;
}

function buildLogRow(log) {
    const riskClass = {
        'High Risk Attack': 'high',
        'Suspicious': 'suspicious',
        'Normal Activity': 'normal'
    }[log.risk_label] || 'normal';

    const rowClass = riskClass === 'high' ? 'high-risk' : riskClass === 'suspicious' ? 'suspicious' : '';
    const timeStr = new Date(log.timestamp).toLocaleTimeString();
    const blocked = log.is_blocked;

    const attackClass = log.attack_type === 'Brute Force' ? 'brute-force'
        : log.attack_type === 'Distributed Brute Force' ? 'distributed'
            : log.attack_type === 'Credential Stuffing' ? 'stuffing'
                : 'normal-type';

    return `<tr class="${rowClass}">
        <td class="time-cell">${timeStr}</td>
        <td class="ip-cell clickable-ip" onclick="openInvestigation('${log.ip}')" title="Click to investigate IP">${escHtml(log.ip)}</td>
        <td class="user-cell">${escHtml(log.username)}</td>
        <td><i class="fas fa-globe" style="color:var(--text-muted);margin-right:5px;font-size:10px"></i>${escHtml(log.country || '—')}</td>
        <td>
            ${blocked
            ? '<span class="status-badge blocked">BLOCKED</span>'
            : log.success
                ? '<span class="status-badge success">✓ OK</span>'
                : '<span class="status-badge fail">✗ FAIL</span>'
        }
        </td>
        <td style="font-family:var(--font-mono);color:var(--neon-orange)">${log.ip_fail_count}</td>
        <td>
            <span class="risk-pill ${riskClass}">
                ${log.risk_score}
            </span>
        </td>
        <td style="font-size:12px;color:${riskClass === 'high' ? 'var(--neon-red)' : riskClass === 'suspicious' ? 'var(--neon-orange)' : 'var(--neon-green)'}">${escHtml(log.risk_label)}</td>
        <td><span class="attack-badge ${attackClass}">${escHtml(log.attack_type)}</span></td>
        <td>
            <button class="btn-block ${blocked ? 'blocked' : ''}"
                    onclick="${blocked ? `unblockIp('${log.ip}',this)` : `blockIp('${log.ip}',this)`}">
                ${blocked ? '🔓 Unblock' : '🔒 Block'}
            </button>
        </td>
    </tr>`;
}

function prependLogRow(log) {
    const tbody = document.getElementById('log-tbody');

    // Remove "waiting" placeholder
    const placeholder = tbody.querySelector('.empty-state');
    if (placeholder) tbody.innerHTML = '';

    const tr = document.createElement('tr');
    tr.className = 'new-entry';
    tr.innerHTML = buildLogRow(log).match(/<tr[^>]*>([\s\S]*)<\/tr>/)[1];

    // Apply row class
    const riskClass = { 'High Risk Attack': 'high-risk', 'Suspicious': 'suspicious' }[log.risk_label] || '';
    if (riskClass) tr.classList.add(riskClass);

    tbody.prepend(tr);

    // Limit to 100 rows in DOM
    while (tbody.rows.length > 100) tbody.deleteRow(-1);

    document.getElementById('log-count').textContent = `${state.allLogs.length} records`;
}

// Live filter/search
document.getElementById('log-search').addEventListener('input', debounce(applyFilters, 300));
document.getElementById('filter-risk').addEventListener('change', applyFilters);
document.getElementById('filter-attack').addEventListener('change', applyFilters);

function applyFilters() {
    const search = document.getElementById('log-search').value.toLowerCase();
    const risk = document.getElementById('filter-risk').value.toLowerCase();
    const attack = document.getElementById('filter-attack').value.toLowerCase();

    const filtered = state.allLogs.filter(log => {
        const matchSearch = !search ||
            log.ip.toLowerCase().includes(search) ||
            log.username.toLowerCase().includes(search) ||
            (log.country || '').toLowerCase().includes(search);
        const matchRisk = !risk || log.risk_label.toLowerCase() === risk;
        const matchAttack = !attack || log.attack_type.toLowerCase() === attack;
        return matchSearch && matchRisk && matchAttack;
    });

    renderLogTable(filtered.slice(0, 100));
}

async function loadMoreLogs() {
    state.logOffset += 100;
    try {
        const qs = new URLSearchParams({ limit: 100, offset: state.logOffset });
        const data = await api(`/api/dashboard/logs?${qs}`);
        if (data && data.logs.length) {
            state.allLogs = [...state.allLogs, ...data.logs];
            renderLogTable(state.allLogs.slice(0, state.logOffset + 100));
        }
    } catch (e) { console.error(e); }
}

// ─────────────────────────────────────────────────────
// Alerts
// ─────────────────────────────────────────────────────
function renderDashboardAlerts(alerts) {
    const el = document.getElementById('dashboard-alerts');
    if (!alerts || alerts.length === 0) {
        el.innerHTML = '<div class="empty-state"><i class="fas fa-check-circle"></i> No alerts yet</div>';
        return;
    }
    el.innerHTML = `<div class="alert-list">` + alerts.map(a => {
        const cls = a.risk_label === 'High Risk Attack' ? 'high' : 'suspicious';
        return `<div class="alert-item ${cls}">
            <span class="alert-dot"></span>
            <div class="alert-body">
                <div class="alert-title">${escHtml(a.risk_label)}</div>
                <div class="alert-meta">${escHtml(a.ip)} → ${escHtml(a.username)} | ${new Date(a.timestamp).toLocaleTimeString()}</div>
            </div>
            <span class="alert-score">${Math.round(a.risk_score)}</span>
        </div>`;
    }).join('') + `</div>`;
}

function renderAlertsFull() {
    const el = document.getElementById('alerts-container');
    if (!state.alerts || state.alerts.length === 0) {
        el.innerHTML = '<div class="empty-state"><i class="fas fa-shield-halved"></i> System is monitoring... No alerts yet.</div>';
        return;
    }
    el.innerHTML = state.alerts.map(a => {
        const cls = a.risk_label === 'High Risk Attack' ? 'high' : 'suspicious';
        const icon = a.risk_label === 'High Risk Attack' ? 'fa-skull-crossbones' : 'fa-triangle-exclamation';
        return `<div class="full-alert-card ${cls}">
            <div class="alert-icon-big"><i class="fas ${icon}"></i></div>
            <div class="full-alert-body">
                <div class="full-alert-title">${escHtml(a.risk_label)} — ${escHtml(a.attack_type)}</div>
                <div class="full-alert-msg">${escHtml(a.message || '')}</div>
                <div class="full-alert-tags">
                    <span class="tag ip"><i class="fas fa-network-wired"></i> ${escHtml(a.ip)}</span>
                    <span class="tag user"><i class="fas fa-user"></i> ${escHtml(a.username)}</span>
                    <span class="tag score"><i class="fas fa-gauge-high"></i> Score: ${a.risk_score}</span>
                    <span class="tag"><i class="fas fa-clock"></i> ${new Date(a.timestamp).toLocaleString()}</span>
                </div>
            </div>
            <div class="full-alert-score">${Math.round(a.risk_score)}</div>
        </div>`;
    }).join('');
}

function clearAlerts() {
    state.alerts = [];
    renderAlertsFull();
    renderDashboardAlerts([]);
    document.getElementById('alerts-badge').textContent = '0';
}

// ─────────────────────────────────────────────────────
// Toast Notification
// ─────────────────────────────────────────────────────
let toastTimer = null;

function showToast(alert) {
    const toast = document.getElementById('alert-toast');
    document.getElementById('toast-title').textContent = alert.risk_label;
    document.getElementById('toast-msg').textContent =
        `${alert.ip} → ${alert.username} | Score: ${alert.risk_score}`;
    toast.classList.remove('hidden');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(closeToast, 5000);
}

function closeToast() {
    document.getElementById('alert-toast').classList.add('hidden');
}

// ─────────────────────────────────────────────────────
// Investigation Panel
// ─────────────────────────────────────────────────────
async function openInvestigation(ip) {
    document.getElementById('investigation-overlay').classList.remove('hidden');
    document.getElementById('investigation-overlay').classList.add('active');
    document.getElementById('investigation-panel').classList.add('active');

    const content = document.getElementById('investigation-content');
    content.innerHTML = `<div style="text-align:center; padding: 60px 20px;">
        <i class="fas fa-spinner fa-spin fa-2x" style="color:var(--neon-blue)"></i>
        <p class="mt-20" style="color:var(--text-secondary)">Gathering Threat Intel for ${ip}...</p>
    </div>`;

    // Process local buffer for intel
    const logsForIp = state.allLogs.filter(l => l.ip === ip);
    const fails = logsForIp.filter(l => !l.success).length;
    const usernames = [...new Set(logsForIp.map(l => l.username))];
    const latestLog = logsForIp[0] || {};
    const riskScore = latestLog.risk_score || 0;

    // Simulate Reputation Score (0 to 100)
    let repScore = Math.min(100, (fails * 3) + (usernames.length * 6) + (riskScore > 50 ? 20 : 0));
    let color = repScore > 65 ? 'var(--neon-red)' : repScore > 35 ? 'var(--neon-orange)' : 'var(--neon-green)';

    // Fetch Geo
    const geo = await getGeo(ip);
    const locStr = geo ? `${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}` : 'Unknown Location';
    const orgStr = geo ? geo.organization || geo.asn || 'Unknown Provider' : 'Unknown Provider';

    content.innerHTML = `
        <div class="inv-section">
            <h2 style="font-family: var(--font-mono); color: var(--neon-blue); font-size: 24px; margin-bottom: 8px;">${ip}</h2>
            <div class="status-badge ${latestLog.is_blocked ? 'blocked' : 'fail'}" style="display:inline-block">
                ${latestLog.is_blocked ? 'BLOCKED' : 'ACTIVE THREAT'}
            </div>
        </div>

        <div class="inv-section">
            <div class="inv-section-title">Threat Intelligence (AbuseIPDB mock)</div>
            <div class="inv-card">
                <div class="inv-card-row">
                    <span class="inv-label">Abuse / Malicious Confidence</span>
                    <span class="inv-value" style="color: ${color}">${repScore}%</span>
                </div>
                <div class="reputation-meter">
                    <div class="reputation-fill" style="width: ${repScore}%; background: ${color}"></div>
                </div>
            </div>
        </div>

        <div class="inv-section">
            <div class="inv-section-title">Enrichment (GeoJS)</div>
            <div class="inv-card">
                <div class="inv-card-row"><span class="inv-label">Location</span><span class="inv-value">${locStr}</span></div>
                <div class="inv-card-row"><span class="inv-label">Provider/ASN</span><span class="inv-value">${orgStr}</span></div>
            </div>
        </div>

        <div class="inv-section">
            <div class="inv-section-title">Attack History (Local Cache)</div>
            <div class="inv-card">
                <div class="inv-card-row"><span class="inv-label">Total Attempts Seen</span><span class="inv-value">${logsForIp.length}</span></div>
                <div class="inv-card-row"><span class="inv-label">Failed Logins</span><span class="inv-value danger">${fails}</span></div>
                <div class="inv-card-row">
                    <span class="inv-label">Targeted Accounts (${usernames.length})</span>
                    <span class="inv-value" style="font-size: 11px; max-width: 150px; white-space: normal; line-height: 1.4;">
                        ${usernames.slice(0, 5).join(', ')}${usernames.length > 5 ? '...' : ''}
                    </span>
                </div>
                <div class="inv-card-row"><span class="inv-label">Last known Attack Type</span><span class="inv-value" style="color: var(--neon-orange)">${latestLog.attack_type || 'N/A'}</span></div>
            </div>
        </div>

        <div style="margin-top: 30px; display: flex; gap: 12px;">
            ${latestLog.is_blocked
            ? `<button class="btn-login" style="background: rgba(168,85,247,0.2); border: 1px solid var(--neon-purple);" onclick="unblockIp('${ip}'); closeInvestigation();">
                       <i class="fas fa-unlock" style="color: var(--neon-purple);"></i>
                       <span style="color: var(--neon-purple); margin-left:8px;">Unblock IP</span>
                   </button>`
            : `<button class="btn-login" style="background: rgba(255,56,96,0.2); border: 1px solid var(--neon-red);" onclick="blockIp('${ip}'); closeInvestigation();">
                       <i class="fas fa-ban" style="color: var(--neon-red);"></i>
                       <span style="color: var(--neon-red); font-weight: bold; margin-left: 8px;">Force Block IP</span>
                   </button>`
        }
        </div>
    `;
}

function closeInvestigation() {
    document.getElementById('investigation-overlay').classList.remove('active');
    document.getElementById('investigation-panel').classList.remove('active');
    setTimeout(() => {
        document.getElementById('investigation-overlay').classList.add('hidden');
    }, 400); // Wait for transition
}

// ─────────────────────────────────────────────────────
// Simulation
// ─────────────────────────────────────────────────────
async function simulate(mode) {
    const modeMap = {
        brute_force: 'sim-brute',
        distributed: 'sim-distributed',
        stuffing: 'sim-stuffing',
        mixed: 'sim-mixed',
    };
    const cardId = modeMap[mode];

    // Show loading
    const card = document.getElementById(cardId);
    const btn = card?.querySelector('.btn-simulate');
    if (btn) { btn.textContent = '⏳ Simulating...'; btn.disabled = true; }

    const resultEl = document.getElementById('sim-result');
    resultEl.classList.add('hidden');

    try {
        const result = await api('/api/simulate', {
            method: 'POST',
            body: JSON.stringify({ mode })
        });
        if (!result) return;

        // Show results box
        resultEl.innerHTML = `
            <h3 style="color:var(--neon-blue);margin-bottom:16px">
                <i class="fas fa-chart-bar"></i> Simulation Complete: <em>${mode.replace('_', ' ')}</em>
            </h3>
            <div class="result-grid">
                <div class="result-stat blue"><div class="num">${result.total_generated}</div><div class="lbl">Total Events</div></div>
                <div class="result-stat red"><div class="num">${result.high_risk}</div><div class="lbl">High Risk</div></div>
                <div class="result-stat orange"><div class="num">${result.suspicious}</div><div class="lbl">Suspicious</div></div>
                <div class="result-stat green"><div class="num">${result.normal}</div><div class="lbl">Normal</div></div>
            </div>
            <p style="margin-top:14px;font-size:12px;color:var(--text-muted)">
                <i class="fas fa-info-circle"></i>
                Attack types detected: ${result.attack_types.join(', ')} | Navigate to <strong>Live Logs</strong> & <strong>Dashboard</strong> to see results.
            </p>`;
        resultEl.classList.remove('hidden');

        // Refresh dashboard
        await loadDashboardStats();
        await loadLogs();

    } catch (e) {
        resultEl.innerHTML = `<div class="manual-result show high">❌ Simulation failed: ${e.message}</div>`;
        resultEl.classList.remove('hidden');
    } finally {
        if (btn) {
            btn.textContent = '▶ Launch Attack';
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-play"></i> Launch Attack';
        }
    }
}

async function submitManual() {
    const ip = document.getElementById('m-ip').value.trim();
    const username = document.getElementById('m-username').value.trim();
    const country = document.getElementById('m-country').value.trim();
    const success = document.getElementById('m-success').value === 'true';
    const resultEl = document.getElementById('manual-result');

    if (!ip || !username) {
        resultEl.className = 'manual-result show suspicious';
        resultEl.textContent = '⚠ IP and username are required.';
        return;
    }

    try {
        const result = await api('/api/login-attempt', {
            method: 'POST',
            body: JSON.stringify({ ip, username, success, country, city: '' })
        });
        if (!result) return;

        const cls = result.risk_label === 'High Risk Attack' ? 'high'
            : result.risk_label === 'Suspicious' ? 'suspicious' : 'normal';
        resultEl.className = `manual-result show ${cls}`;
        resultEl.textContent =
            `→ ${result.risk_label} | Risk Score: ${result.risk_score} | Type: ${result.attack_type} | IP Fails: ${result.ip_fail_count}`;
    } catch (e) {
        resultEl.className = 'manual-result show high';
        resultEl.textContent = `❌ Error: ${e.message}`;
    }
}

// ─────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────
async function loadConfig() {
    try {
        const cfg = await api('/api/config');
        if (!cfg) return;
        document.getElementById('cfg-fail').value = cfg.fail_threshold;
        document.getElementById('cfg-window').value = cfg.time_window;
        document.getElementById('cfg-dist').value = cfg.dist_threshold;
        document.getElementById('cfg-stuff').value = cfg.stuffing_threshold;
        document.getElementById('cfg-fail-val').textContent = cfg.fail_threshold;
        document.getElementById('cfg-window-val').textContent = `${cfg.time_window}s`;
        document.getElementById('cfg-dist-val').textContent = cfg.dist_threshold;
        document.getElementById('cfg-stuff-val').textContent = cfg.stuffing_threshold;
    } catch (e) { console.error('Config load error:', e); }
}

function updateSlider(sliderId, valId) {
    const val = document.getElementById(sliderId).value;
    const label = document.getElementById(valId);
    label.textContent = sliderId === 'cfg-window' ? `${val}s` : val;
}

async function saveConfig() {
    const msgEl = document.getElementById('config-msg');
    try {
        const result = await api('/api/config', {
            method: 'PUT',
            body: JSON.stringify({
                fail_threshold: parseInt(document.getElementById('cfg-fail').value),
                time_window: parseInt(document.getElementById('cfg-window').value),
                dist_threshold: parseInt(document.getElementById('cfg-dist').value),
                stuffing_threshold: parseInt(document.getElementById('cfg-stuff').value),
            })
        });
        if (!result) return;
        msgEl.textContent = '✅ Configuration saved!';
        msgEl.classList.add('show');
        setTimeout(() => msgEl.classList.remove('show'), 3000);
    } catch (e) {
        msgEl.textContent = `❌ ${e.message}`;
        msgEl.style.color = 'var(--neon-red)';
        msgEl.classList.add('show');
        setTimeout(() => { msgEl.classList.remove('show'); msgEl.style.color = ''; }, 4000);
    }
}

// ─────────────────────────────────────────────────────
// IP Blocking
// ─────────────────────────────────────────────────────
async function blockIp(ip, btn) {
    try {
        await api(`/api/ip/block/${encodeURIComponent(ip)}`, { method: 'POST' });
        if (btn) { btn.textContent = '🔓 Unblock'; btn.className = 'btn-block blocked'; btn.onclick = () => unblockIp(ip, btn); }
        loadBlockedIPs();
        showFlash(`✅ IP ${ip} has been blocked.`, 'green');
    } catch (e) { showFlash(`❌ ${e.message}`, 'red'); }
}

async function unblockIp(ip, btn) {
    try {
        await api(`/api/ip/unblock/${encodeURIComponent(ip)}`, { method: 'POST' });
        if (btn) { btn.textContent = '🔒 Block'; btn.className = 'btn-block'; btn.onclick = () => blockIp(ip, btn); }
        loadBlockedIPs();
        showFlash(`✅ IP ${ip} has been unblocked.`, 'green');
    } catch (e) { showFlash(`❌ ${e.message}`, 'red'); }
}

function blockIpManual() {
    const ip = document.getElementById('block-ip-input').value.trim();
    if (!ip) return;
    blockIp(ip, null);
    document.getElementById('block-ip-input').value = '';
}

async function loadBlockedIPs() {
    try {
        const data = await api('/api/ip/blocked');
        if (!data) return;
        const el = document.getElementById('blocked-ips-list');
        animateCount('m-blocked', data.count);
        if (data.blocked_ips.length === 0) {
            el.innerHTML = '<div class="empty-state"><i class="fas fa-shield-check"></i> No blocked IPs</div>';
            return;
        }
        el.innerHTML = '<div class="blocked-list">' + data.blocked_ips.map(ip =>
            `<div class="blocked-ip-row">
                <span><i class="fas fa-ban" style="color:var(--neon-red);margin-right:8px"></i>${escHtml(ip)}</span>
                <button class="btn-sm danger" onclick="unblockIp('${ip}', null)">Unblock</button>
            </div>`
        ).join('') + '</div>';
    } catch (e) { console.error(e); }
}

// ─────────────────────────────────────────────────────
// Export CSV
// ─────────────────────────────────────────────────────
async function exportCSV() {
    try {
        const res = await apiRaw('/api/export/csv');
        if (!res || !res.ok) throw new Error('Export failed');
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `brute_force_logs_${Date.now()}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) { showFlash(`❌ Export failed: ${e.message}`, 'red'); }
}

// ─────────────────────────────────────────────────────
// Clear Logs
// ─────────────────────────────────────────────────────
async function clearLogs() {
    if (!confirm('Clear all logs and reset detection state? This cannot be undone.')) return;
    try {
        await api('/api/logs/clear', { method: 'DELETE' });
        state.allLogs = [];
        state.alerts = [];
        renderLogTable([]);
        renderDashboardAlerts([]);
        renderAlertsFull();
        updateBadges();
        animateCount('m-total', 0);
        animateCount('m-failed', 0);
        animateCount('m-attacks', 0);
        updateCharts({ time_series: [], top_attacking_ips: [], risk_distribution: { 'Normal Activity': 0, 'Suspicious': 0, 'High Risk Attack': 0 } });
        showFlash('✅ All logs cleared.', 'green');
    } catch (e) { showFlash(`❌ ${e.message}`, 'red'); }
}

// ─────────────────────────────────────────────────────
// Utility Helpers
// ─────────────────────────────────────────────────────
function escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function debounce(fn, delay) {
    let timer;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); };
}

function showFlash(msg, color = 'green') {
    const colors = { green: 'var(--neon-green)', red: 'var(--neon-red)', blue: 'var(--neon-blue)' };
    const div = document.createElement('div');
    div.style.cssText = `
        position:fixed;top:24px;right:24px;z-index:99999;
        background:rgba(13,19,33,0.97);
        border:1px solid ${colors[color]};
        border-radius:10px;padding:12px 20px;
        color:${colors[color]};font-size:13px;font-weight:600;
        box-shadow:0 8px 30px rgba(0,0,0,0.5);
        animation:toastIn 0.3s ease;
    `;
    div.textContent = msg;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 3500);
}

// ─────────────────────────────────────────────────────
// Expose globals for inline onclick handlers
// ─────────────────────────────────────────────────────
window.UI = UI;
window.simulate = simulate;
window.submitManual = submitManual;
window.saveConfig = saveConfig;
window.updateSlider = updateSlider;
window.blockIp = blockIp;
window.unblockIp = unblockIp;
window.blockIpManual = blockIpManual;
window.loadMoreLogs = loadMoreLogs;
window.exportCSV = exportCSV;
window.clearLogs = clearLogs;
window.clearAlerts = clearAlerts;
window.toggleLogPause = toggleLogPause;
window.closeToast = closeToast;
