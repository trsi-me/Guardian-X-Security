const API_BASE = typeof window !== 'undefined'
    ? `${window.location.protocol}//${window.location.host}`
    : 'http://127.0.0.1:5000';

// Page titles for each section
const PAGE_TITLES = {
    dashboard: { heading: 'Dashboard', desc: 'Monitor and detect anomalous file activity' },
    events: { heading: 'Events', desc: 'All recorded file activities' },
    health: { heading: 'System Health', desc: 'ML models, containment, server status' },
    reports: { heading: 'Reports', desc: 'Statistical activity summary' }
};

// Activity type icons (SVG - Feather/Lucide style)
const ACTIVITY_ICONS = {
    Create: '<span class="activity-icon" title="Create"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg></span>',
    Read: '<span class="activity-icon" title="Read"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></span>',
    Modify: '<span class="activity-icon" title="Modify"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></span>',
    Delete: '<span class="activity-icon" title="Delete"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg></span>',
    FileDownload: '<span class="activity-icon" title="FileDownload"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></span>',
    Transaction: '<span class="activity-icon" title="Transaction"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg></span>',
    FileCopy: '<span class="activity-icon" title="FileCopy"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></span>'
};

function riskClass(level) {
    if (!level) return 'normal';
    if (String(level).includes('High')) return 'high';
    if (String(level).toLowerCase().includes('suspicious')) return 'suspicious';
    return 'normal';
}

function getApiUrl(path) {
    return API_BASE ? API_BASE + path : path;
}

async function fetchApi(path) {
    const res = await fetch(getApiUrl(path));
    if (!res.ok) throw new Error('Server connection failed');
    return res.json();
}

async function postApi(path, data) {
    const res = await fetch(getApiUrl(path), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Request failed');
    }
    return res.json();
}

// Toast notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(20px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function updateLastUpdate() {
    const el = document.getElementById('lastUpdate');
    if (el) el.textContent = new Date().toLocaleTimeString('en-US');
}

function updateStatus(online) {
    const el = document.getElementById('systemStatus');
    if (!el) return;
    el.classList.remove('online', 'offline');
    el.classList.add(online ? 'online' : 'offline');
    const textEl = el.querySelector('.status-text');
    if (textEl) textEl.textContent = online ? 'Online' : 'Offline';
}

function showSection(sectionId) {
    document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(t => t.classList.remove('active'));
    const section = document.getElementById('section-' + sectionId);
    const tab = document.querySelector('.nav-item[data-section="' + sectionId + '"]');
    if (section) section.classList.add('active');
    if (tab) tab.classList.add('active');

    const titles = PAGE_TITLES[sectionId];
    if (titles) {
        const heading = document.getElementById('pageHeading');
        const desc = document.getElementById('pageDesc');
        if (heading) heading.textContent = titles.heading;
        if (desc) desc.textContent = titles.desc;
    }

    if (sectionId === 'events') loadEventsPage();
    if (sectionId === 'health') loadHealthPage();
    if (sectionId === 'reports') loadReportsPage();
}

async function loadStats() {
    try {
        const data = await fetchApi('/api/stats');
        const h = document.getElementById('highRiskCount');
        const s = document.getElementById('suspiciousCount');
        const a = document.getElementById('alertsCount');
        const t = document.getElementById('totalEvents');
        const ag = document.getElementById('activeAgents');
        if (h) h.textContent = data.high_risk || 0;
        if (s) s.textContent = data.suspicious || 0;
        if (a) a.textContent = data.total_alerts || 0;
        if (t) t.textContent = data.total_events || 0;
        if (ag) ag.textContent = data.active_agents ?? 0;
        updateStatus(true);
        updateLastUpdate();
    } catch (e) {
        updateStatus(false);
    }
}

function formatTime(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleString('en-US');
}

function getActivityIcon(type) {
    return ACTIVITY_ICONS[type] || '<span class="activity-icon" title="File"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></span>';
}

function renderEvents(events, listId, filters = {}, options = {}) {
    const list = document.getElementById(listId);
    if (!list) return;

    let filtered = events;
    if (filters.risk) {
        filtered = filtered.filter(e => (e.risk_level || '') === filters.risk);
    }
    if (filters.search) {
        const q = filters.search.toLowerCase();
        filtered = filtered.filter(e =>
            (e.user_id || '').toLowerCase().includes(q) ||
            (e.file_path || '').toLowerCase().includes(q)
        );
    }

    const showExplain = options.showExplain && listId === 'eventsListFull';
    const isRisky = (e) => (e.risk_level || '').includes('High') || (e.risk_level || '').toLowerCase().includes('suspicious');

    if (!filtered.length) {
        list.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg></div>
                <p class="empty-state-text">No events found</p>
            </div>
        `;
        return;
    }

    list.innerHTML = filtered.map(e => `
        <div class="event-item risk-${riskClass(e.risk_level)}" data-event-id="${e.id || ''}">
            <div class="event-header">
                <span class="event-user">${getActivityIcon(e.activity_type)} ${e.user_id}</span>
                <span class="event-header-right">
                    <span class="risk-pill ${riskClass(e.risk_level)}">${e.risk_level || 'Normal'}</span>
                    ${showExplain && isRisky(e) ? `<button type="button" class="btn-explain" data-event-id="${e.id}" title="View XAI explanation">Explain</button>` : ''}
                </span>
            </div>
            <div class="event-meta">${e.activity_type} — ${e.file_path}</div>
            <div class="event-file">${formatTime(e.timestamp)}</div>
        </div>
    `).join('');

    if (showExplain) {
        list.querySelectorAll('.btn-explain').forEach(btn => {
            btn.addEventListener('click', () => showExplanation(parseInt(btn.dataset.eventId)));
        });
    }
}

function renderAlerts(alerts) {
    const list = document.getElementById('alertsList');
    if (!list) return;

    if (!alerts.length) {
        list.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
                <p class="empty-state-text">No active alerts</p>
            </div>
        `;
        return;
    }

    list.innerHTML = alerts.map(a => `
        <div class="alert-item risk-${riskClass(a.risk_level)}" data-alert-id="${a.id}" data-event-ids="${a.file_event_ids || ''}">
            <div class="event-header">
                <span class="alert-user">${a.user_id}</span>
                <span class="event-header-right">
                    <span class="risk-pill ${riskClass(a.risk_level)}">${a.risk_level || 'Normal'}</span>
                    ${a.risk_level === 'High Risk' ? `<button type="button" class="btn-contain" data-alert-id="${a.id}" data-event-ids="${a.file_event_ids || ''}" title="Simulate containment">Contain</button>` : ''}
                </span>
            </div>
            <div class="alert-reason">${a.reason}</div>
            <div class="event-file">${formatTime(a.timestamp)}</div>
        </div>
    `).join('');
    list.querySelectorAll('.btn-contain').forEach(btn => {
        btn.addEventListener('click', async () => {
            const eventIds = (btn.dataset.eventIds || '').split(',').filter(Boolean);
            const eventId = eventIds[0] ? parseInt(eventIds[0]) : null;
            try {
                await postApi('/api/containment', {
                    alert_id: parseInt(btn.dataset.alertId),
                    file_event_id: eventId,
                    action_type: 'block',
                    details: 'Simulated block action'
                });
                showToast('Containment action logged', 'success');
                loadContainmentList();
            } catch (e) {
                showToast(e.message || 'Failed', 'error');
            }
        });
    });
}

let cachedEvents = [];

async function loadEventsPage() {
    const list = document.getElementById('eventsListFull');
    if (!list) return;
    try {
        list.innerHTML = '<div class="skeleton-list"><div class="skeleton-item"></div><div class="skeleton-item"></div><div class="skeleton-item"></div><div class="skeleton-item"></div><div class="skeleton-item"></div></div>';
        const events = await fetchApi('/api/events?limit=100');
        cachedEvents = events;
        applyEventsFilter();
    } catch (e) {
        list.innerHTML = '<p class="loading">Unable to connect to server</p>';
    }
}

function applyEventsFilter() {
    const riskFilter = document.getElementById('filterRisk');
    const searchInput = document.getElementById('filterSearch');
    const filters = {
        risk: riskFilter?.value || '',
        search: searchInput?.value?.trim() || ''
    };
    renderEvents(cachedEvents, 'eventsListFull', filters, { showExplain: true });
}

async function loadHealthPage() {
    const serverEl = document.getElementById('serverStatus');
    const serverDetail = document.getElementById('serverDetail');
    const dbEl = document.getElementById('dbStatus');
    const dbDetail = document.getElementById('dbDetail');
    const mlEl = document.getElementById('mlStatus');
    const mlDetail = document.getElementById('mlDetail');
    if (!serverEl || !dbEl) return;
    try {
        const data = await fetchApi('/api/health');
        serverEl.textContent = 'Running';
        serverEl.className = 'health-badge ok';
        serverDetail.textContent = 'Server is running normally. Last check: ' + new Date().toLocaleTimeString('en-US');
        dbEl.textContent = data.database === 'connected' ? 'Connected' : 'Error';
        dbEl.className = 'health-badge ' + (data.database === 'connected' ? 'ok' : 'error');
        dbDetail.textContent = data.database === 'connected' ? 'SQLite database is running normally.' : 'Unable to connect to database.';
        if (mlEl) {
            mlEl.textContent = data.ml_models ? 'Ready' : 'Not trained';
            mlEl.className = 'health-badge ' + (data.ml_models ? 'ok' : '');
            if (mlDetail) mlDetail.textContent = data.ml_models ? 'Isolation Forest, LightGBM, Autoencoder loaded' : 'Click "Train ML Models" on Dashboard to train.';
        }
        updateStatus(true);
        loadContainmentList();
        loadAgentsList();
    } catch (e) {
        serverEl.textContent = 'Offline';
        serverEl.className = 'health-badge error';
        serverDetail.textContent = 'Unable to connect to server. Ensure it is running on port 5000.';
        dbEl.textContent = '—';
        dbEl.className = 'health-badge';
        dbDetail.textContent = 'Unavailable without server connection.';
        if (mlEl) { mlEl.textContent = '—'; mlEl.className = 'health-badge'; }
        updateStatus(false);
    }
}

async function loadAgentsList() {
    const list = document.getElementById('agentsList');
    if (!list) return;
    try {
        const agents = await fetchApi('/api/agents');
        if (!agents.length) {
            list.innerHTML = '<div class="empty-state"><p class="empty-state-text">No agents. Use "Simulate Agent" on Dashboard.</p></div>';
            return;
        }
        list.innerHTML = agents.map(a => `
            <div class="containment-item">
                <span class="containment-type">${a.agent_id || '—'}</span>
                <span class="containment-detail">${a.hostname} (${a.source})</span>
                <span class="event-file">${formatTime(a.last_seen)}</span>
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = '<p class="empty-state-text">Unable to load</p>';
    }
}

async function loadContainmentList() {
    const list = document.getElementById('containmentList');
    if (!list) return;
    try {
        const actions = await fetchApi('/api/containment');
        if (!actions.length) {
            list.innerHTML = '<div class="empty-state"><p class="empty-state-text">No containment actions yet</p></div>';
            return;
        }
        list.innerHTML = actions.map(a => `
            <div class="containment-item">
                <span class="containment-type">${a.action_type || 'log'}</span>
                <span class="containment-detail">${a.details || '—'}</span>
                <span class="event-file">${formatTime(a.created_at)}</span>
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = '<p class="empty-state-text">Unable to load</p>';
    }
}

async function showExplanation(eventId) {
    const modal = document.getElementById('explainModal');
    const body = document.getElementById('explainModalBody');
    if (!modal || !body) return;
    modal.classList.add('active');
    body.innerHTML = '<p class="loading">Loading XAI report...</p>';
    try {
        const data = await fetchApi('/api/explain/' + eventId);
        const summary = Array.isArray(data.summary) ? data.summary : (data.summary ? [data.summary] : []);
        let html = '<div class="xai-summary"><h4>Summary</h4><ul>';
        summary.forEach(s => {
    const text = typeof s === 'string' ? s : JSON.stringify(s);
    const isRisk = text.startsWith('INCREASES RISK');
    const isDecreases = text.startsWith('DECREASES RISK');
    const isConfirms = text.startsWith('CONFIRMS RISK');
    const isReduces = text.startsWith('REDUCES RISK');
    let color = '#888';
    let icon = '•';
    if (isRisk) { color = '#e74c3c'; icon = '🔴'; }
    else if (isDecreases) { color = '#27ae60'; icon = '🟢'; }
    else if (isConfirms) { color = '#e67e22'; icon = '🟡'; }
    else if (isReduces) { color = '#27ae60'; icon = '🟢'; }
    html += '<li style="margin-bottom:12px; padding:10px; border-left:3px solid ' + color + '; background:rgba(0,0,0,0.1); border-radius:4px; line-height:1.6;">' + icon + ' ' + text + '</li>';
});
        
        html += '</ul></div>';
        if (data.shap && data.shap.available && data.shap.top_contributors) {
            html += '<div class="xai-shap"><h4>SHAP Contributors</h4><ul>';
            data.shap.top_contributors.forEach(c => {
                html += `<li><strong>${c.feature}</strong>: ${c.contribution?.toFixed(3) || c.contribution}</li>`;
            });
            html += '</ul></div>';
        }
        if (data.lime && data.lime.available && data.lime.top_contributors) {
            html += '<div class="xai-lime"><h4>LIME Contributors</h4><ul>';
            data.lime.top_contributors.forEach(c => {
                html += `<li><strong>${c.feature}</strong>: ${c.contribution?.toFixed(3) || c.contribution}</li>`;
            });
            html += '</ul></div>';
        }
        body.innerHTML = html || '<p>No explanation available.</p>';
    } catch (e) {
        body.innerHTML = '<p class="loading">Error: ' + (e.message || 'Failed to load') + '</p>';
    }
}

async function loadReportsPage() {
    const body = document.getElementById('reportsBody');
    if (!body) return;
    try {
        const [stats, profile, metrics] = await Promise.all([
            fetchApi('/api/stats'),
            fetchApi('/api/profile'),
            fetchApi('/api/metrics').catch(() => ({}))
        ]);
        body.innerHTML = `
            <div class="report-row">
                <span>Total Events</span>
                <span class="report-value">${stats.total_events || 0}</span>
            </div>
            <div class="report-row">
                <span>High Risk Events</span>
                <span class="report-value">${stats.high_risk || 0}</span>
            </div>
            <div class="report-row">
                <span>Suspicious Events</span>
                <span class="report-value">${stats.suspicious || 0}</span>
            </div>
            <div class="report-row">
                <span>Total Alerts</span>
                <span class="report-value">${stats.total_alerts || 0}</span>
            </div>
            <div class="report-row report-section-title"><span>Performance Metrics (Report 1.4.6)</span></div>
            <div class="report-row">
                <span>MTTD (Mean Time to Detect)</span>
                <span class="report-value">${metrics.mttd_seconds ?? 0} sec</span>
            </div>
            <div class="report-row">
                <span>MTTR (Mean Time to Respond)</span>
                <span class="report-value">${metrics.mttr_seconds ?? 0} sec</span>
            </div>
            <div class="report-row">
                <span>Precision</span>
                <span class="report-value">${(metrics.precision ?? 0).toFixed(4)}</span>
            </div>
            <div class="report-row">
                <span>Recall</span>
                <span class="report-value">${(metrics.recall ?? 0).toFixed(4)}</span>
            </div>
            <div class="report-row">
                <span>Detection Rate</span>
                <span class="report-value">${metrics.detection_rate ?? 0}%</span>
            </div>
            <div class="report-row report-section-title"><span>Behavior Profile</span></div>
            <div class="report-row">
                <span>Avg Operations/Hour</span>
                <span class="report-value">${profile?.avg_ops_per_hour || 15}</span>
            </div>
            <div class="report-row">
                <span>Normal Delete Limit</span>
                <span class="report-value">${profile?.normal_delete_limit || 3} files/hour</span>
            </div>
            <div class="report-row">
                <span>Work Hours</span>
                <span class="report-value">${profile?.work_start_time || '08:00'} - ${profile?.work_end_time || '17:00'}</span>
            </div>
        `;
    } catch (e) {
        body.innerHTML = '<p class="loading">Unable to connect to server</p>';
    }
}

async function loadDashboard() {
    try {
        const [events, alerts] = await Promise.all([
            fetchApi('/api/events'),
            fetchApi('/api/alerts')
        ]);
        renderEvents(events, 'eventsList');
        renderAlerts(alerts);
        await loadStats();
        updateLastUpdate();
    } catch (e) {
        updateStatus(false);
        const el = document.getElementById('eventsList');
        const al = document.getElementById('alertsList');
        const emptyHtml = `
            <div class="empty-state">
                <div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
                <p class="empty-state-text">Unable to connect to server.<br>Ensure the server is running on port 5000.</p>
            </div>
        `;
        if (el) el.innerHTML = emptyHtml;
        if (al) al.innerHTML = emptyHtml;
    }
}

async function refreshData() {
    const btn = document.getElementById('btnRefresh');
    if (btn) {
        btn.classList.add('spin');
        btn.disabled = true;
    }
    const activeSection = document.querySelector('.nav-item.active')?.getAttribute('data-section') || 'dashboard';
    if (activeSection === 'dashboard') await loadDashboard();
    else if (activeSection === 'events') await loadEventsPage();
    else if (activeSection === 'health') await loadHealthPage();
    else if (activeSection === 'reports') await loadReportsPage();
    if (btn) {
        btn.classList.remove('spin');
        btn.disabled = false;
    }
    showToast('Data refreshed', 'success');
}

// Event listeners
document.querySelectorAll('.nav-item').forEach(tab => {
    tab.addEventListener('click', function(e) {
        e.preventDefault();
        const section = this.getAttribute('data-section');
        if (section) showSection(section);
    });
});

document.getElementById('btnRefresh')?.addEventListener('click', refreshData);

document.getElementById('filterRisk')?.addEventListener('change', applyEventsFilter);
document.getElementById('filterSearch')?.addEventListener('input', debounce(applyEventsFilter, 300));

function debounce(fn, ms) {
    let t;
    return function() {
        clearTimeout(t);
        t = setTimeout(() => fn.apply(this, arguments), ms);
    };
}

document.getElementById('modalClose')?.addEventListener('click', () => {
    document.getElementById('explainModal')?.classList.remove('active');
});
document.getElementById('explainModal')?.addEventListener('click', function(e) {
    if (e.target === this) this.classList.remove('active');
});

document.getElementById('btnSimulateAgent')?.addEventListener('click', async function() {
    const btn = this;
    btn.disabled = true;
    btn.textContent = 'Registering...';
    try {
        await postApi('/api/agents/heartbeat', {
            agent_id: 'sim-agent-' + Math.floor(Math.random() * 100),
            hostname: 'simulated-pc'
        });
        showToast('Simulated agent registered', 'success');
        loadStats();
        loadAgentsList();
    } catch (e) {
        showToast(e.message || 'Failed', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Simulate Agent';
    }
});

document.getElementById('btnBatchSimulate')?.addEventListener('click', async function() {
    const btn = this;
    btn.disabled = true;
    btn.textContent = 'Simulating...';
    try {
        const r = await postApi('/api/simulate/batch', { count: 5 });
        showToast(`Created ${r.created} events`, 'success');
        loadDashboard();
    } catch (e) {
        showToast(e.message || 'Failed', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Batch Simulate (5)';
    }
});

document.getElementById('btnTrainML')?.addEventListener('click', async function() {
    const btn = this;
    btn.disabled = true;
    btn.textContent = 'Training...';
    try {
        const r = await postApi('/api/train', { use_db: false });
        showToast(r.success ? 'ML models trained successfully!' : r.error, r.success ? 'success' : 'error');
        if (r.success) loadHealthPage();
    } catch (e) {
        showToast(e.message || 'Training failed', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Train ML Models';
    }
});

document.getElementById('simActivity')?.addEventListener('change', function() {
    const isTx = this.value === 'Transaction';
    document.getElementById('formRowFilePath')?.classList.toggle('form-row-hidden', isTx);
    document.getElementById('formRowTransaction')?.classList.toggle('form-row-hidden', !isTx);
});
document.getElementById('simActivity')?.dispatchEvent(new Event('change'));

document.getElementById('simulateForm')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    const user = document.getElementById('simUser').value.trim();
    const activity = document.getElementById('simActivity').value;
    const filePath = document.getElementById('simFilePath').value.trim();
    const amount = parseInt(document.getElementById('simAmount')?.value || 5000, 10);
    const txType = document.getElementById('simTxType')?.value || 'transfer';
    if (!user) return;
    if (activity === 'Transaction' && (!amount || amount < 1)) return;
    if (activity !== 'Transaction' && !filePath) return;

    const btn = this.querySelector('.btn-primary') || document.getElementById('btnSimulate');
    if (btn) {
        btn.disabled = true;
        const txt = btn.querySelector('.btn-text');
        if (txt) txt.textContent = 'Sending...';
    }

    try {
        let result;
        if (activity === 'Transaction') {
            result = await postApi('/api/simulate/transaction', {
                user_id: user,
                amount: amount,
                transaction_type: txType
            });
        } else {
            result = await postApi('/api/events', {
                user_id: user,
                activity_type: activity,
                file_path: filePath || (activity === 'FileDownload' ? 'customer_data.zip' : '')
            });
        }
        showToast(`Event recorded. Risk level: ${result.risk_level}`, result.risk_level === 'High Risk' ? 'error' : result.risk_level === 'Suspicious' ? 'info' : 'success');
        loadDashboard();
    } catch (err) {
        showToast(err.message || 'Request failed', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            const txt = btn.querySelector('.btn-text');
            if (txt) txt.textContent = 'Send Event';
        }
    }
});

// Init
loadDashboard();
setInterval(loadStats, 10000);
