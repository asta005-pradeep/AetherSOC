document.addEventListener('DOMContentLoaded', () => {
    loadAlerts();

    document.getElementById('btn-simulate').addEventListener('click', async () => {
        const btn = document.getElementById('btn-simulate');
        btn.textContent = "Generating...";
        btn.disabled = true;

        try {
            const res = await fetch('/api/simulate', { method: 'POST' });
            const data = await res.json();
            alert(data.message || 'Data generated');
        } catch (e) {
            alert('Error generating data');
        }

        btn.textContent = "1. Generate Data";
        btn.disabled = false;
    });

    document.getElementById('btn-run').addEventListener('click', async () => {
        const btn = document.getElementById('btn-run');
        btn.textContent = "Running Pipeline...";
        btn.disabled = true;

        try {
            const res = await fetch('/api/run', { method: 'POST' });
            if (!res.ok) throw new Error('Pipeline failed');
            alert('Pipeline complete!');
            loadAlerts();
        } catch (e) {
            alert('Error running pipeline');
        }

        btn.textContent = "2. Run Pipeline";
        btn.disabled = false;
    });

    document.getElementById('btn-refresh-alerts').addEventListener('click', loadAlerts);
});

async function loadAlerts() {
    try {
        const res = await fetch('/api/alerts');
        if (!res.ok) throw new Error('Unable to fetch alerts');
        const alerts = await res.json();
        renderAlerts(alerts);
        updateKPIs(alerts);
    } catch (e) {
        console.error('Failed to load alerts', e);
    }
}

function updateKPIs(alerts) {
    document.getElementById('kpi-total').textContent = alerts.length;

    let critical = 0;
    let highMed = 0;
    let open = 0;
    let inProgress = 0;
    let resolved = 0;

    alerts.forEach(alert => {
        const severity = alert.event_details?.severity || "Low";
        if (severity === "Critical") critical++;
        if (severity === "High" || severity === "Medium") highMed++;

        if (alert.status === "RESOLVED") resolved++;
        else if (alert.status === "IN_PROGRESS") inProgress++;
        else open++;
    });

    document.getElementById('kpi-critical').textContent = critical;
    document.getElementById('kpi-high-med').textContent = highMed;
    document.getElementById('kpi-open').textContent = open;
    document.getElementById('kpi-progress').textContent = inProgress;
    document.getElementById('kpi-resolved').textContent = resolved;
}

function renderAlerts(alerts) {
    const tbody = document.getElementById('alerts-tbody');
    tbody.innerHTML = '';

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No alerts found. Run the pipeline.</td></tr>';
        return;
    }

    alerts.forEach(alert => {
        const id = alert.id || "N/A";
        const details = alert.event_details || {};
        const severity = details.severity || "Low";
        const ruleName = details.rule_name || "Detection";
        const processName = details.process_name || "Unknown process";
        const tactic = alert.mitre_tactic || "Unknown tactic";
        const status = alert.status || "OPEN";
        const assigned = alert.assigned_to || "";
        const lastNote = alert.notes && alert.notes.length > 0 ? alert.notes[alert.notes.length - 1] : "";

        let badgeClass = "badge-low";
        if (severity === "Critical") badgeClass = "badge-critical";
        else if (severity === "High") badgeClass = "badge-high";
        else if (severity === "Medium") badgeClass = "badge-medium";

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${escapeHtml(id)}</strong></td>
            <td><span class="badge ${badgeClass}">${escapeHtml(severity)}</span></td>
            <td>
                <div class="alert-title">${escapeHtml(ruleName)}</div>
                <div class="alert-meta">${escapeHtml(processName)} | ${escapeHtml(tactic)}</div>
            </td>
            <td>
                <select id="status-${escapeAttribute(id)}" onchange="updateStatus('${escapeAttribute(id)}')">
                    <option value="OPEN" ${status === 'OPEN' ? 'selected' : ''}>OPEN</option>
                    <option value="IN_PROGRESS" ${status === 'IN_PROGRESS' ? 'selected' : ''}>IN PROGRESS</option>
                    <option value="RESOLVED" ${status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
                </select>
            </td>
            <td>
                <div class="action-row">
                    <input type="text" id="assign-${escapeAttribute(id)}" value="${escapeAttribute(assigned)}" placeholder="Analyst Name" style="width: 130px;">
                    <button class="action-btn" onclick="assignAlert('${escapeAttribute(id)}')">Assign</button>
                </div>
            </td>
            <td>
                <div class="action-row">
                    <input type="text" id="note-${escapeAttribute(id)}" placeholder="Add note..." style="width: 180px;">
                    <button class="action-btn" onclick="addNote('${escapeAttribute(id)}')">Save</button>
                </div>
                ${lastNote ? `<div class="last-note">Last note: ${escapeHtml(lastNote)}</div>` : ''}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function assignAlert(id) {
    const analyst = document.getElementById(`assign-${id}`).value.trim();
    if (!analyst) return alert("Enter an analyst name");

    const res = await fetch('/assign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, analyst })
    });

    if (!res.ok) return alert('Unable to assign alert');
    loadAlerts();
}

async function updateStatus(id) {
    const status = document.getElementById(`status-${id}`).value;
    const res = await fetch('/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, status })
    });

    if (!res.ok) {
        alert('Unable to update status');
        loadAlerts();
        return;
    }

    loadAlerts();
}

async function addNote(id) {
    const input = document.getElementById(`note-${id}`);
    const note = input.value.trim();
    if (!note) return;

    const res = await fetch('/note', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, note })
    });

    if (!res.ok) return alert('Unable to add note');
    input.value = '';
    loadAlerts();
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

function escapeAttribute(value) {
    return escapeHtml(value).replace(/`/g, '&#96;');
}
