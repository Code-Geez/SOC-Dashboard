let currentAlerts =[];
let map;
let processedAlertIds = new Set();
const DC_LATLNG = [38.8951, -77.0364]; 

function initMap() {
    map = L.map('attackMap', { zoomControl: false, attributionControl: false }).setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);
    document.querySelector('a[href="#execTab"]').addEventListener('shown.bs.tab', function() { map.invalidateSize(); });
}
initMap();

function plotAttackOnMap(alert) {
    if(processedAlertIds.has(alert.id)) return;
    processedAlertIds.add(alert.id);
    if(alert.geo.lat !== 0) {
        let color = alert.severity === 'CRITICAL' ? '#ff4757' : '#ffa502';
        L.circleMarker([alert.geo.lat, alert.geo.lng], { radius: 5, color: color, fillOpacity: 1 }).addTo(map).bindPopup(alert.ip);
        let line = L.polyline([[alert.geo.lat, alert.geo.lng], DC_LATLNG], { color: color, weight: 2, dashArray: '5, 5' }).addTo(map);
        setTimeout(() => { map.removeLayer(line); }, 4000);
    }
}

document.getElementById('liveModeToggle').addEventListener('change', async function() {
    const isLive = this.checked;
    const label = document.getElementById('liveModeLabel');
    const overlay = document.getElementById('mapStatusOverlay');
    const demoBtn = document.getElementById('demoBtn');

    if(isLive) {
        label.innerHTML = '<i class="fa-solid fa-biohazard"></i> LIVE KALI OS MODE';
        label.className = 'form-check-label text-danger fw-bold blink';
        overlay.innerText = "WARNING: LIVE KALI TELEMETRY ACTIVE";
        overlay.style.color = "#ff4757";
        overlay.style.borderColor = "#ff4757";
        demoBtn.disabled = true;
    } else {
        label.innerHTML = '<i class="fa-solid fa-vial"></i> SIMULATOR MODE';
        label.className = 'form-check-label text-warning fw-bold';
        overlay.innerText = "SIMULATED TELEMETRY";
        overlay.style.color = "#39c5ff";
        overlay.style.borderColor = "#39c5ff";
        demoBtn.disabled = false;
    }

    map.eachLayer((layer) => { if (layer instanceof L.CircleMarker || layer instanceof L.Polyline) { map.removeLayer(layer); } });
    processedAlertIds.clear();

    await fetch('/api/toggle_mode', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: isLive ? 'LIVE' : 'SIMULATED' })
    });
    fetchDashboardData();
});

async function runPlaybook(ip, incId) {
    const term = document.getElementById('soarTerminal');
    term.innerHTML = '';
    const steps =[`> Initializing SOAR Playbook for ${incId}`, `> [ACTION] Pushing block rule for Attacker IP: ${ip}`, `> Isolating affected host...`, `> Remediation Complete.`];
    for(let i=0; i<steps.length; i++) {
        await new Promise(r => setTimeout(r, 500));
        let div = document.createElement('div'); div.className = 'soar-line'; div.innerText = steps[i];
        if(steps[i].includes('ACTION')) div.style.color = '#39c5ff';
        term.appendChild(div);
        term.scrollTop = term.scrollHeight;
    }
    await fetch(`/api/incident/${ip}/action`, { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({action: "RESOLVE"})});
    fetchDashboardData();
}

document.getElementById('demoBtn').addEventListener('click', async function() {
    this.disabled = true; this.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Attacking...';
    await fetch('/api/demo_attack');
    setTimeout(() => { this.disabled = false; this.innerHTML = '<i class="fa-solid fa-bolt"></i> Launch Simulation'; }, 4000);
});

async function fetchDashboardData() {
    try {
        const res = await fetch('/api/data');
        const data = await res.json();
        currentAlerts = data.alerts;
        
        data.alerts.forEach(plotAttackOnMap);
        document.getElementById('postureScore').innerText = data.score;
        document.getElementById('postureScore').className = 'score-circle ' + (data.score < 60 ? 'score-critical' : data.score < 90 ? 'score-warning' : '');
        
        const epContainer = document.getElementById('endpointsContainer');
        epContainer.innerHTML = '';
        for (const [host, state] of Object.entries(data.endpoints)) {
            if(data.mode === "SIMULATED" && host === "KALI-LOCAL") continue;
            let cls = state === "Clean" ? "ep-clean" : "ep-comp text-danger";
            epContainer.innerHTML += `<div class="col-4"><div class="endpoint-card ${cls}"><small>${host}</small></div></div>`;
        }

        const acc = document.getElementById('incidentAccordion');
        if(!acc.querySelector('.show')) {
            acc.innerHTML = data.incidents.length === 0 ? `<div class="p-3 text-muted">No active incidents.</div>` : '';
            data.incidents.forEach(inc => {
                let badge = inc.severity === 'CRITICAL' ? '<span class="sev-CRITICAL blink">CRITICAL</span>' : `<span class="badge bg-warning">${inc.severity}</span>`;
                acc.innerHTML += `
                    <div class="accordion-item mb-2 border border-secondary rounded">
                        <h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#col${inc.id}"><strong>${inc.id}</strong>&nbsp;| Threat: ${inc.type} |&nbsp;${badge}</button></h2>
                        <div id="col${inc.id}" class="accordion-collapse collapse" data-bs-parent="#incidentAccordion">
                            <div class="accordion-body">
                                <div><strong>Target:</strong> ${inc.target}</div>
                                <button class="btn btn-danger btn-sm mt-2 w-100" onclick="runPlaybook('${inc.ip}', '${inc.id}')"><i class="fa-solid fa-play"></i> Execute Automated Playbook</button>
                            </div>
                        </div>
                    </div>`;
            });
        }

        document.querySelectorAll('.mitre-cell').forEach(c => c.classList.remove('mitre-active'));
        data.incidents.forEach(inc => { if(inc.status === 'Active') inc.mitre_ids.forEach(id => { let cell = document.getElementById(id); if(cell) cell.classList.add('mitre-active'); }); });

        document.getElementById('huntTableBody').innerHTML = data.alerts.map((a, i) => `
            <tr onclick="showPcap(${i})"><td>${a.timestamp}</td><td class="text-cyan">${a.ip}</td><td>${a.host}</td><td>${a.type}</td><td><span class="sev-${a.severity}">${a.severity}</span></td></tr>
        `).join('');

    } catch (e) { console.error(e); }
}

function showPcap(index) {
    const alert = currentAlerts[index];
    document.getElementById('pcapMeta').innerHTML = `<strong>Src:</strong> ${alert.ip} <br><strong>Dst:</strong> ${alert.host} <br><strong>MITRE:</strong> ${alert.mitre} <br><hr><span class="text-cyan">Payload Extraction:</span><br>${alert.raw}`;
    document.getElementById('pcapHex').innerText = alert.pcap;
    new bootstrap.Modal(document.getElementById('pcapModal')).show();
}

setInterval(fetchDashboardData, 1500);
fetchDashboardData();
