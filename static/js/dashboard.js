let currentAlerts =[];
let globalIncidents =[];
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
        overlay.style.color = "#ff4757"; overlay.style.borderColor = "#ff4757";
        demoBtn.disabled = true;
    } else {
        label.innerHTML = '<i class="fa-solid fa-vial"></i> SIMULATOR MODE';
        label.className = 'form-check-label text-warning fw-bold';
        overlay.innerText = "SIMULATED TELEMETRY";
        overlay.style.color = "#39c5ff"; overlay.style.borderColor = "#39c5ff";
        demoBtn.disabled = false;
    }

    map.eachLayer((layer) => { if (layer instanceof L.CircleMarker || layer instanceof L.Polyline) { map.removeLayer(layer); } });
    processedAlertIds.clear();

    try { await fetch('/api/toggle_mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: isLive ? 'LIVE' : 'SIMULATED' }) }); } catch (e) { }
});

async function runPlaybook(ip, incId) {
    const term = document.getElementById('soarTerminal'); term.innerHTML = '';
    const steps = [`> Initializing SOAR Playbook for ${incId}`, `> [API] Fetching Firewall Rules...`, `> [ACTION] Pushing drop rule for Attacker IP: ${ip}`, `> [ACTION] Isolating affected host from internal network.`, `> Remediation Complete. Closing Ticket.`];
    for(let i=0; i<steps.length; i++) {
        await new Promise(r => setTimeout(r, 400));
        let div = document.createElement('div'); div.className = 'soar-line'; div.innerText = steps[i];
        if(steps[i].includes('ACTION')) div.style.color = '#39c5ff';
        term.appendChild(div); term.scrollTop = term.scrollHeight;
    }
    try { await fetch(`/api/incident/${ip}/action`, { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({action: "RESOLVE"})}); } catch(e){}
}

function downloadReport(incId) {
    const inc = globalIncidents.find(i => i.id === incId);
    if(!inc) return;
    
    let csv = "Timestamp,Source IP,Target Host,Threat Type,Severity,MITRE Tactic\n";
    inc.events.forEach(e => { csv += `${e.timestamp},${e.ip},${e.host},${e.type},${e.severity},${e.mitre}\n`; });
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.setAttribute('href', url);
    a.setAttribute('download', `Forensics_Report_${incId}.csv`);
    a.click();
}

document.getElementById('demoBtn').addEventListener('click', async function() {
    this.disabled = true; this.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Attacking...';
    try { await fetch('/api/demo_attack'); } catch(e){}
    setTimeout(() => { this.disabled = false; this.innerHTML = '<i class="fa-solid fa-bolt"></i> Launch Simulation'; }, 4000);
});

async function fetchDashboardData() {
    try {
        const res = await fetch('/api/data');
        if (!res.ok) throw new Error("Server returned " + res.status);
        const data = await res.json();
        currentAlerts = data.alerts;
        globalIncidents = data.incidents;
        
        data.alerts.forEach(plotAttackOnMap);
        document.getElementById('postureScore').innerText = data.score;
        document.getElementById('postureScore').className = 'score-circle ' + (data.score < 60 ? 'score-critical' : data.score < 90 ? 'score-warning' : '');
        
        const epContainer = document.getElementById('endpointsContainer'); epContainer.innerHTML = '';
        for (const[host, state] of Object.entries(data.endpoints)) {
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
                                <div class="mt-3 d-flex gap-2">
                                    <button class="btn btn-danger btn-sm flex-fill" onclick="runPlaybook('${inc.ip}', '${inc.id}')"><i class="fa-solid fa-play"></i> Run Playbook</button>
                                    <button class="btn btn-outline-info btn-sm" onclick="downloadReport('${inc.id}')"><i class="fa-solid fa-file-csv"></i> Export CSV</button>
                                </div>
                            </div>
                        </div>
                    </div>`;
            });
        }

        document.querySelectorAll('.mitre-cell').forEach(c => c.classList.remove('mitre-active'));
        data.incidents.forEach(inc => { if(inc.status === 'Active') inc.mitre_ids.forEach(id => { let cell = document.getElementById(id); if(cell) cell.classList.add('mitre-active'); }); });

        const sq = document.getElementById('huntSearch') ? document.getElementById('huntSearch').value.toLowerCase() : "";
        const filt = data.alerts.filter(a => a.ip.toLowerCase().includes(sq) || a.host.toLowerCase().includes(sq) || a.type.toLowerCase().includes(sq));
        document.getElementById('huntTableBody').innerHTML = filt.map((a, i) => {
            const origIdx = data.alerts.indexOf(a);
            return `<tr onclick="showPcap(${origIdx})"><td>${a.timestamp}</td><td class="text-cyan">${a.ip}</td><td>${a.host}</td><td>${a.type}</td><td><span class="sev-${a.severity}">${a.severity}</span></td></tr>`;
        }).join('');

    } catch (e) {} finally { setTimeout(fetchDashboardData, 1500); }
}

async function showPcap(index) {
    const alert = currentAlerts[index];
    document.getElementById('pcapMeta').innerHTML = `<strong>Src:</strong> ${alert.ip} <br><strong>Dst:</strong> ${alert.host} <br><strong>MITRE:</strong> ${alert.mitre} <br><hr><span class="text-cyan">Payload Extraction:</span><br>${alert.raw}`;
    document.getElementById('pcapHex').innerText = alert.pcap;
    document.getElementById('vtContainer').innerHTML = `<i class="fa-solid fa-spinner fa-spin text-cyan"></i> Querying VirusTotal...`;
    
    new bootstrap.Modal(document.getElementById('pcapModal')).show();

    try {
        const res = await fetch(`/api/vt/${alert.ip}`);
        const vt = await res.json();
        
        let vtColor = vt.stats.malicious > 0 ? 'text-danger' : 'text-success';
        let vtIcon = vt.stats.malicious > 0 ? 'fa-skull' : 'fa-shield-check';
        
        document.getElementById('vtContainer').innerHTML = `
            <div class="fs-2 ${vtColor} fw-bold"><i class="fa-solid ${vtIcon}"></i> ${vt.stats.malicious} <span class="fs-6 text-muted">/ ${vt.stats.malicious + vt.stats.harmless + vt.stats.undetected}</span></div>
            <div class="small mt-2"><strong>Network:</strong> ${vt.network}</div>
            <div class="small"><strong>Location:</strong> ${vt.country}</div>
        `;
    } catch(e) {
        document.getElementById('vtContainer').innerHTML = `<span class="text-warning">VirusTotal Unreachable</span>`;
    }
}

if(document.getElementById('huntSearch')) document.getElementById('huntSearch').addEventListener('input', fetchDashboardData);
fetchDashboardData();
