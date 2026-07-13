// ─── State ────────────────────────────────────────────────────────────────────
const S = {
  nessusUrl: '',
  nessusToken: '',
  selectedScanId: null,
  allCves: [],          // full list from extraction
  allIps: [],
  sigIndex: null,       // result from /api/nsx/signatures/index
  nsxConnected: false,
};

// ─── Utilities ────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Load saved Nessus credentials
  const savedNessus = localStorage.getItem('vdefend_nessus_creds');
  if (savedNessus) {
    try {
      const creds = JSON.parse(savedNessus);
      document.getElementById('nessusUrl').value = creds.url || '';
      document.getElementById('nessusUser').value = creds.user || '';
      document.getElementById('nessusPass').value = creds.pass || '';
      document.getElementById('saveNessusCreds').checked = true;
    } catch(e) {}
  }

  // Load saved NSX credentials
  const savedNsx = localStorage.getItem('vdefend_nsx_creds');
  if (savedNsx) {
    try {
      const creds = JSON.parse(savedNsx);
      document.getElementById('nsxUrl').value = creds.url || '';
      document.getElementById('nsxUser').value = creds.user || '';
      document.getElementById('nsxPass').value = creds.pass || '';
      document.getElementById('saveNsxCreds').checked = true;
    } catch(e) {}
  }

  // Track manual edits on auto-populated name fields so CVE changes don't clobber user input
  ['profileName', 'advRuleName'].forEach(id => {
    const el = document.getElementById(id);
    el.addEventListener('input', () => {
      el.dataset.userEdited = el.value ? '1' : '';
    });
  });
});

function today() {
  return new Date().toISOString().slice(0, 10);
}

function runId() {
  return new Date().toISOString().replace(/[-:T]/g, '').slice(0, 15);
}

function profileName(cves) {
  const PREFIX = '';
  const MAX = 255;
  const full = PREFIX + cves.join('-');
  if (full.length <= MAX) return full;

  // Keep as many CVEs as fit, with '...' in the middle
  let front = [cves[0]];
  let back  = cves.length > 1 ? [cves[cves.length - 1]] : [];
  let lo = 1, hi = cves.length - 2;

  const build = (f, b) =>
    PREFIX + (b.length ? f.join('-') + '...' + b.join('-') : f.join('-'));

  while (lo <= hi) {
    if (build([...front, cves[lo]], back).length <= MAX)       { front.push(cves[lo++]); continue; }
    if (build(front, [cves[hi], ...back]).length <= MAX)       { back.unshift(cves[hi--]); continue; }
    break;
  }

  return build(front, back);
}

function showToast(msg, type = 'danger') {
  const el = document.getElementById('toast');
  el.className = `toast align-items-center border-0 text-bg-${type}`;
  document.getElementById('toastBody').textContent = msg;
  bootstrap.Toast.getOrCreateInstance(el, { delay: 4000 }).show();
}

function setStatus(id, msg, type = '') {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = 'status-text ' + type;
}

function setBtn(id, loading, label) {
  const btn = document.getElementById(id);
  btn.disabled = loading;
  btn.innerHTML = loading
    ? `<span class="spinner-border spinner-border-sm me-1"></span>${label}`
    : label;
}

function goToStep(n) {
  document.querySelectorAll('.wizard-step').forEach(el => el.classList.add('d-none'));
  document.getElementById(`step${n}`).classList.remove('d-none');

  document.querySelectorAll('.step').forEach(el => {
    const s = parseInt(el.dataset.step);
    el.classList.remove('active', 'completed');
    if (s < n) el.classList.add('completed');
    else if (s === n) el.classList.add('active');
  });

  // colour the connector lines
  document.querySelectorAll('.step-line').forEach((line, i) => {
    line.classList.toggle('completed', i < n - 1);
  });

  // update completed step circles to checkmarks
  document.querySelectorAll('.step.completed .step-circle').forEach(c => {
    if (!c.innerHTML.includes('bi-check')) {
      c.innerHTML = '<i class="bi bi-check-lg"></i>';
    }
  });
}

async function apiPost(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.detail || JSON.stringify(data));
  return data;
}

async function apiGet(path, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const r = await fetch(qs ? `${path}?${qs}` : path);
  const data = await r.json();
  if (!r.ok) throw new Error(data.detail || JSON.stringify(data));
  return data;
}

// ─── Severity helpers ─────────────────────────────────────────────────────────

function sevClass(sev) {
  const map = { Critical: 'sev-critical', High: 'sev-high', Medium: 'sev-medium', Low: 'sev-low' };
  return map[sev] || 'sev-info';
}

function sevOrder(sev) {
  return { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }[sev] || 0;
}

// ─── Step 1: Nessus connect ───────────────────────────────────────────────────

async function nessusConnect() {
  const url  = document.getElementById('nessusUrl').value.trim();
  const user = document.getElementById('nessusUser').value.trim();
  const pass = document.getElementById('nessusPass').value;

  if (!url || !user || !pass) { showToast('Please fill in all Nessus fields.'); return; }

  setBtn('btnNessusConnect', true, 'Connecting…');
  setStatus('nessusStatus', '', '');

  try {
    const res = await apiPost('/api/nessus/connect', { url, username: user, password: pass });
    S.nessusUrl   = url;
    S.nessusToken = res.token;
    setStatus('nessusStatus', '✓ Connected', 'success');
    setBtn('btnNessusConnect', false, '<i class="bi bi-plug me-1"></i>Connect &amp; Load Scans');

    if (document.getElementById('saveNessusCreds').checked) {
      localStorage.setItem('vdefend_nessus_creds', JSON.stringify({ url, user, pass }));
    } else {
      localStorage.removeItem('vdefend_nessus_creds');
    }

    await loadScans();
    goToStep(2);
  } catch (e) {
    setStatus('nessusStatus', '✗ ' + e.message, 'error');
    setBtn('btnNessusConnect', false, '<i class="bi bi-plug me-1"></i>Connect &amp; Load Scans');
    showToast(e.message);
  }
}

// ─── Step 2: Load & select scan ───────────────────────────────────────────────

async function loadScans() {
  const data = await apiGet('/api/nessus/scans', { nessus_url: S.nessusUrl, token: S.nessusToken });
  const list = document.getElementById('scanList');
  list.innerHTML = '';

  const scans = (data.scans || []).filter(s => s.status === 'completed');
  if (!scans.length) {
    list.innerHTML = '<div class="col-12 text-muted">No completed scans found. Run a scan in Nessus first.</div>';
    return;
  }

  scans.forEach(scan => {
    const date = scan.creation_date
      ? new Date(scan.creation_date * 1000).toLocaleDateString()
      : 'Unknown date';
    const col = document.createElement('div');
    col.className = 'col-md-4';
    col.innerHTML = `
      <div class="scan-card" onclick="selectScan(${scan.id}, this)">
        <div class="scan-name"><i class="bi bi-clipboard2-pulse me-1"></i>${escHtml(scan.name)}</div>
        <div class="scan-meta">${date} &bull; ${scan.host_count} host${scan.host_count !== 1 ? 's' : ''}</div>
        <div class="scan-meta mt-1">
          <span class="badge bg-secondary">${scan.status}</span>
        </div>
      </div>`;
    list.appendChild(col);
  });
}

function selectScan(id, el) {
  S.selectedScanId = id;
  document.querySelectorAll('.scan-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
  document.getElementById('btnExtract').disabled = false;
}

async function extractCves() {
  if (!S.selectedScanId) return;
  setBtn('btnExtract', true, 'Extracting vulnerabilities…');
  setStatus('extractStatus', 'This may take a minute for large scans…', '');

  try {
    const res = await apiPost('/api/nessus/extract', {
      nessus_url: S.nessusUrl,
      token: S.nessusToken,
      scan_id: S.selectedScanId,
    });

    S.allCves = res.cves || [];
    S.allIps  = res.all_ips || [];

    setStatus('extractStatus',
      `✓ Found ${res.total_cves} CVEs across ${res.total_hosts} host${res.total_hosts !== 1 ? 's' : ''}`,
      'success');
    setBtn('btnExtract', false, '<i class="bi bi-cpu me-1"></i>Extract Vulnerabilities');
    renderCveTable();
    goToStep(3);
  } catch (e) {
    setStatus('extractStatus', '✗ ' + e.message, 'error');
    setBtn('btnExtract', false, '<i class="bi bi-cpu me-1"></i>Extract Vulnerabilities');
    showToast(e.message);
  }
}

// ─── Step 3: CVE selection table ──────────────────────────────────────────────

function renderCveTable(coverageMap = null) {
  const tbody = document.getElementById('cveTableBody');
  tbody.innerHTML = '';

  S.allCves.forEach(cve => {
    const hasCoverage = coverageMap
      ? (coverageMap[cve.cve_id] && coverageMap[cve.cve_id].length > 0)
      : null;

    const sigCount = coverageMap
      ? (coverageMap[cve.cve_id] ? coverageMap[cve.cve_id].length : 0)
      : null;

    const noCov = hasCoverage === false;

    const cvss = cve.cvss != null ? cve.cvss.toFixed(1) : '—';
    const hosts = (cve.affected_hosts || []).join(', ') || '—';
    const desc  = (cve.description || '').slice(0, 100) + (cve.description?.length > 100 ? '…' : '');

    let coverageCell;
    if (coverageMap === null) {
      coverageCell = '<span class="text-muted small">—</span>';
    } else if (hasCoverage) {
      coverageCell = `<span class="badge bg-success coverage-badge"><i class="bi bi-shield-check me-1"></i>${sigCount} sig${sigCount !== 1 ? 's' : ''}</span>`;
    } else {
      coverageCell = '<span class="badge bg-secondary coverage-badge">No coverage</span>';
    }

    const tr = document.createElement('tr');
    if (noCov) tr.classList.add('no-coverage');
    tr.innerHTML = `
      <td><input type="checkbox" class="form-check-input cve-chk" data-cve="${escHtml(cve.cve_id)}" ${noCov ? 'disabled' : 'checked'} onchange="updateSelCount()" /></td>
      <td><span class="cve-id">${escHtml(cve.cve_id)}</span></td>
      <td><span class="badge-sev ${sevClass(cve.severity)}">${escHtml(cve.severity)}</span></td>
      <td>${cvss}</td>
      <td><small>${escHtml(hosts)}</small></td>
      <td>${coverageCell}</td>
      <td class="text-muted small">${escHtml(desc)}</td>`;
    tbody.appendChild(tr);
  });

  updateSelCount();
}

function updateSelCount() {
  const cves = getSelectedCves();
  document.getElementById('cveSelectionBadge').textContent = `${cves.length} selected`;
  const name = cves.length ? profileName(cves) : '';
  const profEl = document.getElementById('profileName');
  const ruleEl = document.getElementById('advRuleName');
  if (!profEl.dataset.userEdited) profEl.value = name;
  if (!ruleEl.dataset.userEdited) ruleEl.value = name;
}

function selectAll() {
  document.querySelectorAll('.cve-chk:not(:disabled)').forEach(c => c.checked = true);
  updateSelCount();
}

function clearAll() {
  document.querySelectorAll('.cve-chk:not(:disabled)').forEach(c => c.checked = false);
  updateSelCount();
}

function selectBySeverity(minSev) {
  clearAll();
  const order = sevOrder(minSev);
  S.allCves.forEach(cve => {
    if (sevOrder(cve.severity) >= order) {
      const chk = document.querySelector(`.cve-chk[data-cve="${CSS.escape(cve.cve_id)}"]`);
      if (chk && !chk.disabled) chk.checked = true;
    }
  });
  updateSelCount();
}

function toggleAll(masterChk) {
  document.querySelectorAll('.cve-chk:not(:disabled)').forEach(c => c.checked = masterChk.checked);
  updateSelCount();
}

function getSelectedCves() {
  return Array.from(document.querySelectorAll('.cve-chk:checked:not(:disabled)')).map(c => c.dataset.cve);
}

function goToStep4() {
  const selected = getSelectedCves();
  if (!selected.length) { showToast('Please select at least one CVE to patch.'); return; }
  goToStep(4);
}

// ─── Step 4: NSX connect + index ──────────────────────────────────────────────

async function nsxConnectAndIndex() {
  const url  = document.getElementById('nsxUrl').value.trim();
  const user = document.getElementById('nsxUser').value.trim();
  const pass = document.getElementById('nsxPass').value;

  if (!url || !user || !pass) { showToast('Please fill in all NSX fields.'); return; }

  setBtn('btnNsxConnect', true, 'Connecting…');
  setStatus('nsxStatus', '', '');
  document.getElementById('indexProgress').classList.add('d-none');
  document.getElementById('coverageSummary').classList.add('d-none');
  document.getElementById('btnDeploy').disabled = true;

  try {
    // 1. Test connection
    const connRes = await apiPost('/api/nsx/connect', { url, username: user, password: pass });
    if (connRes.version) {
      document.getElementById('nsxVersionBadge').textContent =
        `NSX ${connRes.version}${connRes.exclusion_mode ? ' · exclusion mode' : ''} · IDPS`;
    }
    setStatus('nsxStatus', '✓ Connected — indexing signatures…', 'success');
    setBtn('btnNsxConnect', true, 'Indexing signatures…');
    document.getElementById('indexProgress').classList.remove('d-none');

    if (document.getElementById('saveNsxCreds').checked) {
      localStorage.setItem('vdefend_nsx_creds', JSON.stringify({ url, user, pass }));
    } else {
      localStorage.removeItem('vdefend_nsx_creds');
    }

    const selectedCves = getSelectedCves();

    // 2. Index signatures
    const sigRes = await apiPost('/api/nsx/signatures/index', {
      nsx_url: url,
      username: user,
      password: pass,
      cve_list: selectedCves,
    });

    S.sigIndex = sigRes;
    document.getElementById('indexProgress').classList.add('d-none');

    // Update CVE table with coverage data
    renderCveTable(sigRes.matched_cves);

    // Update hint in step 3
    document.getElementById('coverageHint').textContent =
      `${sigRes.coverage_count} of ${sigRes.total_cves_requested} CVEs have IDPS coverage`;

    // Show coverage summary cards
    showCoverageSummary(sigRes);

    setStatus('nsxStatus',
      `✓ ${sigRes.total_signatures.toLocaleString()} signatures indexed`,
      'success');
    setBtn('btnNsxConnect', false, '<i class="bi bi-plug me-1"></i>Connect &amp; Index Signatures');
    document.getElementById('btnDeploy').disabled = false;

  } catch (e) {
    document.getElementById('indexProgress').classList.add('d-none');
    setStatus('nsxStatus', '✗ ' + e.message, 'error');
    setBtn('btnNsxConnect', false, '<i class="bi bi-plug me-1"></i>Connect &amp; Index Signatures');
    showToast(e.message);
  }
}

function showCoverageSummary(sigRes) {
  const wrap = document.getElementById('coverageCards');
  const gapCount = sigRes.total_cves_requested - sigRes.coverage_count;
  wrap.innerHTML = `
    <div class="col-6 col-md-3">
      <div class="cov-card">
        <div class="cov-num text-primary">${sigRes.total_signatures.toLocaleString()}</div>
        <div class="cov-label">Signatures Indexed</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="cov-card">
        <div class="cov-num text-success">${sigRes.coverage_count}</div>
        <div class="cov-label">CVEs Covered</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="cov-card">
        <div class="cov-num text-primary">${sigRes.total_signatures_matched}</div>
        <div class="cov-label">Signatures Matched</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="cov-card">
        <div class="cov-num ${gapCount > 0 ? 'text-warning' : 'text-success'}">${gapCount}</div>
        <div class="cov-label">Coverage Gaps</div>
      </div>
    </div>`;
  document.getElementById('coverageSummary').classList.remove('d-none');
}

// ─── Step 5: Deploy ───────────────────────────────────────────────────────────

async function deploy() {
  const url     = document.getElementById('nsxUrl').value.trim();
  const user    = document.getElementById('nsxUser').value.trim();
  const pass    = document.getElementById('nsxPass').value;
  
  // Advanced Config
  const action   = document.getElementById('actionMode').value;
  const category = document.getElementById('advCategory').value;
  const polN     = document.getElementById('advPolicyName').value.trim() || 'Virtual Patches';
  const ruleN    = document.getElementById('advRuleName').value.trim() || `VirtualPatch-Rule-${today()}`;
  const protocol = document.getElementById('advProtocol').value;
  const port     = document.getElementById('advPort').value.trim();

  const selectedCves = getSelectedCves();
  if (!selectedCves.length) { showToast('No CVEs selected.'); return; }

  const profN = document.getElementById('profileName').value.trim() || profileName(selectedCves);

  goToStep(5);
  const logEl = document.getElementById('deployLog');
  logEl.innerHTML = '';

  function log(msg, type = 'info') {
    const line = document.createElement('div');
    line.className = `log-line ${type}`;
    line.innerHTML = `<i class="bi ${type === 'ok' ? 'bi-check-circle-fill' : type === 'err' ? 'bi-x-circle-fill' : 'bi-arrow-right-circle'}"></i> ${escHtml(msg)}`;
    logEl.appendChild(line);
  }

  log(`Starting deployment — run ID: ${runId()}`);
  log(`Selected ${selectedCves.length} CVEs · ${S.allIps.length} target hosts`);
  log(`Action mode: ${action}`);

  try {
    const rid = runId();
    log('Looking up VMs and applying Vulnerability tags…');
    log('Creating tag-based dynamic group for target VMs…');
    log('Building IDPS profile with matched signatures…');
    log('Pushing distributed IDPS policy rule…');

    const res = await apiPost('/api/deploy', {
      nsx_url: url,
      username: user,
      password: pass,
      cve_list: selectedCves,
      host_ips: S.allIps,
      action: action,
      profile_name: profN,
      policy_name: polN,
      category: category,
      rule_name: ruleN,
      run_id: rid,
      ...(port ? { protocol: protocol || 'TCP', port } : {}),
    });

    if (res.tagged?.length)     log(`Tagged ${res.tagged.length} VM(s): ${res.tagged.join(', ')}`, 'ok');
    if (res.not_found?.length)  log(`VM not found in NSX for: ${res.not_found.join(', ')}`, 'warn');
    log(`Dynamic group created: ${res.group_name}`, 'ok');
    log(`IDPS profile created: ${res.profile_id} (${res.signatures_applied} signatures)`, 'ok');
    log(`Distributed policy rule created: ${res.rule_id} in ${res.policy_id}`, 'ok');
    log('Virtual patch deployed successfully!', 'ok');

    renderResult(res, action, selectedCves.length);
  } catch (e) {
    log('Deployment failed: ' + e.message, 'err');
    showToast('Deployment failed: ' + e.message);
  }
}

function renderResult(res, action, cveCount) {
  const wrap = document.getElementById('resultSummary');
  const stats = [
    { label: 'Policy Category',     value: res.category_used || document.getElementById('advCategory').value, color: '#0070d1' },
    { label: 'Policy',              value: res.policy_id,              color: '#0070d1' },
    { label: 'Rule',                value: res.rule_id,                color: '#0070d1' },
    { label: 'Group (Tag-based)',   value: res.group_name,             color: '#0070d1' },
    { label: 'Profile',             value: res.profile_id,             color: '#0070d1' },
    { label: 'Signatures Applied',  value: res.signatures_applied,     color: '#198754' },
    { label: 'CVEs Covered',        value: res.cves_covered,           color: '#198754' },
    { label: 'Hosts Protected',     value: res.hosts_protected,        color: '#198754' },
    { label: 'Action Mode',         value: action,                     color: action.includes('DETECT') ? '#ffc107' : '#dc3545' },
  ];
  wrap.innerHTML = stats.map(s => `
    <div class="col-sm-6 col-md-4">
      <div class="result-stat" style="border-left-color:${s.color}">
        <div class="stat-label">${escHtml(s.label)}</div>
        <div class="stat-value">${escHtml(String(s.value))}</div>
      </div>
    </div>
  `).join('');
}

function copyResult() {
  const stats = document.querySelectorAll('.result-stat');
  const lines = Array.from(stats).map(s => {
    const lbl = s.querySelector('.stat-label').textContent;
    const val = s.querySelector('.stat-value').textContent;
    return `${lbl}: ${val}`;
  });
  navigator.clipboard.writeText(lines.join('\n')).then(() => showToast('Copied!', 'success'));
}

function resetWizard() {
  S.nessusToken  = '';
  S.selectedScanId = null;
  S.allCves      = [];
  S.allIps       = [];
  S.sigIndex     = null;
  S.nsxConnected = false;
  document.getElementById('cveTableBody').innerHTML = '';
  document.getElementById('deployLog').innerHTML    = '';
  document.getElementById('resultSummary').innerHTML = '';
  document.getElementById('scanList').innerHTML     = '';
  document.getElementById('nessusStatus').textContent = '';
  document.getElementById('nsxStatus').textContent    = '';
  document.querySelectorAll('.step .step-circle').forEach((c, i) => {
    c.innerHTML = (i === 4) ? '<i class="bi bi-shield-check"></i>' : (i + 1);
  });
  goToStep(1);
}

// ─── Escape helper ────────────────────────────────────────────────────────────
function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
