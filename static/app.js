// ─── State ────────────────────────────────────────────────────────────────────
const S = {
  nessusUrl: '',
  nessusToken: '',
  selectedScanId: null,
  allCves: [],          // full list from extraction
  allIps: [],
  allHosts: {},         // ip → display name
  sigIndex: null,       // result from /api/nsx/signatures/index
  nsxConnected: false,
  sspUrl: '',
  sspUser: '',
  sspPass: '',
  sspConnected: false,
  portSuggestions: [],  // [{ip, ports:[{dstPort,protocol,appId,fqdn,flow_count}]}]
  appIdIndex: {},       // {appId: human_label} from NSX DPI registry
  sspViewMode: 'ports', // 'ports' | 'vms'
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

  // Load saved SSP credentials
  const savedSsp = localStorage.getItem('vdefend_ssp_creds');
  if (savedSsp) {
    try {
      const creds = JSON.parse(savedSsp);
      document.getElementById('sspUrl').value  = creds.url  || '';
      document.getElementById('sspUser').value = creds.user || '';
      document.getElementById('sspPass').value = creds.pass || '';
      document.getElementById('saveSspCreds').checked = true;
      // Show "Connect NSX + SSP" combo button when SSP creds are saved
      document.getElementById('btnNsxSspConnect').style.display = '';
    } catch(e) {}
  }

  // Rotate chevron on SSP card expand/collapse
  document.getElementById('sspCardBody').addEventListener('show.bs.collapse',  () => {
    document.getElementById('sspChevron').style.transform = 'rotate(180deg)';
  });
  document.getElementById('sspCardBody').addEventListener('hide.bs.collapse', () => {
    document.getElementById('sspChevron').style.transform = '';
  });

  // Live-sync global Protocol/Port into per-host rows that haven't been manually edited
  document.getElementById('advProtocol').addEventListener('change', _syncGlobalPorts);
  document.getElementById('advPort').addEventListener('input', _syncGlobalPorts);
});

function today() {
  return new Date().toISOString().slice(0, 10);
}

function runId() {
  return new Date().toISOString().replace(/[-:T]/g, '').slice(0, 15);
}

function profileName(cves) {
  const MAX = 255;

  // Compact form: when all CVEs share the same YYYY, abbreviate repeated prefixes.
  // e.g. CVE-2026-109618 + CVE-2026-109619 → "CVE-2026-109618-19"
  const parsed = cves.map(c => {
    const m = String(c).match(/^CVE-(\d{4})-(\d+)$/i);
    return m ? { year: m[1], num: m[2] } : null;
  });
  if (parsed.every(Boolean) && new Set(parsed.map(p => p.year)).size === 1) {
    const year = parsed[0].year;
    const nums = parsed.map(p => p.num);
    // Find longest common prefix across all numeric parts
    let lcp = 0;
    while (lcp < nums[0].length && nums.every(n => n[lcp] === nums[0][lcp])) lcp++;
    // Build: first CVE full, subsequent as last max(len-lcp, 2) digits
    const parts = nums.map((n, i) => {
      if (i === 0) return `CVE-${year}-${n}`;
      return n.slice(-Math.max(n.length - lcp, 2));
    });
    const compact = parts.join('-');
    if (compact.length <= MAX) return compact;
  }

  // Fallback: join all CVEs; if too long, keep as many as fit with '…' in the middle
  const full = cves.join('-');
  if (full.length <= MAX) return full;

  let front = [cves[0]];
  let back  = cves.length > 1 ? [cves[cves.length - 1]] : [];
  let lo = 1, hi = cves.length - 2;
  const build = (f, b) => b.length ? f.join('-') + '...' + b.join('-') : f.join('-');
  while (lo <= hi) {
    if (build([...front, cves[lo]], back).length <= MAX)  { front.push(cves[lo++]); continue; }
    if (build(front, [cves[hi], ...back]).length <= MAX)  { back.unshift(cves[hi--]); continue; }
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
    S.allHosts = {};
    (res.all_hosts || res.hosts || []).forEach(h => {
      const ip   = h.ip || h.hostname || '';
      const name = h.name || ip;
      if (ip) S.allHosts[ip] = name;
    });

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
  renderHostPortTable();
}

function renderHostPortTable() {
  const section = document.getElementById('hostPortOverridesSection');
  if (!S.allIps || !S.allIps.length) { section.classList.add('d-none'); return; }
  _populateHostPortRows();
  section.classList.remove('d-none');
  // If SSP was already connected before hosts were known (joint button flow), the
  // initial loadPortActivity() ran with an empty host_ips list and returned nothing.
  // Reload now that S.allIps is populated so picker buttons light up correctly.
  if (S.sspConnected && S.portSuggestions.length === 0) loadPortActivity();
}

function _populateHostPortRows() {
  const proto   = document.getElementById('advProtocol').value;
  const portVal = document.getElementById('advPort').value.trim();
  const tbody   = document.getElementById('hostPortTableBody');
  tbody.innerHTML = '';
  S.allIps.forEach(ip => {
    const name = S.allHosts[ip];
    const nameHtml = name && name !== ip
      ? `<span class="fw-medium">${escHtml(name)}</span><br><small class="text-muted font-monospace">${escHtml(ip)}</small>`
      : `<code class="small">${escHtml(ip)}</code>`;
    const tr = document.createElement('tr');
    tr.dataset.ip = ip;
    tr.dataset.userEdited = '';
    tr.innerHTML = `
      <td>${nameHtml}</td>
      <td style="width:36px">
        <button class="btn btn-sm btn-outline-secondary py-0 px-1 host-clear-btn"
                title="Clear override — reset to global"
                onclick="clearHostOverride(this.closest('tr'))">
          <i class="bi bi-x"></i>
        </button>
      </td>
      <td>
        <select class="form-select form-select-sm host-proto"
                onchange="this.closest('tr').dataset.userEdited='1'; this.closest('tr').classList.add('table-warning')">
          <option value=""    ${!proto             ? 'selected' : ''}>Any</option>
          <option value="TCP" ${proto === 'TCP'    ? 'selected' : ''}>TCP</option>
          <option value="UDP" ${proto === 'UDP'    ? 'selected' : ''}>UDP</option>
        </select>
      </td>
      <td>
        <input type="text" class="form-control form-control-sm host-port"
               value="${escHtml(portVal)}" placeholder="any (e.g. 80 or 80,443)"
               oninput="this.closest('tr').dataset.userEdited='1'; this.closest('tr').classList.add('table-warning')">
      </td>
      <td>
        <button class="btn btn-sm btn-outline-secondary py-0 px-1 host-picker-btn"
                title="Pick from observed flows"
                onclick="openPortPicker('${escHtml(ip)}')">
          <i class="bi bi-graph-up-arrow"></i>
        </button>
      </td>`;
    tbody.appendChild(tr);
  });
  _refreshPickerButtons();
}

function _syncGlobalPorts() {
  const proto   = document.getElementById('advProtocol').value;
  const portVal = document.getElementById('advPort').value.trim();
  document.querySelectorAll('#hostPortTableBody tr').forEach(tr => {
    if (tr.dataset.userEdited) return;
    const sel = tr.querySelector('.host-proto');
    const inp = tr.querySelector('.host-port');
    if (sel) sel.value = proto;
    if (inp) inp.value = portVal;
  });
}

function resetHostPorts() {
  document.querySelectorAll('#hostPortTableBody tr').forEach(tr => {
    tr.dataset.userEdited = '';
    tr.classList.remove('table-warning');
  });
  _populateHostPortRows();
}

function clearHostOverride(tr) {
  tr.dataset.userEdited = '';
  tr.classList.remove('table-warning');
  const proto = document.getElementById('advProtocol').value;
  const portVal = document.getElementById('advPort').value.trim();
  const sel = tr.querySelector('.host-proto');
  const inp = tr.querySelector('.host-port');
  if (sel) sel.value = proto;
  if (inp) inp.value = portVal;
}

// Update picker button appearance once SSP flow data is available
function _refreshPickerButtons() {
  const ips = new Set(S.portSuggestions.filter(r => r.ports?.length).map(r => r.ip));
  document.querySelectorAll('#hostPortTableBody tr').forEach(tr => {
    const btn = tr.querySelector('.host-picker-btn');
    if (!btn) return;
    btn.disabled = false; // always clickable — modal shows appropriate state
    if (ips.has(tr.dataset.ip)) {
      btn.classList.replace('btn-outline-secondary', 'btn-outline-info');
      btn.title = 'Pick from observed flows';
    }
  });
}

function openPortPicker(ip) {
  const result = S.portSuggestions.find(r => r.ip === ip);
  const name   = S.allHosts[ip] || ip;
  const modal  = document.getElementById('portPickerModal');
  const body   = document.getElementById('portPickerModalBody');
  document.getElementById('portPickerModalLabel').textContent =
    `${name}${name !== ip ? ' · ' + ip : ''}`;

  if (!result || !result.ports?.length) {
    const hint = S.sspConnected ? '' : ' — connect to SSP first';
    body.innerHTML = `<p class="text-muted small mb-0 fst-italic">No flow data for this host yet${escHtml(hint)}.</p>`;
  } else {
    const ports = _aggregatePorts(result.ports);
    body.innerHTML = `
      <table class="table table-sm table-hover mb-0">
        <thead class="table-light">
          <tr>
            <th class="small fw-normal text-muted">Proto</th>
            <th class="small fw-normal text-muted">Port</th>
            <th class="small fw-normal text-muted">App</th>
            <th class="small fw-normal text-muted text-end">Flows</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${ports.map(row => `
          <tr>
            <td class="font-monospace small">${escHtml(row.proto)}</td>
            <td class="font-monospace small fw-medium">${escHtml(row.port)}</td>
            <td class="small text-muted">${escHtml(row.app)}</td>
            <td class="small text-muted text-end">${row.count.toLocaleString()}×</td>
            <td class="text-end">
              <button class="btn btn-sm btn-outline-primary py-0 px-2"
                      onclick="applyPortSuggestion('${escHtml(ip)}','${escHtml(row.proto)}','${escHtml(row.port)}');bootstrap.Modal.getInstance(document.getElementById('portPickerModal')).hide()">
                Apply
              </button>
            </td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  }

  bootstrap.Modal.getOrCreateInstance(modal).show();
}

// ─── Short-name derivation from NSX signature names ──────────────────────────

function _deriveShortName(matchedCves) {
  const allNames = [];
  for (const sigs of Object.values(matchedCves || {})) {
    for (const s of (sigs || [])) { if (s.sig_name) allNames.push(s.sig_name); }
  }
  if (!allNames.length) return null;

  // ET WEB_SPECIFIC_APPS: "ET WEB_SPECIFIC_APPS Langflow AI ..." → product name is 4th word
  for (const name of allNames) {
    const m = name.match(/^ET WEB_SPECIFIC_APPS (\S+)/);
    if (m && m[1].length >= 3) return m[1].charAt(0).toUpperCase() + m[1].slice(1);
  }

  // SLR Alert: "SLR Alert - Nacos Authentication Bypass ..." → product name after " - "
  for (const name of allNames) {
    const m = name.match(/^SLR Alert - (\S+)/);
    if (m && m[1].length >= 3) return m[1].charAt(0).toUpperCase() + m[1].slice(1);
  }

  // ET signatures follow "ET EXPLOIT|HUNTING PRODUCT nickname ..." — extract nickname
  for (const name of allNames) {
    const m = name.match(/^ET (?:EXPLOIT|HUNTING|POLICY) \S+ (\S+)/);
    if (m) {
      const tok = m[1];
      // Accept if it looks like a vulnerability nickname: contains digit (php2shell, log4j)
      // or mixed case (SpringShell) — not a plain English word
      if (/\d/.test(tok) || /[a-z][A-Z]/.test(tok)) {
        return tok.charAt(0).toUpperCase() + tok.slice(1);
      }
    }
  }

  // Generic fallback: look for letter+digit+letter tokens (Log4j, php2shell, etc.)
  const SKIP = new Set(['detect','exploit','hunting','policy','nsx','et','php','java',
    'python','http','https','rce','sqli','xss','cve','attempt','attempts','initial',
    'access','inject','injection','code','execution','remote','generic','upload',
    'progress','session','handler','mismatch','request','response']);
  for (const name of allNames) {
    for (const tok of name.split(/[\s\-_(),]+/)) {
      if (tok.length < 4 || SKIP.has(tok.toLowerCase())) continue;
      if (/[a-zA-Z].*\d.*[a-zA-Z]/i.test(tok)) {
        return tok.charAt(0).toUpperCase() + tok.slice(1);
      }
    }
  }
  return null;
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

    // Auto-populate profile/rule name with short nickname if not user-edited
    const shortName = _deriveShortName(sigRes.matched_cves);
    if (shortName) {
      const cveBase = profileName(selectedCves);
      const profEl = document.getElementById('profileName');
      const ruleEl = document.getElementById('advRuleName');
      if (!profEl.dataset.userEdited) {
        profEl.value = shortName;
        profEl.dataset.userEdited = '';
      }
      if (!ruleEl.dataset.userEdited) {
        ruleEl.value = shortName;
        ruleEl.dataset.userEdited = '';
      }
    }

    // Update CVE table with coverage data
    renderCveTable(sigRes.matched_cves);

    // Update hint in step 3
    document.getElementById('coverageHint').textContent =
      `${sigRes.coverage_count} of ${sigRes.total_cves_requested} CVEs have IDPS coverage`;

    // Show coverage summary cards
    showCoverageSummary(sigRes);

    S.nsxConnected = true;
    setStatus('nsxStatus',
      `✓ ${sigRes.unique_signatures ?? sigRes.total_signatures} unique signatures matched`,
      'success');
    setBtn('btnNsxConnect', false, '<i class="bi bi-plug me-1"></i>Connect &amp; Index Signatures');
    document.getElementById('btnDeploy').disabled = false;
    document.getElementById('btnSspConnect').disabled = false;

    // Fetch DPI app ID registry for display in port picker (best-effort, silent on error)
    apiPost('/api/nsx/app-ids', { nsx_url: url, username: user, password: pass })
      .then(r => { if (r.app_ids) S.appIdIndex = r.app_ids; })
      .catch(() => {});

    // Joint button (btnNsxSspConnect) handles SSP connect itself after awaiting this
    // function — no auto-SSP logic here.

  } catch (e) {
    document.getElementById('indexProgress').classList.add('d-none');
    setStatus('nsxStatus', '✗ ' + e.message, 'error');
    setBtn('btnNsxConnect', false, '<i class="bi bi-plug me-1"></i>Connect &amp; Index Signatures');
    showToast(e.message);
  }
}

// Joint "Connect NSX + SSP" handler: awaits NSX fully, then awaits SSP.
async function nsxAndSspConnect() {
  await nsxConnectAndIndex();
  if (!S.nsxConnected) return; // NSX failed — don't attempt SSP
  bootstrap.Collapse.getOrCreateInstance(
    document.getElementById('sspCardBody'), { toggle: false }
  ).show();
  await sspConnect();
}

function showCoverageSummary(sigRes) {
  const wrap = document.getElementById('coverageCards');
  const gapCount = sigRes.total_cves_requested - sigRes.coverage_count;
  wrap.innerHTML = `
    <div class="col-6 col-md-3">
      <div class="cov-card">
        <div class="cov-num text-primary">${sigRes.total_signatures.toLocaleString()}</div>
        <div class="cov-label">NSX DB Matches</div>
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
        <div class="cov-num text-primary">${sigRes.unique_signatures ?? sigRes.total_signatures_matched}</div>
        <div class="cov-label">Unique Sigs Matched</div>
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
  const portRaw  = document.getElementById('advPort').value.trim();
  const ports    = portRaw ? portRaw.split(',').map(p => p.trim()).filter(Boolean) : [];

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

    // Collect per-host port overrides from the table
    const hostPorts = Array.from(
      document.querySelectorAll('#hostPortTableBody tr')
    ).map(tr => ({
      ip:       tr.dataset.ip,
      protocol: tr.querySelector('.host-proto').value,
      port:     tr.querySelector('.host-port').value.trim(),
    }));

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
      host_ports: hostPorts,
      ...(ports.length ? { protocol: protocol || 'TCP', ports } : {}),
    });

    if (res.tagged?.length)     log(`Tagged ${res.tagged.length} VM(s): ${res.tagged.join(', ')}`, 'ok');
    if (res.not_found?.length)  log(`VM not found in NSX for: ${res.not_found.join(', ')}`, 'warn');
    if (res.groups?.length > 1) {
      res.groups.forEach(g => log(`Tag-based group created: ${g.group_name}`, 'ok'));
    } else {
      log(`Tag-based group created: ${res.group_name}`, 'ok');
    }
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
    { label: 'Group(s) (Tag-based)', value: res.groups?.length > 1 ? res.groups.map(g => g.group_name).join(', ') : res.group_name, color: '#0070d1' },
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

// ─── SSP Port Intelligence ────────────────────────────────────────────────────

async function sspConnect() {
  const url  = document.getElementById('sspUrl').value.trim();
  const user = document.getElementById('sspUser').value.trim();
  const pass = document.getElementById('sspPass').value;

  if (!url) { showToast('Please enter the SSP URL.'); return; }

  setBtn('btnSspConnect', true, 'Connecting…');
  setStatus('sspStatus', '', '');

  try {
    const res = await apiPost('/api/ssp/connect', { url, username: user, password: pass });
    if (!res.success) throw new Error(res.error || 'SSP connect failed');

    S.sspConnected = true;
    S.sspUrl  = url;
    S.sspUser = user;
    S.sspPass = pass;

    setStatus('sspStatus', '✓ ' + res.message, 'success');
    setBtn('btnSspConnect', false, '<i class="bi bi-check-circle me-1"></i>Connected');
    document.getElementById('sspQueryRow').classList.remove('d-none');

    if (document.getElementById('saveSspCreds').checked) {
      localStorage.setItem('vdefend_ssp_creds', JSON.stringify({ url, user, pass }));
      document.getElementById('btnNsxSspConnect').style.display = '';
    } else {
      localStorage.removeItem('vdefend_ssp_creds');
      document.getElementById('btnNsxSspConnect').style.display = 'none';
    }

    // Auto-load port activity immediately after connect
    loadPortActivity();
  } catch(e) {
    setStatus('sspStatus', '✗ ' + e.message, 'error');
    setBtn('btnSspConnect', false, '<i class="bi bi-plug me-1"></i>Connect to SSP');
    showToast(e.message);
  }
}

function setTimeRange(btn) {
  document.querySelectorAll('.time-range-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

async function loadPortActivity() {
  const hours = parseInt(document.querySelector('.time-range-btn.active')?.dataset.hours || '24');

  setBtn('btnLoadFlows', true, '<span class="spinner-border spinner-border-sm me-1"></span>Querying SSP…');
  setStatus('sspFlowStatus', 'Connecting via SSPI — may take 30–60 s…', '');
  document.getElementById('portSuggestionsArea').classList.add('d-none');
  document.getElementById('btnApplyAll').classList.add('d-none');

  try {
    const res = await apiPost('/api/ssp/flows', {
      ssp_url:       S.sspUrl,
      username:      S.sspUser,
      password:      S.sspPass,
      host_ips:      S.allIps,
      lookback_hours: hours,
    });

    S.portSuggestions = res.results || [];
    renderPortSuggestions(S.portSuggestions, hours);

    const withData = S.portSuggestions.filter(r => r.ports && r.ports.length).length;
    setStatus('sspFlowStatus',
      `✓ ${withData} of ${S.portSuggestions.length} host(s) have flow data`, 'success');
    if (withData) document.getElementById('btnApplyAll').classList.remove('d-none');
  } catch(e) {
    setStatus('sspFlowStatus', '✗ ' + e.message, 'error');
    showToast('SSP query failed: ' + e.message);
  } finally {
    setBtn('btnLoadFlows', false, '<i class="bi bi-activity me-1"></i>Load Port Activity');
  }
}

// Aggregate Druid rows by (proto, port) — Druid returns one row per appId/fqdn combo
function _aggregatePorts(ports) {
  const map = new Map();
  for (const row of (ports || [])) {
    const proto = (row.protocol || 'TCP').toUpperCase();
    const port  = String(row.dstPort || '');
    const key   = `${proto}|${port}`;
    if (!map.has(key)) map.set(key, { proto, port, count: 0, appIds: new Set() });
    const e = map.get(key);
    e.count += (row.flow_count || 0);
    // Only keep named app IDs (e.g. "SSL", "TLS_V13") — filter bare numbers
    const aid = String(row.appId || '');
    if (aid && aid !== 'UNKNOWN' && /[a-zA-Z]/.test(aid)) e.appIds.add(aid);
  }
  const _PORT_APP = { '80':'HTTP','8080':'HTTP','443':'HTTPS','8443':'HTTPS',
    '22':'SSH','21':'FTP','3389':'RDP','5985':'WinRM','5432':'PostgreSQL',
    '3306':'MySQL','1433':'MSSQL','6379':'Redis','27017':'MongoDB' };
  return [...map.values()]
    .sort((a, b) => b.count - a.count)
    .map(e => {
      // Resolve app IDs to human labels via NSX DPI registry (populated at NSX connect)
      const idx = S.appIdIndex || {};
      const resolvedApps = [...e.appIds].map(id => idx[id] || id);
      // Deduplicate resolved names (e.g. TLS_V12+TLS_V13 both → "TLS 1.x")
      const uniqueApps = [...new Set(resolvedApps)];
      const dpiLabel = uniqueApps.join(' / ');
      const app = dpiLabel || _PORT_APP[e.port] || '';
      return { proto: e.proto, port: e.port, count: e.count, app };
    });
}

function setSspView(mode) {
  S.sspViewMode = mode;
  if (S.portSuggestions.length) {
    const hours = parseInt(document.querySelector('.time-range-btn.active')?.dataset.hours || '24');
    renderPortSuggestions(S.portSuggestions, hours);
  }
}

function renderPortSuggestions(results, hours) {
  const area = document.getElementById('portSuggestionsArea');

  if (!results || !results.length) {
    area.innerHTML = '<p class="text-muted small mb-0">No results returned.</p>';
    area.classList.remove('d-none');
    return;
  }

  const periodLabel = { 24: 'last 24 h', 168: 'last week', 720: 'last month' }[hours] || `last ${hours} h`;
  const mode = S.sspViewMode || 'ports';

  const toggleHtml = `
    <div class="d-flex align-items-center justify-content-between mb-2">
      <p class="text-muted small mb-0">Destination traffic observed in the <strong>${periodLabel}</strong>:</p>
      <div class="btn-group btn-group-sm ms-3" role="group">
        <button type="button" class="btn btn-outline-secondary${mode === 'ports' ? ' active' : ''}" onclick="setSspView('ports')">Ports</button>
        <button type="button" class="btn btn-outline-secondary${mode === 'vms' ? ' active' : ''}" onclick="setSspView('vms')">VMs</button>
      </div>
    </div>`;

  let html = toggleHtml;

  if (mode === 'vms') {
    // VM-grouped view: one section per host
    const hasAny = results.some(r => r.ports?.length);
    if (!hasAny) {
      html += '<p class="text-muted small mb-0 fst-italic">No flows found in this window.</p>';
    } else {
      results.forEach(hostResult => {
        if (!hostResult.ports?.length) return;
        const name = S.allHosts[hostResult.ip] || hostResult.ip;
        const label = name !== hostResult.ip ? name : hostResult.ip;
        html += `
          <div class="mb-3">
            <div class="d-flex align-items-center gap-2 mb-1 fw-semibold small">
              <i class="bi bi-pc-display-horizontal text-muted"></i>
              <span>${escHtml(label)}</span>
              ${name !== hostResult.ip ? `<span class="text-muted font-monospace fw-normal">${escHtml(hostResult.ip)}</span>` : ''}
            </div>
            <div class="d-flex flex-wrap gap-2 ps-2">
              ${_aggregatePorts(hostResult.ports).map(row => {
                const portLabel = `${row.proto}:${row.port}`;
                return `<div class="port-chip" title="Override ${escHtml(label)} to ${escHtml(portLabel)}">
                  <span class="small font-monospace text-primary">${escHtml(portLabel)}</span>
                  ${row.app ? `<span class="text-muted" style="font-size:0.75rem">${escHtml(row.app)}</span>` : ''}
                  <span class="text-muted" style="font-size:0.75rem">${row.count.toLocaleString()}×</span>
                  <button class="apply-btn" title="Override ${escHtml(label)} to ${escHtml(portLabel)}"
                          onclick="applyPortSuggestion('${escHtml(hostResult.ip)}','${escHtml(row.proto)}','${escHtml(row.port)}')">↑</button>
                </div>`;
              }).join('')}
            </div>
          </div>`;
      });
    }
  } else {
    // Port-grouped view (default): one section per port
    const portMap = new Map();
    results.forEach(hostResult => {
      if (!hostResult.ports?.length) return;
      const name = S.allHosts[hostResult.ip] || hostResult.ip;
      _aggregatePorts(hostResult.ports).forEach(row => {
        const key = `${row.proto}|${row.port}`;
        if (!portMap.has(key)) {
          portMap.set(key, { proto: row.proto, port: row.port, app: row.app, totalCount: 0, hosts: [] });
        }
        const e = portMap.get(key);
        e.totalCount += row.count;
        e.hosts.push({ ip: hostResult.ip, name, count: row.count });
      });
    });

    const portEntries = [...portMap.values()].sort((a, b) => b.totalCount - a.totalCount);

    if (!portEntries.length) {
      html += '<p class="text-muted small mb-0 fst-italic">No flows found in this window.</p>';
    } else {
      portEntries.forEach(({ proto, port, app, totalCount, hosts }) => {
        html += `
          <div class="mb-3">
            <div class="d-flex align-items-center gap-2 mb-1 flex-wrap">
              <span class="fw-semibold font-monospace text-primary">${escHtml(proto)}:${escHtml(port)}</span>
              ${app ? `<span class="text-muted small">${escHtml(app)}</span>` : ''}
              <span class="text-muted small">${totalCount.toLocaleString()}×</span>
              <button class="btn btn-sm btn-outline-primary py-0 px-2"
                      onclick="populateGlobalPort('${escHtml(proto)}','${escHtml(port)}')">→ Global</button>
            </div>
            <div class="d-flex flex-wrap gap-2 ps-2">
              ${hosts.map(h => {
                const label = h.name && h.name !== h.ip ? h.name : h.ip;
                return `<div class="port-chip" title="${escHtml(h.name || h.ip)} — ${escHtml(proto)}:${escHtml(port)}">
                  <span class="small">${escHtml(label)}</span>
                  <span class="text-muted" style="font-size:0.75rem">${h.count.toLocaleString()}×</span>
                  <button class="apply-btn" title="Override ${escHtml(h.name || h.ip)} to ${escHtml(proto)}:${escHtml(port)}"
                          onclick="applyPortSuggestion('${escHtml(h.ip)}','${escHtml(proto)}','${escHtml(port)}')">↑</button>
                </div>`;
              }).join('')}
            </div>
          </div>`;
      });

      const noData = results.filter(r => !r.ports?.length && !r.error);
      if (noData.length) {
        html += `<div class="text-muted small fst-italic mt-1">No flows: ${noData.map(r => escHtml(S.allHosts[r.ip] || r.ip)).join(', ')}</div>`;
      }
    }
  }

  area.innerHTML = html;
  area.classList.remove('d-none');

  // Refresh picker button states now that data is loaded
  _refreshPickerButtons();
}

function populateGlobalPort(proto, port) {
  document.getElementById('advProtocol').value = proto;
  const portEl = document.getElementById('advPort');
  const existing = portEl.value.trim();
  if (existing) {
    const parts = existing.split(',').map(s => s.trim()).filter(Boolean);
    if (!parts.includes(port)) parts.push(port);
    portEl.value = parts.join(',');
  } else {
    portEl.value = port;
  }
  _syncGlobalPorts();
  const collapse = document.getElementById('collapseAdvanced');
  if (collapse && !collapse.classList.contains('show')) {
    bootstrap.Collapse.getOrCreateInstance(collapse).show();
  }
  showToast(`Global port: ${portEl.value}`, 'success');
}

function applyPortSuggestion(ip, proto, port) {
  const row = document.querySelector(`#hostPortTableBody tr[data-ip="${CSS.escape(ip)}"]`);
  if (!row) {
    showToast(`No per-host row for ${ip} — expand Advanced and load hosts first.`);
    return;
  }
  const sel = row.querySelector('.host-proto');
  const inp = row.querySelector('.host-port');
  if (sel) sel.value = proto;
  if (inp) inp.value = port;
  row.dataset.userEdited = '1';
  row.classList.add('table-warning');

  // Ensure Advanced accordion is open so the user can see the change
  const collapse = document.getElementById('collapseAdvanced');
  if (collapse && !collapse.classList.contains('show')) {
    bootstrap.Collapse.getOrCreateInstance(collapse).show();
  }
  showToast(`Applied ${proto}:${port} → ${S.allHosts[ip] || ip}`, 'success');
}

function applyAllSuggestions() {
  if (!S.portSuggestions.length) return;
  let applied = 0;
  S.portSuggestions.forEach(hostResult => {
    if (!hostResult.ports || !hostResult.ports.length) return;
    const top  = hostResult.ports[0];
    const proto = (top.protocol || 'TCP').toUpperCase();
    const port  = String(top.dstPort || '');
    if (!port) return;
    const row = document.querySelector(`#hostPortTableBody tr[data-ip="${CSS.escape(hostResult.ip)}"]`);
    if (!row) return;
    const sel = row.querySelector('.host-proto');
    const inp = row.querySelector('.host-port');
    if (sel) sel.value = proto;
    if (inp) inp.value = port;
    row.dataset.userEdited = '1';
    row.classList.add('table-warning');
    applied++;
  });
  if (applied) {
    const collapse = document.getElementById('collapseAdvanced');
    if (collapse && !collapse.classList.contains('show')) {
      bootstrap.Collapse.getOrCreateInstance(collapse).show();
    }
    showToast(`Applied top suggestion to ${applied} host(s)`, 'success');
  }
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
  S.allHosts     = {};
  S.sigIndex     = null;
  S.nsxConnected = false;
  S.sspConnected = false;
  S.portSuggestions = [];
  document.getElementById('cveTableBody').innerHTML = '';
  document.getElementById('deployLog').innerHTML    = '';
  document.getElementById('resultSummary').innerHTML = '';
  document.getElementById('scanList').innerHTML     = '';
  document.getElementById('nessusStatus').textContent = '';
  document.getElementById('nsxStatus').textContent    = '';
  document.getElementById('sspStatus').textContent    = '';
  document.getElementById('sspFlowStatus').textContent = '';
  document.getElementById('portSuggestionsArea').classList.add('d-none');
  document.getElementById('sspQueryRow').classList.add('d-none');
  document.getElementById('btnApplyAll').classList.add('d-none');
  document.getElementById('btnSspConnect').disabled = true;
  setBtn('btnSspConnect', false, '<i class="bi bi-plug me-1"></i>Connect to SSP');
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
