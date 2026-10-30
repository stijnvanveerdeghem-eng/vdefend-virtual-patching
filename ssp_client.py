"""SSP Security Intelligence client — queries Druid via kubectl port-forward on SSPI.

The SSPI SSH connection string is read from the SSPI_HOST environment variable,
or can be passed explicitly via the ssp_url parameter (e.g. "sysadmin@10.0.4.49").
Falls back to the SSPI_HOST env var, then "sysadmin@localhost".
"""
import json
import os
import subprocess

_DEFAULT_SSPI_HOST = os.environ.get("SSPI_HOST", "sysadmin@localhost")
SSH_KEY = os.path.expanduser("~/.ssh/id_rsa")


def _ssh_base(host: str) -> list:
    return [
        "ssh", "-i", SSH_KEY,
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-o", "BatchMode=yes",
        host,
    ]

# ── Reusable script fragment: set up /tmp/ssp-kubeconfig.yaml on SSPI ──────────
# On error: prints {"success": false, "error": "..."} and exits.
_SETUP_KC = """\
import subprocess, base64, sys, json as _j
_r = subprocess.run(
    ['kubectl','get','secret','-n','ssp','ssp-kubeconfig',
     '-o','jsonpath={.data.value}'],
    capture_output=True, text=True
)
if _r.returncode != 0:
    print(_j.dumps({'success': False, 'error': 'kubeconfig: ' + _r.stderr[:150]}))
    sys.exit(0)
open('/tmp/ssp-kubeconfig.yaml','w').write(
    base64.b64decode(_r.stdout.strip()).decode()
)
"""

# ── Query script body: uses IPS (list) and LOOKBACK (int) set by the caller ────
_QUERY_BODY = """\
import json, subprocess, time, urllib.request, ssl

_pf = subprocess.Popen(
    ['kubectl','--kubeconfig','/tmp/ssp-kubeconfig.yaml',
     'port-forward','-n','nsxi-platform','svc/druid-broker','18283:8282'],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(4)

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode    = ssl.CERT_NONE

def _druid(sql):
    req = urllib.request.Request(
        'https://localhost:18283/druid/v2/sql',
        data=json.dumps({'query': sql}).encode(),
        headers={'Content-Type': 'application/json'}
    )
    resp = urllib.request.urlopen(req, context=_ctx, timeout=30)
    return json.loads(resp.read())

_q   = chr(39)
_out = []
try:
    for _ip in IPS:
        _sql = (
            "SELECT dstPort, protocol, appId, fqdn, COUNT(*) as flow_count "
            "FROM correlated_flow_viz "
            "WHERE __time >= CURRENT_TIMESTAMP - INTERVAL "+_q+str(LOOKBACK)+_q+" HOUR "
            "  AND MV_CONTAINS(dstIps, "+_q+_ip+_q+") "
            "  AND dstPort IS NOT NULL AND dstPort <> '' "
            "GROUP BY dstPort, protocol, appId, fqdn "
            "ORDER BY flow_count DESC LIMIT 20"
        )
        try:
            _out.append({'ip': _ip, 'ports': _druid(_sql)})
        except Exception as _e:
            _out.append({'ip': _ip, 'ports': [], 'error': str(_e)[:200]})
finally:
    _pf.terminate()

print(json.dumps(_out))
"""


def _run(script: str, host: str, timeout: int = 90) -> str:
    r = subprocess.run(
        _ssh_base(host) + ["python3 -"],
        input=script, capture_output=True, text=True, timeout=timeout,
    )
    if r.returncode != 0:
        raise Exception(r.stderr.strip()[:400] or "SSPI connection failed")
    out = r.stdout.strip()
    if not out:
        raise Exception("SSPI script produced no output")
    return out


def _host(ssp_url: str) -> str:
    """Extract SSH connection string from ssp_url, or fall back to env/default."""
    url = (ssp_url or "").strip()
    # Accept bare "user@host" or "host" directly; ignore http(s):// URLs.
    if url and not url.startswith("http"):
        return url
    return _DEFAULT_SSPI_HOST


def connect(ssp_url: str, username: str, password: str) -> dict:
    """SSH to SSPI, set up SSP kubeconfig, verify Druid broker is reachable."""
    check = _SETUP_KC + """\
import json, subprocess
_r2 = subprocess.run(
    ['kubectl','--kubeconfig','/tmp/ssp-kubeconfig.yaml',
     'get','svc','druid-broker','-n','nsxi-platform','--no-headers'],
    capture_output=True, text=True
)
if _r2.returncode == 0:
    print(json.dumps({'success': True, 'message': 'SSP reachable — Druid broker found'}))
else:
    print(json.dumps({'success': False, 'error': 'Druid broker not found: ' + _r2.stderr[:100]}))
"""
    return json.loads(_run(check, _host(ssp_url), timeout=30))


def query_port_activity(
    ssp_url: str, username: str, password: str,
    host_ips: list, lookback_hours: int = 24,
) -> list:
    """Return per-IP destination port/protocol/DPI data from correlated_flow_viz."""
    header = f"IPS = {json.dumps(host_ips)}\nLOOKBACK = {int(lookback_hours)}\n"
    raw    = _run(_SETUP_KC + header + _QUERY_BODY, _host(ssp_url), timeout=120)
    result = json.loads(raw)
    if isinstance(result, dict):
        raise Exception(result.get("error", "SSP query failed"))
    return result if isinstance(result, list) else []
