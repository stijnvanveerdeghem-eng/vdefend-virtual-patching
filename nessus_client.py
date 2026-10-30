"""Nessus Essentials API client — stdlib only."""
import json
import ssl
import urllib.request
import urllib.error
from typing import Optional

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

TIMEOUT = 120


def _req(url: str, method: str = "GET", body=None, headers: dict = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, context=_SSL_CTX, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def connect(url: str, username: str, password: str) -> dict:
    url = url.rstrip("/")
    if not url.startswith("http"):
        url = "https://" + url
    result = _req(f"{url}/session", "POST", {"username": username, "password": password})
    return {"success": True, "token": result["token"]}


def list_scans(url: str, token: str) -> list:
    data = _req(f"{url}/scans", headers={"X-Cookie": f"token={token}"})
    scans = data.get("scans") or []
    out = []
    for s in scans:
        out.append({
            "id": s["id"],
            "name": s.get("name", "Unnamed"),
            "status": s.get("status", "unknown"),
            "creation_date": s.get("creation_date"),
            "host_count": s.get("hostcount", 0),
        })
    return out


def _get_plugin_cves(url: str, token: str, plugin_id: int) -> dict:
    try:
        data = _req(f"{url}/plugins/plugin/{plugin_id}",
                    headers={"X-Cookie": f"token={token}"})
        attrs = data.get("attributes", [])
    except Exception:
        return {"cves": [], "cvss": None, "description": ""}

    cves, cvss, description = [], None, ""
    for attr in attrs:
        name = attr.get("attribute_name", "")
        value = attr.get("attribute_value", "")
        if name == "cve":
            cves.append(value.upper())
        elif name in ("cvss3_base_score", "cvss_base_score") and cvss is None:
            try:
                cvss = float(value)
            except ValueError:
                pass
        elif name == "description" and not description:
            description = value[:300]
    return {"cves": cves, "cvss": cvss, "description": description}


SEVERITY_MAP = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def extract_cves(url: str, token: str, scan_id: int) -> dict:
    hdrs = {"X-Cookie": f"token={token}"}
    scan_data = _req(f"{url}/scans/{scan_id}", headers=hdrs)

    hosts_raw = scan_data.get("hosts") or []
    hosts_out = []
    for h in hosts_raw:
        ip = h.get("hostname", "")
        hosts_out.append({
            "host_id": h["host_id"],
            "ip": ip,
            "hostname": ip,
            "name": h.get("name") or ip,
            "critical": h.get("critical", 0),
            "high": h.get("high", 0),
            "medium": h.get("medium", 0),
            "low": h.get("low", 0),
        })

    plugin_to_hosts: dict = {}
    plugin_severities: dict = {}

    for h in hosts_raw:
        try:
            hr = _req(f"{url}/scans/{scan_id}/hosts/{h['host_id']}", headers=hdrs)
        except Exception:
            continue
        vulns = hr.get("vulnerabilities") or []
        host_ip = h.get("hostname", str(h["host_id"]))
        for v in vulns:
            if v.get("severity", 0) < 2:
                continue
            pid = v["plugin_id"]
            if pid not in plugin_to_hosts:
                plugin_to_hosts[pid] = []
                plugin_severities[pid] = v.get("severity", 2)
            if host_ip not in plugin_to_hosts[pid]:
                plugin_to_hosts[pid].append(host_ip)

    plugin_details: dict = {}
    for pid in plugin_to_hosts:
        plugin_details[pid] = _get_plugin_cves(url, token, pid)

    cve_map: dict = {}
    for pid, detail in plugin_details.items():
        for cve in detail["cves"]:
            if cve not in cve_map:
                sev_int = plugin_severities.get(pid, 2)
                cve_map[cve] = {
                    "cve_id": cve,
                    "severity": SEVERITY_MAP.get(sev_int, "Medium"),
                    "severity_int": sev_int,
                    "cvss": detail["cvss"],
                    "description": detail["description"],
                    "affected_hosts": [],
                    "plugin_ids": [],
                }
            for ip in plugin_to_hosts.get(pid, []):
                if ip not in cve_map[cve]["affected_hosts"]:
                    cve_map[cve]["affected_hosts"].append(ip)
            if pid not in cve_map[cve]["plugin_ids"]:
                cve_map[cve]["plugin_ids"].append(pid)

    cves_list = sorted(cve_map.values(), key=lambda x: (-x["severity_int"], x["cve_id"]))
    seen_ips: set = set()
    all_ips: list = []
    all_hosts: list = []
    for h in hosts_out:
        if h["ip"] and h["ip"] not in seen_ips:
            seen_ips.add(h["ip"])
            all_ips.append(h["ip"])
            all_hosts.append({"ip": h["ip"], "name": h["name"]})

    return {
        "hosts": hosts_out,
        "cves": cves_list,
        "total_hosts": len(hosts_out),
        "total_cves": len(cves_list),
        "all_ips": all_ips,
        "all_hosts": all_hosts,
    }
