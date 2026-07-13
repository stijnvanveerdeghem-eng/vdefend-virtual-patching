"""vDefend Virtual Patching Tool — stdlib only, no pip required."""
import json
import mimetypes
import os

# Force Python to ignore the broken lab proxy
os.environ["http_proxy"] = ""
os.environ["https_proxy"] = ""
os.environ["HTTP_PROXY"] = ""
os.environ["HTTPS_PROXY"] = ""
os.environ["no_proxy"] = "*"
os.environ["NO_PROXY"] = "*"

import threading
import traceback
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import urllib.error
from urllib.parse import urlparse, parse_qs

import nessus_client
import nsx_client

PORT = 5002
STATIC_DIR = Path(__file__).parent / "static"
STATE_FILE = Path(__file__).parent / "profiles_state.json"

# ── In-memory state (single-user demo) ────────────────────────────────────────
_state: dict = {}


def _record_profile(profile_id: str, profile_name: str, cve_list: list, rule_action: str):
    """Upsert a profile entry in profiles_state.json for refresh_profiles.py."""
    try:
        state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {"profiles": []}
        profiles = state.setdefault("profiles", [])
        # Update existing entry or append new one
        for p in profiles:
            if p["profile_id"] == profile_id:
                p["profile_name"] = profile_name
                p["cve_list"] = cve_list
                p["rule_action"] = rule_action
                p["deployed_at"] = datetime.utcnow().isoformat() + "Z"
                break
        else:
            profiles.append({
                "profile_id": profile_id,
                "profile_name": profile_name,
                "cve_list": cve_list,
                "rule_action": rule_action,
                "deployed_at": datetime.utcnow().isoformat() + "Z",
                "last_refreshed": None,
            })
        STATE_FILE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        print(f"Warning: could not update profiles_state.json: {e}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _json_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length", 0))
    return json.loads(handler.rfile.read(length)) if length else {}


def _ok(handler, data: dict, status: int = 200):
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", len(body))
    handler.end_headers()
    handler.wfile.write(body)


def _err(handler, message: str, status: int = 400):
    _ok(handler, {"success": False, "detail": message}, status)


# ── Request handler ───────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} {fmt % args}")

    # ── GET ──────────────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self._serve_file(STATIC_DIR / "index.html")
            return

        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            self._serve_file(STATIC_DIR / rel)
            return

        if path == "/api/nessus/scans":
            qs = parse_qs(parsed.query)
            nessus_url = (qs.get("nessus_url") or [""])[0]
            token = (qs.get("token") or [""])[0]
            try:
                scans = nessus_client.list_scans(nessus_url, token)
                _ok(self, {"scans": scans})
            except Exception as e:
                _err(self, str(e))
            return

        self.send_response(404)
        self.end_headers()

    def _serve_file(self, filepath: Path):
        if not filepath.exists():
            self.send_response(404)
            self.end_headers()
            return
        mime, _ = mimetypes.guess_type(str(filepath))
        body = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    # ── POST ─────────────────────────────────────────────────────────────────
    def do_POST(self):
        path = urlparse(self.path).path
        body = _json_body(self)

        try:
            if path == "/api/nessus/connect":
                result = nessus_client.connect(body["url"], body["username"], body["password"])
                _state["nessus_url"] = body["url"]
                _state["nessus_token"] = result["token"]
                _ok(self, {"success": True, "token": result["token"], "message": "Connected to Nessus"})

            elif path == "/api/nessus/extract":
                result = nessus_client.extract_cves(body["nessus_url"], body["token"], body["scan_id"])
                _state["last_extract"] = result
                _ok(self, result)

            elif path == "/api/nsx/connect":
                result = nsx_client.connect(body["url"], body["username"], body["password"])
                _state.update({
                    "nsx_url": body["url"],
                    "nsx_username": body["username"],
                    "nsx_password": body["password"],
                    "nsx_version": result.get("version", ""),
                })
                _ok(self, result)

            elif path == "/api/nsx/signatures/index":
                result = nsx_client.index_signatures(
                    body["nsx_url"], body["username"], body["password"], body["cve_list"]
                )
                _state["last_sig_index"] = result
                _ok(self, result)

            elif path == "/api/deploy":
                self._handle_deploy(body)

            else:
                _err(self, "Not found", 404)

        except KeyError as e:
            _err(self, f"Missing field: {e}")
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode()
            except Exception:
                err_body = "No response body"
            print(f"HTTPError: {e.code} - {err_body}")
            _err(self, f"API Error {e.code}: {err_body}", 500)
        except Exception as e:
            traceback.print_exc()
            _err(self, str(e), 500)

    def _handle_deploy(self, body: dict):
        run_id = body.get("run_id") or datetime.now().strftime("%Y%m%d-%H%M%S")
        url, user, pwd = body["nsx_url"], body["username"], body["password"]
        cve_list = body["cve_list"]
        host_ips = body["host_ips"]

        # NSX version from state (set during /api/nsx/connect)
        nsx_version = _state.get("nsx_version", "")

        # Advanced config overrides
        action = body.get("action", "DETECT_PREVENT").upper()
        profile_name = body.get("profile_name", f"VirtualPatch-{run_id}")
        policy_name = body.get("policy_name", "Virtual Patches")
        category = body.get("category", "EmergencyThreatRules")
        rule_name = body.get("rule_name", f"VirtualPatch-Rule-{run_id}")
        rule_protocol = body.get("protocol", "")
        rule_port = body.get("port", "")

        # Rule-level action only; signature default actions are left unchanged.
        rule_action = "DETECT" if action == "DETECT" else "DETECT_PREVENT"

        sig_result = nsx_client.index_signatures(url, user, pwd, cve_list)
        matched_cves = sig_result["matched_cves"]

        if not matched_cves:
            _err(self, "No IDPS signatures found for selected CVEs.")
            return

        # Tag the VMs
        tag_results = [nsx_client.tag_vm_by_ip(url, user, pwd, ip, cve_list) for ip in host_ips]
        tagged = [r["ip"] for r in tag_results if r and r.get("tagged")]
        not_found = [r["ip"] for r in tag_results if r and not r.get("tagged")]

        group_r   = nsx_client.create_group(url, user, pwd, run_id, cve_list)
        profile_r = nsx_client.create_profile(
            url, user, pwd, run_id, profile_name, matched_cves,
            rule_action=rule_action, nsx_version=nsx_version,
        )
        rule_tag = "IDS-" + ",".join(cve_list)
        policy_r  = nsx_client.create_policy(
            url, user, pwd, run_id, rule_name,
            profile_r["profile_path"], group_r["group_path"],
            category, policy_name, rule_action,
            nsx_version=nsx_version,
            rule_tag=rule_tag,
            protocol=rule_protocol,
            port=rule_port,
        )

        _record_profile(profile_r["profile_id"], profile_name, cve_list, rule_action)

        _ok(self, {
            "success": True,
            "run_id": run_id,
            **group_r, **profile_r, **policy_r,
            "cves_covered": len(matched_cves),
            "hosts_protected": len(host_ips),
            "tagged": tagged,
            "not_found": not_found,
            "action": action,
            "nsx_version": nsx_version,
            "message": "Virtual patch deployed successfully.",
        })


# ── Entry point ───────────────────────────────────────────────────────────────

def run():
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"\n  vDefend Virtual Patching Tool")
    print(f"  ================================")
    print(f"  Open http://localhost:{PORT} in your browser")
    print(f"  Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()


if __name__ == "__main__":
    run()
