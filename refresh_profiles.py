#!/usr/bin/env python3
"""Refresh virtual patch profiles after NSX signature updates.

For each profile recorded in profiles_state.json, fetches the current NSX
signature set, diffs it against the profile's existing exclusion list, and
patches in any new signatures.  Profiles that are already up to date are
skipped with no API write.

Credentials are read from ../.credentials (the labadmin repo credentials file).
No wrapper script or environment setup required — just run directly:

    python3 refresh_profiles.py

Typical cron usage (see README.md for full setup):
    0 2 * * * cd /home/rpletka/labadmin/vdefend-virtual-patching && python3 refresh_profiles.py >> /var/log/vdefend-refresh.log 2>&1
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running from any directory
sys.path.insert(0, str(Path(__file__).parent))
import nsx_client

STATE_FILE  = Path(__file__).parent / "profiles_state.json"
CREDS_FILE  = Path(__file__).parent / ".credentials"


def _load_credentials(path: Path) -> dict:
    """Parse a bash export KEY=VALUE credentials file into a plain dict."""
    creds = {}
    if not path.exists():
        return creds
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        # Strip surrounding matching quotes
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        creds[key] = val
    return creds


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"profiles": []}


def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def main():
    creds = _load_credentials(CREDS_FILE)

    # NSX_FQDN and PASSWORD come from the shared .credentials file.
    # Any of these can be overridden with an environment variable.
    nsx_host = os.environ.get("NSX_URL") or f"https://{creds.get('NSX_FQDN', '')}"
    nsx_user = os.environ.get("NSX_USER") or creds.get("NSX_USER", "admin")
    nsx_pass = os.environ.get("NSX_PASS") or creds.get("PASSWORD", "")

    if not nsx_host.startswith("http") or not nsx_pass:
        print(f"ERROR: could not load NSX credentials from {CREDS_FILE}", file=sys.stderr)
        print("Ensure NSX_FQDN and PASSWORD are set in .credentials, or set NSX_URL / NSX_PASS env vars.", file=sys.stderr)
        sys.exit(1)

    print(f"[{_now()}] Connecting to {nsx_host}")
    conn = nsx_client.connect(nsx_host, nsx_user, nsx_pass)
    nsx_version = conn.get("version", "")
    exclusion_mode = conn.get("exclusion_mode", False)
    print(f"[{_now()}] NSX {nsx_version} — exclusion_mode={exclusion_mode}")

    if not exclusion_mode:
        print(f"[{_now()}] NSX {nsx_version} uses CVE criteria (no refresh needed — profiles are version-independent)")
        sys.exit(0)

    state = load_state()
    profiles = state.get("profiles", [])

    if not profiles:
        print(f"[{_now()}] No profiles in {STATE_FILE}. Deploy a virtual patch via the web UI first.")
        sys.exit(0)

    print(f"[{_now()}] {len(profiles)} profile(s) to check\n")

    total_new = 0
    errors = 0

    for p in profiles:
        profile_id  = p["profile_id"]
        cve_list    = p["cve_list"]
        profile_name = p["profile_name"]
        rule_action  = p.get("rule_action", "DETECT_PREVENT")

        print(f"  [{_now()}] {profile_id}  CVEs: {', '.join(cve_list)}")

        try:
            sig_result = nsx_client.index_signatures(nsx_host, nsx_user, nsx_pass, cve_list)
            matched_cves = sig_result.get("matched_cves", {})

            if not matched_cves:
                print(f"  [{_now()}]   WARNING: no signatures found — skipping")
                continue

            result = nsx_client.create_profile(
                nsx_host, nsx_user, nsx_pass,
                run_id="refresh",
                profile_name=profile_name,
                matched_cves=matched_cves,
                rule_action=rule_action,
                nsx_version=nsx_version,
            )

            new_excl = result.get("new_exclusions_added", 0)
            total_new += new_excl
            p["last_refreshed"] = _now()

            if new_excl:
                print(f"  [{_now()}]   +{new_excl} new exclusion(s) patched in")
            else:
                print(f"  [{_now()}]   already up to date")

        except Exception as e:
            print(f"  [{_now()}]   ERROR: {e}", file=sys.stderr)
            errors += 1

    save_state(state)
    print(f"\n[{_now()}] Done — {total_new} new exclusion(s) added, {errors} error(s)")
    sys.exit(1 if errors else 0)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


if __name__ == "__main__":
    main()
