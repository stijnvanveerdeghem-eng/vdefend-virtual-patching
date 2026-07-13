"""NSX vDefend IDPS API client — stdlib only."""
import io
import json
import re
import ssl
import urllib.error
import urllib.request
import base64
import urllib.parse
from typing import Optional

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

TIMEOUT = 120
POLICY = "/policy/api/v1"


def _auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def _req(url: str, method: str = "GET", body=None, username: str = "", password: str = "") -> dict:
    print(f"NSX API Request: {method} {url}")
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": _auth_header(username, password),
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, context=_SSL_CTX, timeout=TIMEOUT) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}


def _clean_url(url: str) -> str:
    url = url.strip(" ./")
    if url.endswith("/login.jsp"):
        url = url[:-10]
    if not url.startswith("http"):
        url = "https://" + url
    return url


def _version_tuple(version_str: str) -> tuple:
    """Parse '4.2.3.0' into (4, 2, 3, 0) for comparison."""
    try:
        return tuple(int(x) for x in version_str.split(".")[:4])
    except (ValueError, AttributeError):
        return (0,)


def _needs_exclusion_approach(version_str: str) -> bool:
    """True when NSX requires the exclusion approach for IDS profiles.

    NSX 9.0.x and NSX 4.x must enumerate and disable every non-target signature
    individually (enable:false) because the CVE-based include criteria filter
    was not added until NSX 9.1.  NSX 9.1+ can use IdsProfileFilterCriteria.
    """
    if not version_str:
        return False
    t = _version_tuple(version_str)
    major = t[0]
    minor = t[1] if len(t) > 1 else 0
    return major <= 4 or (major == 9 and minor == 0)


def get_nsx_version(url: str, username: str, password: str) -> str:
    url = _clean_url(url)
    try:
        data = _req(f"{url}/api/v1/node", username=username, password=password)
        return data.get("product_version", "")
    except Exception as e:
        print(f"Could not fetch NSX version: {e}")
        return ""


def connect(url: str, username: str, password: str) -> dict:
    url = _clean_url(url)
    _req(
        f"{url}{POLICY}/infra/settings/firewall/security/intrusion-services",
        username=username,
        password=password,
    )
    version = get_nsx_version(url, username, password)
    exclusion_mode = _needs_exclusion_approach(version)
    return {
        "success": True,
        "message": "Connected to NSX Manager",
        "version": version,
        "exclusion_mode": exclusion_mode,
    }


def get_active_signature_version(url: str, username: str, password: str) -> str:
    url = _clean_url(url)
    endpoint = f"{url}{POLICY}/infra/settings/firewall/security/intrusion-services/signature-versions"
    data = _req(endpoint, username=username, password=password)
    results = data.get("results") or []
    if not results:
        raise Exception("No signature versions found in NSX. Please update signatures in the NSX UI.")

    version_id = results[0].get("version_id")
    if not version_id:
        raise Exception("Could not determine signature version ID.")
    return version_id


def _get_signatures_by_severity(url: str, username: str, password: str, severities: set) -> list:
    """Paginate through all IDS signatures matching the given severity levels."""
    sev_terms = " OR ".join(f"severity:{s}" for s in severities)
    query = f"resource_type:IdsSignature AND ({sev_terms})"
    all_sigs = []
    cursor = None
    while True:
        params = f"query={urllib.parse.quote(query)}&page_size=1000"
        if cursor:
            params += f"&cursor={urllib.parse.quote(str(cursor))}"
        endpoint = f"{url}{POLICY}/search/query?{params}"
        try:
            data = _req(endpoint, username=username, password=password)
        except Exception as e:
            print(f"Error fetching signature page: {e}")
            break
        results = data.get("results", [])
        all_sigs.extend(results)
        cursor = data.get("cursor")
        if not cursor or not results:
            break
    print(f"Fetched {len(all_sigs)} signatures at severities {severities}")
    return all_sigs


def index_signatures(url: str, username: str, password: str, cve_list: list) -> dict:
    url = _clean_url(url)
    cve_set = {c.upper() for c in cve_list}
    cve_to_sigs: dict = {c: [] for c in cve_set}
    total_signatures = 0

    if not cve_set:
        return {"cve_to_sigs": cve_to_sigs, "total_indexed": 0}

    # Extract just the numbers "YYYY-NNNN" for NSX search
    nsx_cves = []
    for c in cve_set:
        if c.startswith("CVE-"):
            nsx_cves.append(c[4:])
        else:
            nsx_cves.append(c)

    # Chunk into batches of 50 to avoid URL length limits
    batch_size = 50
    for i in range(0, len(nsx_cves), batch_size):
        batch = nsx_cves[i:i+batch_size]

        cve_queries = [f"cves:{c}" for c in batch]
        or_clause = " OR ".join(cve_queries)
        query = f"resource_type:IdsSignature AND ({or_clause})"

        endpoint = f"{url}{POLICY}/search/query?query={urllib.parse.quote(query)}&page_size=1000"

        try:
            data = _req(endpoint, username=username, password=password)
            results = data.get("results", [])
            total_signatures += len(results)

            for sig in results:
                raw_cves = sig.get("cves") or sig.get("cve_ids") or []
                for cv in raw_cves:
                    cv_upper = cv.upper()
                    normalized_cve = f"CVE-{cv_upper}" if not cv_upper.startswith("CVE-") else cv_upper
                    if normalized_cve in cve_to_sigs:
                        cve_to_sigs[normalized_cve].append({
                            "sig_id": sig.get("id") or sig.get("signature_id"),
                            "sig_name": sig.get("name") or sig.get("display_name", ""),
                            "severity": sig.get("severity", ""),
                            "action": sig.get("action", ""),
                        })
        except Exception as e:
            print(f"Error fetching batch: {e}")

    matched_cves = {k: v for k, v in cve_to_sigs.items() if v}
    return {
        "total_signatures": total_signatures,
        "matched_cves": matched_cves,
        "coverage_count": len(matched_cves),
        "total_cves_requested": len(cve_list),
        "total_signatures_matched": sum(len(v) for v in matched_cves.values()),
    }


_IP_RE = __import__("re").compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def tag_vm_by_ip(url: str, username: str, password: str, ip_address: str, cve_list: list):
    url = _clean_url(url)

    def _vif_lookup(ip):
        """Walk fabric VIFs — IPs are nested in ip_address_info[].ip_addresses[]."""
        cursor = None
        while True:
            qs = f"page_size=500{f'&cursor={urllib.parse.quote(cursor)}' if cursor else ''}"
            res = _req(f"{url}/api/v1/fabric/vifs?{qs}", username=username, password=password)
            for vif in (res or {}).get("results", []):
                vif_ips = [a for info in vif.get("ip_address_info", [])
                           for a in info.get("ip_addresses", [])]
                if ip in vif_ips:
                    return vif.get("owner_vm_id")
            cursor = (res or {}).get("cursor")
            if not cursor:
                break
        return None

    def _name_search(name):
        """Fabric VM list by display_name — only useful when identifier is a hostname."""
        res = _req(f"{url}/api/v1/fabric/virtual-machines?display_name={urllib.parse.quote(name)}",
                   username=username, password=password)
        results = (res or {}).get("results", [])
        return results[0].get("external_id") if results else None

    is_ip = bool(_IP_RE.match(ip_address))
    short_name = ip_address.split(".")[0] if not is_ip else None

    vm_id = _vif_lookup(ip_address)
    if not vm_id and short_name:
        vm_id = _name_search(short_name)

    if not vm_id:
        print(f"Could not find VM in NSX inventory for {ip_address}")
        return {"tagged": False, "ip": ip_address}

    print(f"Found VM {vm_id} for {ip_address}. Applying tags...")

    tags = [{"scope": "Vulnerability", "tag": cve} for cve in cve_list[:30]]
    _req(f"{url}/api/v1/fabric/virtual-machines?action=add_tags",
         method="POST", body={"external_id": vm_id, "tags": tags},
         username=username, password=password)
    print(f"Successfully tagged VM {vm_id} with {cve_list}")
    return {"tagged": True, "ip": ip_address, "vm_id": vm_id}


def create_group(url: str, username: str, password: str, run_id: str, cve_list: list) -> dict:
    url = _clean_url(url)
    group_name = cve_list[0] if len(cve_list) == 1 else "VirtualPatch-Multiple-CVEs"
    # Stable ID so re-deploys update the same group rather than creating new ones
    group_id = "virtualPatch-" + "-".join(sorted(c.upper().replace("CVE-", "") for c in cve_list))

    expressions = []
    for i, cve in enumerate(cve_list):
        expr = {
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Tag",
            "operator": "EQUALS",
            "value": f"Vulnerability|{cve}"
        }
        expressions.append(expr)
        if i < len(cve_list) - 1:
            expressions.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})

    body = {
        "display_name": group_name,
        "expression": expressions,
    }
    endpoint = f"{url}{POLICY}/infra/domains/default/groups/{group_id}"
    try:
        _req(endpoint, username=username, password=password)
        method = "PATCH"
    except Exception:
        method = "PUT"
    _req(endpoint, method=method, body=body, username=username, password=password)
    return {"group_id": group_id, "group_path": f"/infra/domains/default/groups/{group_id}", "group_name": group_name}


def _should_escalate(sig_action: str) -> bool:
    """True when a signature's current action is non-blocking and safe to escalate to REJECT."""
    return sig_action.upper() not in ("REJECT", "DROP", "DISABLED")


def _profile_id_for_cves(cve_list: list) -> str:
    """Stable profile ID derived from the CVE set, so re-runs update the same profile."""
    slug = "-".join(sorted(c.upper().replace("CVE-", "") for c in cve_list))
    # Keep it short; NSX IDs can't be excessively long
    if len(slug) > 60:
        import hashlib
        slug = hashlib.sha1(slug.encode()).hexdigest()[:12]
    return f"virtualPatch-{slug}"


def _patch_profile_with_retry(
    profile_endpoint: str, method: str, body: dict,
    username: str, password: str,
) -> dict:
    """PATCH/PUT an IDS profile with automatic retry on signature ID rejections.

    NSX returns 400 in two cases where the fix is the same — strip the offending
    signature IDs from overridden_signatures and retry:
      523669 — IDs not recognised by the profile API (retired / custom sigs that
               appear in the search index but can't be overridden)
      523673 — IDs whose severity in the API doesn't match the profile's
               profile_severity (search index is stale vs live sig metadata)

    Both errors can appear on successive retries (e.g. 523669 on attempt 0,
    523673 on attempt 1), so we accumulate the bad IDs across retries and keep
    going until we succeed or hit a non-retriable error.

    Any other HTTP error is re-raised with the body still readable by the caller.
    """
    _RETRIABLE = {523669, 523673}
    _LABELS = {523669: "invalid", 523673: "severity-mismatch"}
    MAX_RETRIES = 5
    accumulated_bad: set = set()

    for attempt in range(MAX_RETRIES + 1):
        try:
            return _req(profile_endpoint, method=method, body=body,
                        username=username, password=password)
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                err = json.loads(raw)
            except Exception:
                raise urllib.error.HTTPError(e.url, e.code, raw, e.headers,
                                             io.BytesIO(raw.encode()))

            error_code = err.get("error_code")
            if error_code not in _RETRIABLE or attempt >= MAX_RETRIES:
                raise urllib.error.HTTPError(e.url, e.code, raw, e.headers,
                                             io.BytesIO(raw.encode()))

            m = re.search(r"\[([0-9,\s]+)\]", err.get("error_message", ""))
            if not m:
                raise urllib.error.HTTPError(e.url, e.code, raw, e.headers,
                                             io.BytesIO(raw.encode()))

            new_bad = {s.strip() for s in m.group(1).split(",")}
            accumulated_bad.update(new_bad)
            label = _LABELS.get(error_code, str(error_code))
            print(f"Retry {attempt + 1}/{MAX_RETRIES}: stripped {len(new_bad)} "
                  f"{label} IDs ({len(accumulated_bad)} total filtered)")
            body["overridden_signatures"] = [
                o for o in body.get("overridden_signatures", [])
                if str(o.get("signature_id", "")) not in accumulated_bad
            ]


def create_profile(
    url: str, username: str, password: str,
    run_id: str, profile_name: str, matched_cves: dict,
    rule_action: str = "DETECT_PREVENT", nsx_version: str = "",
) -> dict:
    url = _clean_url(url)

    # Build CVE sig ID set and per-sig action map from the index results
    cve_sig_ids: set = set()
    cve_sig_actions: dict = {}
    for sigs in matched_cves.values():
        for sig in sigs:
            sid = sig.get("sig_id")
            if sid:
                cve_sig_ids.add(str(sid))
                cve_sig_actions[str(sid)] = sig.get("action", "")

    if _needs_exclusion_approach(nsx_version):
        # NSX 9.0.x / 4.x: no CVE criteria filter — must exclude every non-target
        # signature individually via enable:false.
        #
        # Sustainability: the profile ID is derived from the CVE set so the same
        # profile is reused across runs.  We fetch the existing profile first and
        # only add overrides for signatures that aren't already there, so signature
        # database updates produce a cheap incremental PATCH rather than a full rebuild.

        # Stable profile ID so re-runs update the same object
        profile_id = _profile_id_for_cves(list(matched_cves.keys()))
        profile_endpoint = f"{url}{POLICY}/infra/settings/firewall/security/intrusion-services/profiles/{profile_id}"

        target_severities: set = set()
        for sigs in matched_cves.values():
            for sig in sigs:
                sev = sig.get("severity", "").upper()
                if sev:
                    target_severities.add(sev)
        if not target_severities:
            target_severities = {"CRITICAL", "HIGH"}

        # Load existing profile overrides so we can diff instead of rebuilding
        existing_by_sid: dict = {}
        is_update = False
        try:
            existing = _req(profile_endpoint, username=username, password=password)
            for entry in existing.get("overridden_signatures", []):
                sid = str(entry.get("signature_id", ""))
                if sid:
                    existing_by_sid[sid] = entry
            is_update = True
            print(f"Profile {profile_id} exists ({len(existing_by_sid)} overrides) — incremental update")
        except Exception:
            print(f"Profile {profile_id} not found — full build")

        # Fetch current signatures at target severities
        print(f"Fetching signatures at {target_severities}")
        all_sigs = _get_signatures_by_severity(url, username, password, target_severities)

        # Build only the NEW overrides (sigs not yet in the profile)
        new_overrides = []
        for sig in all_sigs:
            sid = str(sig.get("id") or sig.get("signature_id") or "")
            if not sid or sid in existing_by_sid:
                continue  # already handled — leave existing state untouched
            if sid in cve_sig_ids:
                if rule_action == "DETECT_PREVENT" and _should_escalate(sig.get("action", "")):
                    new_overrides.append({"signature_id": sid, "enable": True, "action": "REJECT"})
                # DETECT mode or already blocking — no override needed, stays enabled at default
            else:
                new_overrides.append({"signature_id": sid, "enable": False})

        print(f"New signatures to add: {len(new_overrides)}")

        all_overrides = list(existing_by_sid.values()) + new_overrides
        body = {
            "display_name": profile_name,
            "overridden_signatures": all_overrides,
            "profile_severity": sorted(target_severities),
            "include_system_signatures": True,
            "include_custom_signatures": False,
        }
        method = "PATCH" if is_update else "PUT"
        _patch_profile_with_retry(profile_endpoint, method, body, username, password)

        return {
            "profile_id": profile_id,
            "profile_path": f"/infra/settings/firewall/security/intrusion-services/profiles/{profile_id}",
            "signatures_applied": len(cve_sig_ids),
            "new_exclusions_added": len(new_overrides),
        }

    else:
        # Modern NSX (9.1+): CVE criteria filter handles scoping cleanly.
        # In DETECT_PREVENT mode, escalate any ALERT signatures to REJECT.
        # In DETECT mode, no overrides — rule-level DETECT makes everything alert-only.
        profile_id = f"virtualPatch-profile-{run_id}"
        nsx_cves = [cve[4:] if cve.startswith("CVE-") else cve for cve in matched_cves.keys()]

        overrides = []
        if rule_action == "DETECT_PREVENT":
            seen: set = set()
            for sigs in matched_cves.values():
                for sig in sigs:
                    sid = sig.get("sig_id")
                    if sid and sid not in seen and _should_escalate(sig.get("action", "")):
                        seen.add(sid)
                        overrides.append({"signature_id": sid, "action": "REJECT"})

        body = {
            "display_name": profile_name,
            "criteria": [
                {
                    "resource_type": "IdsProfileFilterCriteria",
                    "filter_name": "CVE",
                    "filter_value": nsx_cves,
                }
            ],
            "overridden_signatures": overrides,
            "profile_severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "include_system_signatures": True,
            "include_custom_signatures": False,
        }
        _req(
            f"{url}{POLICY}/infra/settings/firewall/security/intrusion-services/profiles/{profile_id}",
            method="PUT", body=body, username=username, password=password,
        )
        return {
            "profile_id": profile_id,
            "profile_path": f"/infra/settings/firewall/security/intrusion-services/profiles/{profile_id}",
            "signatures_applied": len(cve_sig_ids),
            "new_exclusions_added": 0,
        }


def _resolve_service(url: str, username: str, password: str,
                     protocol: str, port: str) -> str:
    """Return the path of an NSX service matching protocol/port.

    Searches all existing services first (built-in and custom). Only creates
    a new vp- service if no existing service matches.
    """
    proto = protocol.upper()
    port_str = str(port)

    # Walk all services looking for an L4 entry that matches
    cursor = None
    while True:
        qs = f"page_size=1000{f'&cursor={urllib.parse.quote(cursor)}' if cursor else ''}"
        res = _req(f"{url}{POLICY}/infra/services?{qs}", username=username, password=password)
        for svc in (res or {}).get("results", []):
            for entry in svc.get("service_entries", []):
                if (entry.get("resource_type") == "L4PortSetServiceEntry"
                        and entry.get("l4_protocol", "").upper() == proto
                        and port_str in [str(p) for p in entry.get("destination_ports", [])]):
                    path = svc.get("path") or f"/infra/services/{svc['id']}"
                    print(f"Found existing service {svc['id']} for {proto} {port_str}")
                    return path
        cursor = (res or {}).get("cursor")
        if not cursor:
            break

    # No existing service matched — create a custom one
    service_id = f"{proto.lower()}-{port_str}"
    print(f"Creating service {service_id} ({proto} {port_str})")
    _req(f"{url}{POLICY}/infra/services/{service_id}",
         method="PATCH", username=username, password=password, body={
             "display_name": f"{proto} {port_str}",
             "service_entries": [{
                 "id": f"port-{port_str}",
                 "resource_type": "L4PortSetServiceEntry",
                 "l4_protocol": proto,
                 "destination_ports": [port_str],
             }],
         })
    return f"/infra/services/{service_id}"


def create_policy(
    url: str, username: str, password: str,
    run_id: str, rule_name: str, profile_path: str, group_path: str,
    category: str = "EmergencyThreatRules", policy_name: str = "Virtual Patches",
    rule_action: str = "DETECT_PREVENT", nsx_version: str = "",
    rule_tag: str = "", protocol: str = "", port: str = "",
) -> dict:
    url = _clean_url(url)
    policy_id = "Virtual-Patches-Policy"
    sequence_number = 1

    endpoint = f"{url}{POLICY}/infra/domains/default/intrusion-service-policies/{policy_id}"
    try:
        existing_policy = _req(endpoint, username=username, password=password)
        rules = existing_policy.get("rules", [])
        method = "PATCH"
    except Exception:
        rules = []
        method = "PUT"

    if protocol and port:
        service_path = _resolve_service(url, username, password, protocol, port)
        services = [service_path]
    else:
        services = ["ANY"]

    # Stable rule ID derived from the profile so re-deploys update the same rule
    rule_id = "rule-" + profile_path.split("/")[-1]

    new_rule = {
        "id": rule_id,
        "display_name": rule_name,
        "ids_profiles": [profile_path],
        "source_groups": ["ANY"],
        "destination_groups": [group_path],
        "services": services,
        "action": rule_action,
        "direction": "IN",
        "logged": True,
        "scope": [group_path],
    }
    if rule_tag:
        new_rule["tag"] = rule_tag

    # Replace any existing rule with the same ID rather than appending
    rules = [r for r in rules if r.get("id") != rule_id]
    rules.append(new_rule)

    body = {
        "display_name": policy_name,
        "category": category,
        "sequence_number": sequence_number,
        "rules": rules,
    }
    _req(endpoint, method=method, body=body, username=username, password=password)
    return {
        "policy_id": policy_id,
        "policy_path": f"/infra/domains/default/intrusion-service-policies/{policy_id}",
        "rule_id": rule_id,
        "category_used": category,
    }
