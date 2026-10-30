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


_TLS_DISPLAY = {
    "TLS_V10": "TLS 1.0", "TLS_V11": "TLS 1.1",
    "TLS_V12": "TLS 1.2", "TLS_V13": "TLS 1.3",
}


def get_app_id_index(url: str, username: str, password: str) -> dict:
    """Return {appId: short_label} for all 5000+ NSX DPI application IDs.

    Uses GET /policy/api/v1/infra/context-profiles/attributes?attribute_key=APP_ID
    (NSX 9.1 renamed the endpoint from attribute-values to attributes).
    The app ID itself is the short name; TLS versions get "TLS 1.x" overrides.
    """
    url = _clean_url(url)
    data = _req(
        f"{url}{POLICY}/infra/context-profiles/attributes?attribute_key=APP_ID",
        username=username, password=password,
    )
    result = {}
    for attr in (data.get("results") or [{}])[0].get("attributes", []):
        val = (attr.get("value") or [None])[0]
        if not val:
            continue
        result[val] = _TLS_DISPLAY.get(val, val)
    return result


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
    unique_sig_ids = {str(sig["sig_id"]) for sigs in matched_cves.values()
                      for sig in sigs if sig.get("sig_id")}
    return {
        "total_signatures": total_signatures,
        "matched_cves": matched_cves,
        "coverage_count": len(matched_cves),
        "total_cves_requested": len(cve_list),
        "total_signatures_matched": sum(len(v) for v in matched_cves.values()),
        "unique_signatures": len(unique_sig_ids),
    }


_IP_RE = __import__("re").compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def tag_vm_by_ip(url: str, username: str, password: str, ip_address: str, cve_list: list, extra_tags: list = None):
    url = _clean_url(url)

    def _policy_search(ip):
        """Search policy index for VirtualMachine by IP — works across all NSX 9.x versions."""
        query = urllib.parse.quote(f"resource_type:VirtualMachine AND ip_addresses:{ip}")
        res = _req(f"{url}{POLICY}/search/query?query={query}&page_size=10",
                   username=username, password=password)
        results = (res or {}).get("results", [])
        return results[0].get("external_id") if results else None

    def _vif_pagination(ip):
        """Walk all fabric VIFs and inspect ip_address_info — slower but broadly compatible."""
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

    vm_id = _policy_search(ip_address) if is_ip else None
    if not vm_id:
        vm_id = _vif_pagination(ip_address)
    if not vm_id and short_name:
        vm_id = _name_search(short_name)

    if not vm_id:
        print(f"Could not find VM in NSX inventory for {ip_address}")
        return {"tagged": False, "ip": ip_address}

    print(f"Found VM {vm_id} for {ip_address}. Applying tags...")

    tags = [{"scope": "Vulnerability", "tag": cve} for cve in cve_list[:30]]
    if extra_tags:
        tags.extend(extra_tags)
    _req(f"{url}/api/v1/fabric/virtual-machines?action=add_tags",
         method="POST", body={"external_id": vm_id, "tags": tags},
         username=username, password=password)
    print(f"Successfully tagged VM {vm_id} with {cve_list}")
    return {"tagged": True, "ip": ip_address, "vm_id": vm_id}


def create_ip_group(url: str, username: str, password: str,
                    group_id: str, group_name: str, ip_list: list) -> dict:
    """Create/update a static IP-address-based NSX group."""
    url = _clean_url(url)
    body = {
        "display_name": group_name,
        "expression": [{
            "resource_type": "IPAddressExpression",
            "ip_addresses": ip_list,
        }],
    }
    endpoint = f"{url}{POLICY}/infra/domains/default/groups/{group_id}"
    try:
        _req(endpoint, username=username, password=password)
        method = "PATCH"
    except Exception:
        method = "PUT"
    _req(endpoint, method=method, body=body, username=username, password=password)
    return {
        "group_id": group_id,
        "group_path": f"/infra/domains/default/groups/{group_id}",
        "group_name": group_name,
    }


def create_group(url: str, username: str, password: str, run_id: str, cve_list: list,
                 group_name: str = "", port: str = "", proto: str = "") -> dict:
    """Create/update a tag-based NSX group.

    Without port: expression is (CVE-1 OR CVE-2 ...) matching Vulnerability scope.
    With port: expression is (CVE-1 OR CVE-2 ...) AND DestPort:TCPxxx using a
    NestedExpression so the OR precedence is correct before the AND.
    VMs must be tagged with both Vulnerability:CVE-xxx and DestPort:TCPxxx tags
    for per-port group membership to work.
    """
    url = _clean_url(url)
    if not group_name:
        group_name = cve_list[0] if len(cve_list) == 1 else "VirtualPatch-Multiple-CVEs"
    cve_slug = "-".join(sorted(c.upper().replace("CVE-", "") for c in cve_list))
    proto_upper = (proto or "TCP").upper()
    # Support comma-delimited ports: "80,443" → ["80", "443"]
    port_list = [p.strip() for p in port.split(",") if p.strip()] if port else []
    port_slug = ("_" + "-".join(f"{proto_upper}{p}" for p in port_list)) if port_list else ""
    group_id = f"virtualPatch-{cve_slug}{port_slug}"

    # Build CVE OR conditions (used when no port is given)
    cve_conditions = []
    for i, cve in enumerate(cve_list):
        cve_conditions.append({
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Tag",
            "operator": "EQUALS",
            "value": f"Vulnerability|{cve}",
        })
        if i < len(cve_list) - 1:
            cve_conditions.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})

    if port_list:
        # NSX only allows AND inside NestedExpression; flat arrays use AND-before-OR.
        # Solution: one NestedExpression per (CVE × port) pair, OR'd at the top level.
        # Max 5 criteria supported by NSX — (CVEs × ports) must stay ≤ 5.
        pairs = [(cve, f"{proto_upper}{p}") for cve in cve_list for p in port_list]
        if len(pairs) == 1:
            # Single CVE + single port: flat AND, no nesting needed
            cve, dest_port_tag = pairs[0]
            expressions = [
                {
                    "resource_type": "Condition",
                    "member_type": "VirtualMachine",
                    "key": "Tag",
                    "operator": "EQUALS",
                    "value": f"Vulnerability|{cve}",
                },
                {"resource_type": "ConjunctionOperator", "conjunction_operator": "AND"},
                {
                    "resource_type": "Condition",
                    "member_type": "VirtualMachine",
                    "key": "Tag",
                    "operator": "EQUALS",
                    "value": f"DestPort|{dest_port_tag}",
                },
            ]
        else:
            expressions = []
            for i, (cve, dest_port_tag) in enumerate(pairs):
                if i > 0:
                    expressions.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})
                expressions.append({
                    "resource_type": "NestedExpression",
                    "expressions": [
                        {
                            "resource_type": "Condition",
                            "member_type": "VirtualMachine",
                            "key": "Tag",
                            "operator": "EQUALS",
                            "value": f"Vulnerability|{cve}",
                        },
                        {"resource_type": "ConjunctionOperator", "conjunction_operator": "AND"},
                        {
                            "resource_type": "Condition",
                            "member_type": "VirtualMachine",
                            "key": "Tag",
                            "operator": "EQUALS",
                            "value": f"DestPort|{dest_port_tag}",
                        },
                    ],
                })
    else:
        expressions = cve_conditions

    body = {
        "display_name": group_name,
        "expression": expressions,
    }
    endpoint = f"{url}{POLICY}/infra/domains/default/groups/{group_id}"
    # NSX Policy PATCH is a declarative upsert — creates or fully replaces.
    # PUT rejects existing objects with 400, so always use PATCH.
    _req(endpoint, method="PATCH", body=body, username=username, password=password)
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
        # Modern NSX (9.1+): include all system signatures at all severities, then
        # explicitly enable and set action for each CVE-matched signature via overrides.
        # NSX's CVE criteria filter does not reliably match non-standard CVE numbers
        # (e.g. 6-digit NNNNNNs like 2026-109618), so we skip criteria and use the
        # IDS rule's scope (destination groups) to provide targeting instead.
        profile_id = _profile_id_for_cves(list(matched_cves.keys()))

        seen: set = set()
        overrides = []
        for sigs in matched_cves.values():
            for sig in sigs:
                sid = sig.get("sig_id")
                if not sid or sid in seen:
                    continue
                seen.add(sid)
                if rule_action == "DETECT_PREVENT" and _should_escalate(sig.get("action", "")):
                    overrides.append({"signature_id": sid, "enable": True, "action": "REJECT"})
                # else: include_system_signatures:true already enables at default action; no override needed

        profile_endpoint = f"{url}{POLICY}/infra/settings/firewall/security/intrusion-services/profiles/{profile_id}"
        existing_overrides_by_sid: dict = {}
        method = "PUT"
        try:
            existing = _req(profile_endpoint, username=username, password=password)
            method = "PATCH"
            # Preserve existing overrides (e.g. manually added sigs lacking CVE enrichment)
            for entry in existing.get("overridden_signatures", []):
                sid = str(entry.get("signature_id", ""))
                if sid:
                    existing_overrides_by_sid[sid] = entry
            print(f"Profile {profile_id} exists ({len(existing_overrides_by_sid)} existing overrides) — merging")
        except Exception:
            print(f"Profile {profile_id} not found — creating")

        # Our CVE-derived overrides take precedence; unknown existing ones are kept as-is
        merged: dict = {**existing_overrides_by_sid}
        for o in overrides:
            merged[str(o["signature_id"])] = o

        body = {
            "display_name": profile_name,
            "criteria": [],
            "overridden_signatures": list(merged.values()),
            "profile_severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SUSPICIOUS"],
            "include_system_signatures": True,
            "include_custom_signatures": False,
        }
        _req(profile_endpoint, method=method, body=body, username=username, password=password)
        return {
            "profile_id": profile_id,
            "profile_path": f"/infra/settings/firewall/security/intrusion-services/profiles/{profile_id}",
            "signatures_applied": len(cve_sig_ids),
            "new_exclusions_added": 0,
        }


# Well-known NSX built-in service IDs for common single ports
_BUILTIN_SERVICES = {
    ("TCP", "80"):   "HTTP",
    ("TCP", "443"):  "HTTPS",
    ("TCP", "8080"): "HTTP-ALT",
    ("TCP", "8443"): "HTTPS-ALT",
    ("TCP", "22"):   "SSH",
    ("TCP", "3389"): "RDP",
    ("TCP", "3306"): "MySQL",
    ("TCP", "1433"): "MS-SQL",
    ("TCP", "53"):   "DNS",
    ("UDP", "53"):   "DNS",
}


def _resolve_service(url: str, username: str, password: str,
                     protocol: str, ports: list) -> str:
    """Return the path of an NSX service matching protocol/ports.

    For a single port, tries the well-known built-in service ID first (fast
    direct GET), then falls back to a full pagination search, then creates a
    custom vp- service. For multiple ports, always creates/updates a custom
    vp- service with all ports in one L4 entry.
    """
    proto = protocol.upper()
    port_strs = [str(p) for p in ports]

    if len(port_strs) == 1:
        port_str = port_strs[0]

        # Fast path: try well-known built-in service ID directly
        builtin_id = _BUILTIN_SERVICES.get((proto, port_str))
        if builtin_id:
            try:
                svc = _req(f"{url}{POLICY}/infra/services/{builtin_id}",
                           username=username, password=password)
                for entry in svc.get("service_entries", []):
                    if (entry.get("resource_type") == "L4PortSetServiceEntry"
                            and entry.get("l4_protocol", "").upper() == proto
                            and port_str in [str(p) for p in entry.get("destination_ports", [])]):
                        path = svc.get("path") or f"/infra/services/{builtin_id}"
                        print(f"Using built-in service {builtin_id} for {proto}:{port_str}")
                        return path
            except Exception:
                pass  # not found or doesn't match — fall through

        # Slow path: paginate through all services
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
                        print(f"Found existing service {svc['id']} for {proto}:{port_str}")
                        return path
            cursor = (res or {}).get("cursor")
            if not cursor:
                break

    # Multiple ports, or no match found — create/update a custom vp- service
    try:
        slug = "-".join(sorted(port_strs, key=int))
    except ValueError:
        slug = "-".join(sorted(port_strs))
    service_id = f"vp-{proto.lower()}-{slug}"
    display = f"{proto} {', '.join(sorted(port_strs, key=lambda p: int(p) if p.isdigit() else 0))}"
    print(f"Creating/updating service {service_id} ({display})")
    _req(f"{url}{POLICY}/infra/services/{service_id}",
         method="PATCH", username=username, password=password, body={
             "display_name": display,
             "service_entries": [{
                 "id": f"ports-{slug}",
                 "resource_type": "L4PortSetServiceEntry",
                 "l4_protocol": proto,
                 "destination_ports": sorted(port_strs, key=lambda p: int(p) if p.isdigit() else 0),
             }],
         })
    return f"/infra/services/{service_id}"


def create_policy(
    url: str, username: str, password: str,
    run_id: str, rule_name: str, profile_path: str, group_path: str = "",
    category: str = "EmergencyThreatRules", policy_name: str = "Virtual Patches",
    rule_action: str = "DETECT_PREVENT", nsx_version: str = "",
    rule_tag: str = "", protocol: str = "", ports: list = None,
    group_paths: list = None,
) -> dict:
    """Create or update one IDS rule in the Virtual Patches policy.

    group_paths overrides group_path when provided — use it to pass multiple
    destination groups (e.g. one per CVE) into a single rule.
    """
    url = _clean_url(url)
    policy_id = "Virtual-Patches-Policy"
    sequence_number = 1

    dest_groups = group_paths if group_paths else ([group_path] if group_path else ["ANY"])

    endpoint = f"{url}{POLICY}/infra/domains/default/intrusion-service-policies/{policy_id}"
    try:
        existing_policy = _req(endpoint, username=username, password=password)
        rules = existing_policy.get("rules", [])
        method = "PATCH"
    except Exception:
        rules = []
        method = "PUT"

    if protocol and ports:
        service_path = _resolve_service(url, username, password, protocol, ports)
        services = [service_path]
    else:
        services = ["ANY"]

    # Rule ID: keyed on port so one rule per port coexists in the policy.
    # Use the first group path as a stable anchor, then append the port slug.
    rule_id = "rule-" + dest_groups[0].split("/")[-1]
    if ports:
        try:
            slug = "-".join(sorted(ports, key=int))
        except (ValueError, TypeError):
            slug = "-".join(sorted(str(p) for p in ports))
        rule_id += f"-{(protocol or 'tcp').lower()}-{slug}"

    new_rule = {
        "id": rule_id,
        "display_name": rule_name,
        "ids_profiles": [profile_path],
        "source_groups": ["ANY"],
        "destination_groups": dest_groups,
        "services": services,
        "action": rule_action,
        "direction": "IN",
        "logged": True,
        "scope": dest_groups,
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
