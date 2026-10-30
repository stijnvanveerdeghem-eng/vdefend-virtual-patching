# vDefend IDPS Virtual Patching Automation

**GitHub:** [stijnvanveerdeghem-eng/vdefend-virtual-patching](https://github.com/stijnvanveerdeghem-eng/vdefend-virtual-patching)

This repository contains a standalone, Python-based automation tool that demonstrates the power of **vDefend IDPS** for virtual patching. It integrates with Nessus vulnerability scans to automatically deploy targeted IDPS signatures to protect vulnerable workloads.

Included in this repository is the shareable code for the tool, as well as a recorded demo video showing the end-to-end workflow.

## Features

1. **Vulnerability Ingestion**: Connects to Nessus Essentials via API to extract completed vulnerability scans.
2. **CVE Parsing**: Parses the scan results to identify Critical and High severity CVEs affecting specific workloads.
3. **NSX Signature Mapping**: Queries the vDefend IDPS signature database to find exact matches for the detected CVEs.
4. **Dynamic Grouping & Tagging**: Automatically applies NSX tags to vulnerable workloads and creates dynamic Security Groups.
5. **Automated Policy Deployment**: Generates a custom IDPS profile containing only the necessary signatures and deploys a distributed IDPS policy to protect the vulnerable workloads.

## Running the Tool

This tool is built using only the Python standard library, meaning **no `pip install` is required**.

```bash
python3 app.py
```

Then open `http://localhost:5002` in your web browser.

## Refreshing Profiles After Signature Updates

On NSX 9.0.x, virtual patch profiles work by including all signatures at the
target severity (e.g. MEDIUM) and individually disabling every signature except
the CVE you are patching.  When NSX downloads a signature update, newly added
signatures at that severity are not yet in the exclusion list and become active
in the profile.  Run `refresh_profiles.py` after each signature update to patch
them in incrementally — only new signatures are written, existing overrides are
left untouched.

The script reads `NSX_FQDN` and `PASSWORD` directly from `.credentials` (via
the symlink to the shared labadmin credentials file) — no environment setup or
wrapper script required.

### One-off refresh

```bash
cd /home/rpletka/labadmin/vdefend-virtual-patching
python3 refresh_profiles.py
```

### Cron setup

Add to crontab (`crontab -e`):

```
# Refresh vDefend virtual patch profiles daily at 02:00 UTC
0 2 * * * cd /home/rpletka/labadmin/vdefend-virtual-patching && python3 refresh_profiles.py >> /var/log/vdefend-refresh.log 2>&1
```

The script exits 0 when all profiles are up to date and 1 if any profile
errored, so standard cron alerting will catch failures.  Profile state is
persisted in `profiles_state.json` (written by the web UI on each deploy).

## Demo Video

Check out the included `vdefend_virtual_patching_demo.mp4` for a full walkthrough of the tool in action, demonstrating how it automatically protects a workload against a critical vulnerability.
