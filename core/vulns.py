"""
Vulnerability lookups: NIST NVD API + WPScan API.
Includes CVE parsing, CVSS helpers, deduplication, and the main run_scan() orchestrator.
"""

import re
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Optional

from core.analyzer import (
    HEADERS,
    KNOWN_COMPONENTS,
    analyse_site,
    detect_plugin_versions,
    fetch_json,
)

NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WPSCAN_API = "https://wpscan.com/api/v3"


# ── CVSS helpers ─────────────────────────────────────────────────────────────

def _extract_cvss(metrics: dict) -> tuple:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cvss = entries[0].get("cvssData", {})
            return (
                cvss.get("baseScore"),
                cvss.get("baseSeverity", "NONE"),
                cvss.get("vectorString", ""),
            )
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        cvss  = entries[0].get("cvssData", {})
        score = cvss.get("baseScore")
        sev   = ("HIGH"   if score and score >= 7
                 else "MEDIUM" if score and score >= 4
                 else "LOW")
        return score, sev, cvss.get("vectorString", "")
    return None, "NONE", ""


def cvss_to_severity(score) -> str:
    if score is None: return "NONE"
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    return "LOW"


def parse_vector(vector: str) -> dict:
    """Return a human-readable breakdown of a CVSS v3 vector string."""
    if not vector:
        return {}
    av_map = {"N": "Network (Remote)", "A": "Adjacent", "L": "Local", "P": "Physical"}
    ac_map = {"L": "Low",  "H": "High"}
    pr_map = {"N": "None", "L": "Low", "H": "High"}
    ui_map = {"N": "None", "R": "Required"}
    sc_map = {"C": "Changed", "U": "Unchanged"}
    parts  = {}
    for seg in vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/"):
        if ":" in seg:
            k, v = seg.split(":", 1)
            parts[k] = v
    return {
        "Attack Vector":       av_map.get(parts.get("AV", ""), parts.get("AV", "?")),
        "Attack Complexity":   ac_map.get(parts.get("AC", ""), parts.get("AC", "?")),
        "Privileges Required": pr_map.get(parts.get("PR", ""), parts.get("PR", "?")),
        "User Interaction":    ui_map.get(parts.get("UI", ""), parts.get("UI", "?")),
        "Scope":               sc_map.get(parts.get("S",  ""), parts.get("S",  "?")),
    }


def build_remediation(vuln: dict, component: str) -> str:
    if vuln.get("fixed_in") and vuln["fixed_in"] not in ("not fixed", None):
        return (f"Update <strong>{component}</strong> to version "
                f"<strong>{vuln['fixed_in']}</strong> or later.")
    if "AV:N" in vuln.get("vector", ""):
        return ("Apply vendor patch. Until patched: restrict via WAF rules "
                "or IP allowlist and monitor access logs.")
    return ("Apply available vendor patch or remove the component; "
            "isolate the service until resolved.")


# ── NVD ──────────────────────────────────────────────────────────────────────

def _parse_nvd_response(data: dict, component: str) -> list:
    cves = []
    for item in data.get("vulnerabilities", []):
        cve   = item.get("cve", {})
        cid   = cve.get("id", "N/A")
        descs = cve.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"),
                     "No description")
        score, sev, vector = _extract_cvss(cve.get("metrics", {}))
        entry = {
            "id":          cid,
            "description": desc,
            "score":       score,
            "severity":    sev,
            "vector":      vector,
            "vector_map":  parse_vector(vector),
            "published":   cve.get("published", "")[:10],
            "url":         f"https://nvd.nist.gov/vuln/detail/{cid}",
            "fixed_in":    None,
            "source":      "NVD",
        }
        entry["remediation"] = build_remediation(entry, component)
        cves.append(entry)
    cves.sort(key=lambda x: x["score"] or 0, reverse=True)
    return cves


def query_nvd_cpe(cpe: str, version: str, component: str, n: int = 15) -> list:
    full_cpe = f"{cpe}:{version}:*:*:*:*:*:*:*:*"
    data = fetch_json(NVD_API, {"cpeName": full_cpe, "resultsPerPage": n})
    return _parse_nvd_response(data, component) if data else []


def query_nvd_keyword(keyword: str, version: str, component: str,
                      n: int = 20) -> list:
    data = fetch_json(NVD_API, {"keywordSearch": keyword, "resultsPerPage": 50})
    if not data:
        return []
    all_cves = _parse_nvd_response(data, component)
    filtered = [
        c for c in all_cves
        if (version and version in c["description"])  # exact version match
        or (c["score"] and c["score"] >= 4.0)         # any Medium, High or Critical
    ]
    return filtered[:n]


# ── WPScan ───────────────────────────────────────────────────────────────────

def _version_lte(a: str, b: str) -> bool:
    def parts(v):
        try:
            return [int(x) for x in re.split(r"[.\-]", v)[:3]]
        except ValueError:
            return [0, 0, 0]
    return parts(a) <= parts(b)


def _wpscan_entry(v: dict, component: str) -> dict:
    cvss    = v.get("cvss") or {}
    score   = cvss.get("score")
    vector  = cvss.get("vector", "")
    refs    = v.get("references") or {}
    cve_ids = refs.get("cve") or []
    cid     = ("CVE-" + cve_ids[0]) if cve_ids else v.get("id", "WPSCAN")
    urls    = refs.get("url") or [f"https://wpscan.com/vulnerability/{v.get('id')}"]
    fixed   = v.get("fixed_in")
    entry = {
        "id":          cid,
        "description": v.get("title", "")[:300],
        "score":       score,
        "severity":    cvss_to_severity(score),
        "vector":      vector,
        "vector_map":  parse_vector(vector),
        "published":   (v.get("created_at") or "")[:10],
        "url":         urls[0],
        "fixed_in":    fixed,
        "source":      "WPScan",
    }
    entry["remediation"] = build_remediation(entry, component)
    return entry


def query_wpscan_plugin(slug: str, version: str, key: str) -> list:
    data = fetch_json(
        f"{WPSCAN_API}/plugins/{slug}",
        extra_headers={"Authorization": f"Token token={key}"},
    )
    if not data:
        return []
    result = []
    for v in data.get(slug, {}).get("vulnerabilities", []):
        fixed = v.get("fixed_in")
        if fixed and not _version_lte(version, fixed):
            continue
        result.append(_wpscan_entry(v, slug))
    result.sort(key=lambda x: x["score"] or 0, reverse=True)
    return result


def query_wpscan_wordpress(version: str, key: str) -> list:
    slug = version.replace(".", "")
    data = fetch_json(
        f"{WPSCAN_API}/wordpresses/{slug}",
        extra_headers={"Authorization": f"Token token={key}"},
    )
    if not data:
        return []
    result = [_wpscan_entry(v, "wordpress")
              for v in data.get(slug, {}).get("vulnerabilities", [])]
    result.sort(key=lambda x: x["score"] or 0, reverse=True)
    return result


# ── deduplication + per-component fetch ─────────────────────────────────────

def dedupe(cves: list) -> list:
    seen: dict = {}
    for c in cves:
        cid = c["id"]
        if cid not in seen or (c["score"] or 0) > (seen[cid]["score"] or 0):
            seen[cid] = c
    return sorted(seen.values(), key=lambda x: x["score"] or 0, reverse=True)


def get_vulns(name: str, info: dict, wpscan_key: str = "") -> list:
    version = info.get("version")
    if not version:
        return []

    cves: list = []

    if wpscan_key:
        if name == "wordpress":
            cves = query_wpscan_wordpress(version, wpscan_key)
        elif info.get("type") in ("plugin", "theme"):
            cves = query_wpscan_plugin(name, version, wpscan_key)
        time.sleep(0.6)

    if info.get("cpe"):
        nvd = query_nvd_cpe(info["cpe"], version, name)
        time.sleep(1)
        if not nvd:
            nvd = query_nvd_keyword(name, version, name)
            time.sleep(1)
    else:
        nvd = query_nvd_keyword(name, version, name)
        time.sleep(1)

    return dedupe(cves + nvd)


# ── main scan orchestrator ───────────────────────────────────────────────────

def run_scan(target: str, wpscan_key: str = "") -> dict:
    print(f"\n[1/3] Analysing site: {target}")
    site = analyse_site(target)

    components = deepcopy(KNOWN_COMPONENTS)

    # Overwrite with live-detected versions
    if site.get("wp_version"):
        components["wordpress"]["version"] = site["wp_version"]
    if site.get("php"):
        components["php"]["version"] = site["php"]
    if site.get("theme"):
        theme = site["theme"]
        if theme in components:
            components[theme]["version"] = site.get("theme_version")
        else:
            components[theme] = {
                "cpe":     None,
                "version": site.get("theme_version"),
                "type":    "theme",
            }

    print("[2/3] Detecting plugin versions (probing common plugins + HTML refs)...")
    for slug, ver in detect_plugin_versions(target, extra_slugs=site.get("plugins_html", [])).items():
        if slug in components:
            components[slug]["version"] = ver
        else:
            components[slug] = {"cpe": None, "version": ver, "type": "plugin"}

    src_label = "NVD" + (" + WPScan" if wpscan_key else "")
    print(f"[3/3] Querying vulnerability databases ({src_label})...")

    results: dict = {}
    for name, info in components.items():
        ver = info.get("version")
        print(f"      {name} {ver or '(unknown)'}...", end=" ", flush=True)
        if not ver:
            print("skipped")
            continue
        vulns = get_vulns(name, info, wpscan_key)
        counts = {
            "total":    len(vulns),
            "critical": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
            "high":     sum(1 for v in vulns if v["severity"] == "HIGH"),
            "medium":   sum(1 for v in vulns if v["severity"] == "MEDIUM"),
            "low":      sum(1 for v in vulns if v["severity"] == "LOW"),
        }
        results[name] = {
            "type":    info.get("type"),
            "version": ver,
            "cpe":     info.get("cpe"),
            "vulns":   vulns,
            "counts":  counts,
        }
        c = counts
        print(f"{c['total']} CVEs  "
              f"(C:{c['critical']}  H:{c['high']}  M:{c['medium']}  L:{c['low']})")

    summary = {
        "total":    sum(r["counts"]["total"]    for r in results.values()),
        "critical": sum(r["counts"]["critical"] for r in results.values()),
        "high":     sum(r["counts"]["high"]     for r in results.values()),
        "medium":   sum(r["counts"]["medium"]   for r in results.values()),
    }

    return {
        "site":       site,
        "components": results,
        "summary":    summary,
        "generated":  datetime.now(timezone.utc).isoformat(),
    }
