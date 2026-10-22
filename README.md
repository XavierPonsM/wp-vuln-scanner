# wp-vuln-scanner

Passive vulnerability assessment for **WordPress** sites. It fingerprints the server and the WordPress stack (core, theme, plugins, PHP), maps every detected version to known CVEs from **NIST NVD** and the **WPScan** database, and produces a self-contained HTML report with a composite risk score, CVSS breakdown and per-component remediation guidance.

Built for quick external exposure reviews of small business websites: run one command and get a report you can hand to a non-technical owner.

## Quick start

```bash
pip install -r requirements.txt
python3 scanner.py example.com
```

```bash
python3 scanner.py https://example.com --wpscan-key <TOKEN>   # richer plugin/theme coverage
python3 scanner.py example.com --out ~/Desktop/report.html    # custom output path
```

The report is saved as `report_<host>_<timestamp>.html` and opened in the browser. Requires Python 3.9+.

## What it checks

| Area | Checks |
|---|---|
| Infrastructure | DNS resolution, web server and PHP version from headers, HTTPS redirect, HSTS, X-Frame-Options |
| WordPress core | Version fingerprinting, active theme and version |
| Attack surface | XML-RPC enabled, REST API user enumeration (`/wp-json/wp/v2/users`) |
| Plugins | Concurrent probing of 40+ common plugins plus slugs found in the page HTML; version read from each plugin's `readme.txt` |
| Vulnerabilities | NVD lookup by CPE and keyword, WPScan lookup by slug, version-range filtering, de-duplication |

## The report

- Composite **risk score (0–100)** and severity summary (Critical / High / Medium / Low)
- One section per component with an SVG **CVSS gauge** per CVE
- **Attack vector** decoded from the CVSS vector string (AV, AC, PR, UI, S, C/I/A)
- Specific **remediation** steps per component, plus a hardening checklist (HTTP security headers, TLS)
- Print-friendly (`@media print`) so it can be exported to PDF

## How it works

```
scanner.py ── CLI
   │
   ├─ core/analyzer.py     HTTP + DNS fingerprinting, plugin probing (ThreadPoolExecutor)
   ├─ core/vulns.py        NVD 2.0 API + WPScan v3 API → normalized CVE list, CVSS parsing
   ├─ core/remediations.py Remediation guidance per component type
   └─ core/report.py       Self-contained HTML report (no external assets)
```

## Data sources

| Source | Coverage | API key |
|---|---|---|
| [NIST NVD](https://nvd.nist.gov/) | PHP, WordPress core, plugins with a CPE | Optional (public rate limit: 5 requests / 30 s) |
| [WPScan DB](https://wpscan.com/api) | WordPress plugins and themes | Free tier, 50 requests / day |

## Limitations

- Version detection relies on publicly exposed metadata (headers, `readme.txt`, asset query strings); hardened sites will report fewer components.
- A version match is not proof of exploitability — findings should be validated before reporting them as confirmed.
- No authenticated checks and no active exploitation.

## Legal

Use only against systems you own or have **written authorization** to assess. The scanner sends ordinary HTTP requests, but unauthorized security testing may be illegal in your jurisdiction.

## License

MIT
