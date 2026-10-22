"""
HTML report generator: takes the scan dict produced by vulns.run_scan()
and returns a self-contained HTML string.
"""

import re

from core.remediations import REMEDIATION_GUIDE
from core.vulns import cvss_to_severity

SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#16a34a",
    "NONE":     "#94a3b8",
}
SEV_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#f0fdf4",
    "NONE":     "#f8fafc",
}


# ── small HTML helpers ────────────────────────────────────────────────────────

def severity_badge(sev: str) -> str:
    c = SEV_COLOR.get(sev, "#94a3b8")
    b = SEV_BG.get(sev, "#f8fafc")
    return (f'<span class="badge" style="color:{c};background:{b};'
            f'border:1px solid {c}30">{sev}</span>')


def cvss_gauge(score) -> str:
    if score is None:
        return '<div class="gauge gauge-none">N/A</div>'
    sev   = cvss_to_severity(score)
    color = SEV_COLOR[sev]
    r     = 20
    circ  = 2 * 3.14159 * r
    dash  = circ * (score / 10)
    return f"""<div class="gauge-wrap">
  <svg viewBox="0 0 50 50" width="54" height="54">
    <circle cx="25" cy="25" r="{r}" fill="none" stroke="#e2e8f0" stroke-width="5"/>
    <circle cx="25" cy="25" r="{r}" fill="none" stroke="{color}" stroke-width="5"
      stroke-dasharray="{dash:.1f} {circ:.1f}"
      stroke-dashoffset="{circ/4:.1f}" stroke-linecap="round"/>
    <text x="25" y="30" text-anchor="middle" font-size="11"
      font-weight="700" fill="{color}">{score:.1f}</text>
  </svg>
</div>"""


def vector_table(vmap: dict) -> str:
    if not vmap:
        return ""
    icon = {"Network (Remote)": "🌐", "Adjacent": "📡", "Local": "💻", "Physical": "🤝"}
    rows = "".join(
        f"<tr><td class='vk'>{k}</td>"
        f"<td class='vv'>{icon.get(v, '')} {v}</td></tr>"
        for k, v in vmap.items()
    )
    return f"<table class='vtable'>{rows}</table>"


# ── CVE card ─────────────────────────────────────────────────────────────────

def cve_card(cve: dict, idx: int, comp_id: str) -> str:
    card_id   = f"cve-{comp_id}-{idx}"
    sev       = cve["severity"]
    col       = SEV_COLOR.get(sev, "#94a3b8")
    desc      = cve["description"].replace("<", "&lt;").replace(">", "&gt;")
    rem       = cve.get("remediation", "Apply the vendor patch.")
    src       = cve.get("source", "NVD")
    src_badge = f'<span class="src-badge src-{src.lower()}">{src}</span>'
    vt        = vector_table(cve.get("vector_map") or {})
    fi        = cve.get("fixed_in")
    fixed_line = (f'<div class="fixed-in">✔ Fixed in version '
                  f'<strong>{fi}</strong></div>') if fi else ""

    return f"""<div class="cve-card" style="border-left:4px solid {col}">
  <div class="cve-header" onclick="toggle('{card_id}')">
    <div class="cve-left">
      {cvss_gauge(cve['score'])}
      <div class="cve-meta">
        <span class="cve-id">
          <a href="{cve['url']}" target="_blank" rel="noopener">{cve['id']}</a>
        </span>
        {severity_badge(sev)}
        {src_badge}
        <span class="pub-date">📅 {cve['published']}</span>
      </div>
    </div>
    <div class="cve-title">{desc[:140]}{'…' if len(desc) > 140 else ''}</div>
    <div class="cve-toggle" id="arrow-{card_id}">▼</div>
  </div>
  <div class="cve-body" id="{card_id}" style="display:none">
    <p class="full-desc">{desc}</p>
    {fixed_line}
    {f'<div class="vec-label">CVSS Vector: <code>{cve["vector"]}</code></div>' if cve.get("vector") else ""}
    {vt}
    <div class="rem-box">
      <span class="rem-title">🔧 Remediation</span>
      <p>{rem}</p>
    </div>
  </div>
</div>"""


# ── component section ─────────────────────────────────────────────────────────

def component_section(name: str, data: dict) -> str:
    counts  = data["counts"]
    version = data["version"]
    ctype   = (data.get("type") or "").upper()
    vulns   = data["vulns"]
    comp_id = re.sub(r"[^a-z0-9]", "-", name.lower())

    total = counts["total"] or 1
    bars  = "".join(
        f'<div class="bar-seg" style="width:{counts[k] / total * 100:.0f}%;'
        f'background:{SEV_COLOR[s]}" title="{s}: {counts[k]}"></div>'
        for s, k in [("CRITICAL","critical"),("HIGH","high"),
                     ("MEDIUM","medium"),("LOW","low")]
        if counts[k]
    )

    guide     = REMEDIATION_GUIDE.get(name) or REMEDIATION_GUIDE.get("_" + name)
    guide_html = ""
    if guide:
        steps = "".join(f"<li>{s}</li>" for s in guide["steps"])
        refs  = "".join(
            f'<a href="{r}" target="_blank" rel="noopener">{r}</a>'
            for r in guide.get("refs", [])
        )
        guide_html = f"""<div class="guide-box">
  <div class="guide-title">📋 {guide['title']}</div>
  <ol class="guide-steps">{steps}</ol>
  {'<div class="guide-refs">References: ' + refs + '</div>' if refs else ''}
</div>"""

    cards = "\n".join(cve_card(v, i, comp_id) for i, v in enumerate(vulns))
    if not cards:
        cards = '<p class="no-vulns">✅ No CVEs found in NVD for this version.</p>'

    badge_row = "".join(
        f'<span class="count-pill" style="background:{SEV_COLOR[s]}">'
        f'{counts[k]} {s[0]}</span>'
        for s, k in [("CRITICAL","critical"),("HIGH","high"),
                     ("MEDIUM","medium"),("LOW","low")]
        if counts[k]
    )

    return f"""<section class="comp-section" id="comp-{comp_id}">
  <div class="comp-header">
    <div class="comp-title-row">
      <h2 class="comp-name">{name}</h2>
      <span class="comp-version">v{version}</span>
      <span class="comp-type">{ctype}</span>
      <div class="count-pills">{badge_row}</div>
    </div>
    <div class="bar-track">{bars}<div class="bar-bg"></div></div>
  </div>
  {guide_html}
  <div class="cve-list">{cards}</div>
</section>"""


# ── summary helpers ───────────────────────────────────────────────────────────

def overview_card(label: str, value, color: str) -> str:
    return f"""<div class="ov-card" style="border-top:4px solid {color}">
  <div class="ov-num" style="color:{color}">{value}</div>
  <div class="ov-label">{label}</div>
</div>"""


def risk_score(summary: dict) -> tuple:
    """Return (score 0–100, label, color)."""
    s = min(summary["critical"] * 10 + summary["high"] * 4 + summary["medium"], 100)
    if s >= 60: return s, "CRITICAL", SEV_COLOR["CRITICAL"]
    if s >= 30: return s, "HIGH",     SEV_COLOR["HIGH"]
    if s >= 10: return s, "MEDIUM",   SEV_COLOR["MEDIUM"]
    return s, "LOW", SEV_COLOR["LOW"]


def infra_rows(site: dict) -> str:
    rows = [
        ("IP Address(es)",  ", ".join(site.get("ips") or [])),
        ("Server",          site.get("server") or "unknown"),
        ("PHP Version",     site.get("php") or "hidden"),
        ("Powered By",      site.get("powered_by") or "—"),
        ("Final URL",       site.get("final_url") or "—"),
        ("HTTP Status",     str(site.get("status") or "—")),
        ("WP Version",      site.get("wp_version") or "—"),
        ("Active Theme",    (site.get("theme") or "—") +
                            (f" v{site['theme_version']}" if site.get("theme_version") else "")),
        ("XML-RPC",         "⚠️ Enabled" if site.get("xmlrpc") else "✅ Disabled"),
        ("WP REST API",     f"⚠️ Exposed — {site['wpjson']['name']}"
                            if site.get("wpjson") else "Not detected"),
        ("HSTS Header",     "✅ Present" if site.get("hsts")    else "❌ Missing"),
        ("X-Frame-Options", "✅ Present" if site.get("x_frame") else "❌ Missing"),
        ("HTTPS Redirect",  "✅ Yes"     if site.get("redirect_https") else "❌ No"),
    ]
    return "".join(
        f'<tr class="{"row-warn" if "⚠️" in v or "❌" in v else ""}">'
        f'<td class="ik">{k}</td><td class="iv">{v}</td></tr>'
        for k, v in rows
    )


def toc_links(components: dict) -> str:
    def sort_key(item):
        c = item[1]["counts"]
        return c["critical"] * 100 + c["high"]

    links = []
    for name, data in sorted(components.items(), key=sort_key, reverse=True):
        cid   = re.sub(r"[^a-z0-9]", "-", name.lower())
        c     = data["counts"]
        pills = "".join(
            f'<span style="color:{SEV_COLOR[sc]};font-weight:700">{c[k]}{s}</span> '
            for s, k, sc in [("C","critical","CRITICAL"),
                              ("H","high","HIGH"),
                              ("M","medium","MEDIUM")]
            if c[k]
        )
        links.append(
            f'<a href="#comp-{cid}" class="toc-link">'
            f'{name} <span class="toc-ver">v{data["version"]}</span>'
            f'<span class="toc-pills">{pills}</span></a>'
        )
    return "\n".join(links)


def extra_remediations() -> str:
    out = ""
    for key in ("_headers", "_ssl"):
        g     = REMEDIATION_GUIDE[key]
        steps = "".join(f"<li>{s}</li>" for s in g["steps"])
        refs  = "".join(
            f'<a href="{r}" target="_blank" rel="noopener">{r}</a>'
            for r in g.get("refs", [])
        )
        out += f"""<div class="extra-guide">
  <h3>🔒 {g['title']}</h3>
  <ol>{steps}</ol>
  {'<p class="guide-refs">References: ' + refs + '</p>' if refs else ''}
</div>"""
    return out


# ── main HTML builder ─────────────────────────────────────────────────────────

def generate_html(scan: dict) -> str:
    site     = scan["site"]
    comps    = scan["components"]
    summary  = scan["summary"]
    gen      = scan["generated"]
    hostname = site.get("hostname", "unknown")

    rs, rl, rc = risk_score(summary)

    sorted_comps = sorted(
        comps.items(),
        key=lambda x: (x[1]["counts"]["critical"] * 1000
                       + x[1]["counts"]["high"] * 10
                       + x[1]["counts"]["total"]),
        reverse=True,
    )
    comp_sections = "\n".join(component_section(n, d) for n, d in sorted_comps)

    has_wpscan = any(
        v.get("source") == "WPScan"
        for comp in comps.values()
        for v in comp.get("vulns", [])
    )
    src_label = "NIST NVD" + (" + WPScan" if has_wpscan else "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — {hostname}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#f1f5f9;color:#1e293b;line-height:1.6;font-size:15px}}
a{{color:#2563eb;text-decoration:none}}a:hover{{text-decoration:underline}}
code{{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:.85em;color:#c026d3}}
.page{{max-width:1100px;margin:0 auto;padding:24px 16px}}
.two-col{{display:grid;grid-template-columns:260px 1fr;gap:24px;align-items:start}}
@media(max-width:768px){{.two-col{{grid-template-columns:1fr}}}}
.report-header{{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);
               color:#fff;padding:36px 40px;border-radius:16px;margin-bottom:24px}}
.report-header h1{{font-size:1.8rem;font-weight:700;letter-spacing:-.5px}}
.report-header .sub{{opacity:.7;margin-top:6px;font-size:.9rem}}
.header-meta{{display:flex;gap:32px;margin-top:20px;flex-wrap:wrap}}
.header-meta span{{font-size:.85rem;opacity:.8}}
.header-meta strong{{color:#fff;opacity:1}}
.risk-hero{{text-align:center;padding:20px}}
.risk-num{{font-size:3.5rem;font-weight:800;line-height:1}}
.risk-label{{font-size:1.1rem;font-weight:600;margin-top:4px;letter-spacing:1px}}
.risk-sub{{font-size:.8rem;color:#64748b;margin-top:8px}}
.ov-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}}
@media(max-width:600px){{.ov-grid{{grid-template-columns:repeat(2,1fr)}}}}
.ov-card{{background:#fff;border-radius:12px;padding:20px 16px;text-align:center;
          box-shadow:0 1px 4px rgba(0,0,0,.06)}}
.ov-num{{font-size:2.4rem;font-weight:800;line-height:1}}
.ov-label{{font-size:.78rem;color:#64748b;text-transform:uppercase;letter-spacing:.6px;margin-top:4px}}
.sidebar{{position:sticky;top:24px}}
.sidebar-card{{background:#fff;border-radius:12px;padding:20px;
              box-shadow:0 1px 4px rgba(0,0,0,.06);margin-bottom:16px}}
.sidebar-card h3{{font-size:.8rem;text-transform:uppercase;letter-spacing:.8px;
                  color:#64748b;margin-bottom:12px}}
.toc-link{{display:flex;justify-content:space-between;align-items:center;
           padding:7px 10px;border-radius:7px;font-size:.88rem;
           color:#1e293b;margin-bottom:3px;transition:background .15s}}
.toc-link:hover{{background:#f1f5f9;text-decoration:none}}
.toc-ver{{font-size:.75rem;color:#94a3b8;margin-left:4px}}
.toc-pills{{font-size:.78rem;margin-left:auto;padding-left:8px}}
.panel{{background:#fff;border-radius:12px;padding:24px;
        box-shadow:0 1px 4px rgba(0,0,0,.06);margin-bottom:20px}}
.panel h2{{font-size:1.1rem;font-weight:700;margin-bottom:14px;color:#0f172a}}
.infra-table{{width:100%;border-collapse:collapse;font-size:.88rem}}
.infra-table td{{padding:7px 10px;border-bottom:1px solid #f1f5f9}}
.ik{{color:#64748b;width:160px;white-space:nowrap}}
.iv{{font-weight:500}}
.row-warn .iv{{color:#dc2626}}
.comp-section{{background:#fff;border-radius:12px;
              box-shadow:0 1px 4px rgba(0,0,0,.06);margin-bottom:24px;overflow:hidden}}
.comp-header{{padding:20px 24px;border-bottom:1px solid #f1f5f9}}
.comp-title-row{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}}
.comp-name{{font-size:1.2rem;font-weight:700;color:#0f172a}}
.comp-version{{font-size:.82rem;background:#f1f5f9;color:#475569;padding:2px 8px;border-radius:20px}}
.comp-type{{font-size:.72rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.6px}}
.count-pills{{display:flex;gap:6px;margin-left:auto}}
.count-pill{{padding:2px 10px;border-radius:20px;color:#fff;font-size:.78rem;font-weight:700}}
.bar-track{{height:6px;background:#f1f5f9;border-radius:3px;display:flex;overflow:hidden;margin-top:6px}}
.bar-seg{{height:100%}}
.guide-box{{margin:0;padding:20px 24px;background:#f8fafc;border-bottom:1px solid #e2e8f0}}
.guide-title{{font-weight:700;font-size:.95rem;margin-bottom:10px;color:#0f172a}}
.guide-steps{{padding-left:20px;font-size:.88rem;color:#334155}}
.guide-steps li{{margin-bottom:6px}}
.guide-refs{{font-size:.78rem;color:#64748b;margin-top:10px}}
.guide-refs a{{margin-right:12px}}
.cve-list{{padding:12px 16px}}
.no-vulns{{text-align:center;padding:20px;color:#64748b;font-size:.9rem}}
.cve-card{{border-radius:8px;margin-bottom:8px;background:#fafafa;overflow:hidden}}
.cve-header{{display:flex;align-items:center;gap:12px;padding:12px 14px;cursor:pointer;
             transition:background .15s;flex-wrap:wrap}}
.cve-header:hover{{background:#f1f5f9}}
.cve-left{{display:flex;align-items:center;gap:10px;flex-shrink:0}}
.cve-meta{{display:flex;flex-direction:column;gap:3px}}
.cve-id{{font-size:.9rem;font-weight:700}}
.cve-id a{{color:#1e293b}}
.pub-date{{font-size:.75rem;color:#94a3b8}}
.cve-title{{flex:1;font-size:.85rem;color:#334155;min-width:0}}
.cve-toggle{{color:#94a3b8;font-size:.8rem;flex-shrink:0;transition:transform .2s}}
.cve-body{{padding:0 16px 16px;border-top:1px solid #e2e8f0;background:#fff}}
.full-desc{{margin-top:12px;font-size:.88rem;color:#334155;line-height:1.6}}
.fixed-in{{margin-top:8px;font-size:.85rem;color:#16a34a}}
.vec-label{{margin-top:10px;font-size:.8rem;color:#64748b}}
.vtable{{margin-top:6px;width:100%;border-collapse:collapse;font-size:.82rem}}
.vtable td{{padding:4px 8px;border-bottom:1px solid #f1f5f9}}
.vk{{color:#64748b;width:160px}}
.vv{{font-weight:500}}
.rem-box{{margin-top:14px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:12px 14px}}
.rem-title{{font-weight:700;font-size:.85rem;color:#1d4ed8;display:block;margin-bottom:4px}}
.rem-box p{{font-size:.85rem;color:#1e3a8a}}
.badge{{font-size:.72rem;font-weight:700;padding:2px 8px;border-radius:20px;
        letter-spacing:.3px;text-transform:uppercase}}
.src-badge{{font-size:.68rem;padding:1px 6px;border-radius:10px;
            font-weight:600;text-transform:uppercase;letter-spacing:.4px}}
.src-nvd{{background:#dbeafe;color:#1d4ed8}}
.src-wpscan{{background:#fce7f3;color:#be185d}}
.gauge-wrap svg{{display:block}}
.extra-guide{{margin-bottom:20px}}
.extra-guide h3{{font-size:1rem;font-weight:700;margin-bottom:10px;color:#0f172a}}
.extra-guide ol{{padding-left:20px;font-size:.88rem;color:#334155}}
.extra-guide li{{margin-bottom:6px}}
.extra-guide p{{font-size:.78rem;color:#64748b;margin-top:8px}}
.footer{{text-align:center;color:#94a3b8;font-size:.8rem;padding:30px 0 10px}}
@media print{{
  body{{background:#fff}}
  .sidebar{{display:none}}
  .two-col{{grid-template-columns:1fr}}
  .cve-body{{display:block!important}}
  .cve-toggle{{display:none}}
}}
</style>
</head>
<body>
<div class="page">

<div class="report-header">
  <h1>🔐 Vulnerability Security Report</h1>
  <div class="sub">Automated scan — for informational purposes only</div>
  <div class="header-meta">
    <span>🎯 Target: <strong>{site.get('final_url', site.get('target'))}</strong></span>
    <span>🖥 Server: <strong>{site.get('server','unknown')}</strong></span>
    <span>📅 Generated: <strong>{gen[:10]}</strong></span>
    <span>🌐 IP: <strong>{', '.join(site.get('ips') or [])}</strong></span>
  </div>
</div>

<div class="ov-grid">
  {overview_card("Total CVEs",    summary['total'],    "#2563eb")}
  {overview_card("Critical",      summary['critical'], SEV_COLOR['CRITICAL'])}
  {overview_card("High",          summary['high'],     SEV_COLOR['HIGH'])}
  {overview_card("Medium",        summary['medium'],   SEV_COLOR['MEDIUM'])}
</div>

<div class="two-col">
  <aside class="sidebar">
    <div class="sidebar-card">
      <div class="risk-hero">
        <div class="risk-num" style="color:{rc}">{rs}</div>
        <div class="risk-label" style="color:{rc}">RISK {rl}</div>
        <div class="risk-sub">Composite score (0–100)</div>
      </div>
    </div>
    <div class="sidebar-card">
      <h3>Components</h3>
      {toc_links(comps)}
    </div>
    <div class="sidebar-card">
      <h3>Scan info</h3>
      <p style="font-size:.8rem;color:#64748b">
        Sources: {src_label}<br>
        NVD rate-limit: 5 req / 30s (no API key)<br><br>
        Free API keys for fuller coverage:<br>
        <a href="https://nvd.nist.gov/developers/request-an-api-key">NVD</a> ·
        <a href="https://wpscan.com/api">WPScan</a>
      </p>
    </div>
  </aside>

  <main>
    <div class="panel">
      <h2>🏗 Infrastructure</h2>
      <table class="infra-table">{infra_rows(site)}</table>
    </div>

    {comp_sections}

    <div class="panel" id="extra-rem">
      <h2>🛡 Additional Hardening</h2>
      {extra_remediations()}
    </div>
  </main>
</div>

<div class="footer">
  Generated by VulnMapper · Data sources: {src_label} ·
  {gen[:10]} · For educational and defensive purposes only.
</div>
</div>

<script>
function toggle(id) {{
  var el = document.getElementById(id);
  var arrow = document.getElementById('arrow-' + id);
  if (el.style.display === 'none') {{
    el.style.display = 'block';
    arrow.style.transform = 'rotate(180deg)';
  }} else {{
    el.style.display = 'none';
    arrow.style.transform = '';
  }}
}}
document.addEventListener('DOMContentLoaded', function() {{
  document.querySelectorAll('.cve-card').forEach(function(card) {{
    var badge = card.querySelector('.badge');
    if (badge && (badge.textContent === 'CRITICAL' || badge.textContent === 'HIGH')) {{
      var body  = card.querySelector('[id^="cve-"]');
      var arrow = card.querySelector('[id^="arrow-"]');
      if (body)  body.style.display = 'block';
      if (arrow) arrow.style.transform = 'rotate(180deg)';
    }}
  }});
}});
</script>
</body>
</html>"""
