"""
Site analysis: DNS resolution, HTTP probing, WordPress fingerprinting,
plugin version detection.
"""

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    raise SystemExit("Run: pip3 install requests beautifulsoup4")

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VulnMapper/1.0)"}

# Plugins actively probed on every scan regardless of HTML presence.
COMMON_PLUGINS: list = [
    "woocommerce", "contact-form-7", "yoast-seo", "wordfence",
    "elementor", "wpforms-lite", "akismet", "jetpack",
    "really-simple-ssl", "updraftplus", "all-in-one-wp-migration",
    "wp-super-cache", "w3-total-cache", "redirection",
    "google-analytics-for-wordpress", "wp-mail-smtp",
    "all-in-one-seo-pack", "shortpixel-image-optimiser",
    "duplicate-post", "classic-editor", "wpml", "polylang",
    "loco-translate", "wp-rocket", "ninja-forms", "gravityforms",
    "advanced-custom-fields", "beaver-builder-lite-version",
    "the-events-calendar", "wp-fastest-cache", "litespeed-cache",
    "rank-math", "seo-by-rank-math", "wpforms", "mailchimp-for-wp",
    "cookie-law-info", "complianz", "wp-gdpr-compliance",
    "wordfence-login-security", "limit-login-attempts-reloaded",
]

# Components tracked by default — versions filled in during the live scan.
KNOWN_COMPONENTS: dict = {
    "php":         {"cpe": "cpe:2.3:a:php:php",                "version": None, "type": "runtime"},
    "wordpress":   {"cpe": "cpe:2.3:a:wordpress:wordpress",    "version": None, "type": "cms"},
    "jetpack":     {"cpe": "cpe:2.3:a:automattic:jetpack",     "version": None, "type": "plugin"},
    "woocommerce": {"cpe": "cpe:2.3:a:woocommerce:woocommerce","version": None, "type": "plugin"},
    "divi":        {"cpe": "cpe:2.3:a:elegantthemes:divi",     "version": None, "type": "theme"},
}


def fetch(url: str, timeout: int = 10) -> Optional[requests.Response]:
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None


def fetch_json(url: str, params: dict = None,
               extra_headers: dict = None) -> Optional[dict]:
    h = {**HEADERS, **(extra_headers or {})}
    try:
        r = requests.get(url, headers=h, params=params, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def resolve_ip(hostname: str) -> list:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(hostname, None)})
    except socket.gaierror as e:
        return [f"Error: {e}"]


def analyse_site(target: str) -> dict:
    """Fetch the target and extract infrastructure + WordPress metadata."""
    parsed   = urlparse(target)
    hostname = parsed.hostname
    info = {
        "target":         target,
        "hostname":       hostname,
        "ips":            resolve_ip(hostname),
        "server":         "unknown",
        "php":            None,
        "powered_by":     None,
        "final_url":      target,
        "status":         None,
        "headers":        {},
        "is_wordpress":   False,
        "wp_version":     None,
        "theme":          None,
        "theme_version":  None,
        "plugins_html":   [],
        "xmlrpc":         False,
        "wpjson":         None,
        "hsts":           False,
        "x_frame":        False,
        "redirect_https": False,
    }

    resp = fetch(target)
    if not resp:
        return info

    h = resp.headers
    info["status"]         = resp.status_code
    info["final_url"]      = resp.url
    info["server"]         = h.get("Server", "unknown")
    info["headers"]        = dict(h)
    info["hsts"]           = bool(h.get("Strict-Transport-Security"))
    info["x_frame"]        = bool(h.get("X-Frame-Options"))
    info["redirect_https"] = resp.url.startswith("https://")

    xpb              = h.get("X-Powered-By", "")
    info["powered_by"] = xpb or None
    php_m = re.search(r"PHP/([\d.]+)", xpb)
    if php_m:
        info["php"] = php_m.group(1)

    body = resp.text
    wp_indicators = ["/wp-content/", "/wp-includes/", 'content="WordPress', "wp-emoji"]
    if any(ind in body for ind in wp_indicators):
        info["is_wordpress"] = True

    m = re.search(r'content="WordPress\s+([\d.]+)"', body)
    if m:
        info["wp_version"] = m.group(1)

    tm = re.search(r'/wp-content/themes/([^/\'"]+)', body)
    if tm:
        theme        = tm.group(1)
        info["theme"] = theme
        r2 = fetch(urljoin(target.rstrip("/") + "/",
                           f"wp-content/themes/{theme}/readme.txt"))
        if r2 and r2.status_code == 200:
            vm = re.search(r"Stable tag:\s*([\S]+)", r2.text, re.IGNORECASE)
            info["theme_version"] = vm.group(1) if vm else None

    info["plugins_html"] = sorted(
        set(re.findall(r'/wp-content/plugins/([^/\'"]+)', body))
    )

    # XML-RPC probe
    rxp = fetch(urljoin(target.rstrip("/") + "/", "xmlrpc.php"))
    info["xmlrpc"] = bool(rxp and rxp.status_code == 200 and "XML-RPC" in rxp.text)

    # WP REST API probe
    rj = fetch(urljoin(target.rstrip("/") + "/", "wp-json/"))
    if rj and rj.status_code == 200:
        try:
            jd = rj.json()
            info["wpjson"] = {
                "name":        jd.get("name"),
                "description": jd.get("description"),
            }
        except Exception:
            pass

    return info


def _probe_plugin(target: str, slug: str) -> Optional[tuple]:
    """Return (slug, version) if the plugin's readme.txt responds with 200."""
    url = urljoin(target.rstrip("/") + "/",
                  f"wp-content/plugins/{slug}/readme.txt")
    r = fetch(url)
    if r and r.status_code == 200:
        m = re.search(r"Stable tag:\s*([\S]+)", r.text, re.IGNORECASE)
        if m:
            return slug, m.group(1)
    return None


def detect_plugin_versions(target: str, extra_slugs: list = None) -> dict:
    """Concurrently probe COMMON_PLUGINS + any extra slugs found in the HTML.

    Returns a dict of {slug: version} for every plugin that responds.
    """
    slugs = list({*COMMON_PLUGINS, *(extra_slugs or [])})
    versions: dict = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_probe_plugin, target, s): s for s in slugs}
        for future in as_completed(futures):
            result = future.result()
            if result:
                slug, ver = result
                versions[slug] = ver
    return versions
