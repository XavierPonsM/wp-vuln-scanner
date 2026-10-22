"""
Remediation guidance per detected component.
Keys match component names used in the scan (or "_name" for generic topics).
"""

REMEDIATION_GUIDE: dict = {
    "php": {
        "title": "Upgrade PHP to a supported release",
        "steps": [
            "PHP 7.3 reached End-of-Life in December 2020 — no security patches are issued.",
            "Target <strong>PHP 8.2 or 8.3</strong> (current LTS). PHP 8.1 is the bare minimum.",
            "On Plesk: go to <em>Tools &amp; Settings → PHP Settings</em> and switch the PHP handler to 8.2 FPM.",
            "Test the WordPress site and all plugins for PHP 8.x compatibility before switching in production.",
            "Enable <code>opcache</code> for performance gains alongside the upgrade.",
        ],
        "refs": [
            "https://www.php.net/supported-versions.php",
            "https://www.plesk.com/blog/various/php-versions/",
        ],
    },
    "wordpress": {
        "title": "Keep WordPress core up to date",
        "steps": [
            "Enable automatic background updates for minor releases: add <code>define('WP_AUTO_UPDATE_CORE', true);</code> to wp-config.php.",
            "Monitor <a href='https://wordpress.org/news/category/releases/'>wordpress.org/news</a> for security releases.",
            "Restrict <strong>wp-json/wp/v2/users</strong> if user enumeration is not needed (add a rewrite rule or use a plugin like Perfmatters).",
            "Harden wp-config.php: move it above webroot or restrict read permissions to the web-server user only.",
            "Remove the WordPress version from the HTML source (<code>remove_action('wp_head','wp_generator');</code>).",
        ],
        "refs": ["https://wordpress.org/documentation/article/hardening-wordpress/"],
    },
    "jetpack": {
        "title": "Update Jetpack — multiple CVEs in 9.x",
        "steps": [
            "Jetpack 9.0.5 is severely outdated (current: 14.x). Update immediately via the WP admin Plugins page.",
            "If Automattic.com connectivity is not needed, consider replacing Jetpack with lighter alternatives (WP Statistics, Really Simple SSL, etc.).",
            "After updating, audit which Jetpack modules are active and deactivate unused ones to reduce attack surface.",
            "Review Jetpack's security log under <em>Jetpack → Security</em> for any past intrusion attempts.",
        ],
        "refs": [
            "https://jetpack.com/changelog/",
            "https://wpscan.com/plugins/jetpack",
        ],
    },
    "woocommerce": {
        "title": "Update WooCommerce — critical patches since 4.6.x",
        "steps": [
            "WooCommerce 4.6.3 is multiple major versions behind (current: 9.x). Update in a staging environment first.",
            "Before updating, back up the database and <code>wp-content/</code> directory.",
            "Verify all WooCommerce extensions/add-ons are compatible with the target version.",
            "Enable PCI-DSS relevant headers: Content-Security-Policy, X-Content-Type-Options.",
            "Restrict order and customer data endpoints if the REST API is not used externally.",
        ],
        "refs": [
            "https://developer.woocommerce.com/changelog/",
            "https://woocommerce.com/document/update-woocommerce/",
        ],
    },
    "divi": {
        "title": "Verify and update the Divi theme",
        "steps": [
            "Ensure Divi (Elegant Themes) is set to receive automatic updates via a valid license key.",
            "Go to <em>Divi → Theme Options → Updates</em> and confirm the Elegant Themes username and API key are set.",
            "Keep Divi Builder up to date alongside the theme — they share the same codebase.",
            "Disable Divi's built-in page builder for user roles that don't need it.",
        ],
        "refs": ["https://www.elegantthemes.com/documentation/divi/update-divi/"],
    },
    "_headers": {
        "title": "Add missing security HTTP headers",
        "steps": [
            "Add to the Nginx vhost config: <code>add_header X-Frame-Options SAMEORIGIN;</code>",
            "Add HSTS: <code>add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;</code>",
            "Add: <code>add_header X-Content-Type-Options nosniff;</code>",
            "Add: <code>add_header Referrer-Policy strict-origin-when-cross-origin;</code>",
            "Consider a Content-Security-Policy header — start in report-only mode with Report-URI.",
            "Use <a href='https://securityheaders.com'>securityheaders.com</a> to validate after applying changes.",
        ],
        "refs": [
            "https://owasp.org/www-project-secure-headers/",
            "https://securityheaders.com",
        ],
    },
    "_ssl": {
        "title": "Enforce HTTPS and redirect all HTTP traffic",
        "steps": [
            "In Nginx: add a server block that redirects port 80 → 443 with a 301.",
            "Enable HSTS once HTTPS is fully working (see headers section above).",
            "Set <code>define('FORCE_SSL_ADMIN', true);</code> in wp-config.php.",
            "Check the SSL certificate expiry and ensure auto-renewal is active (Let's Encrypt / Plesk integration).",
        ],
        "refs": [
            "https://letsencrypt.org/",
            "https://docs.plesk.com/en-US/obsidian/customer-guide/ssl-tls-certificates.html",
        ],
    },
}
