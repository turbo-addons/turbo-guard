=== Turbo Guard – Security & Malware Scanner ===
Contributors: turboaddons
Tags: security, malware, scanner, firewall, 2fa
Requires at least: 5.6
Tested up to: 7.0
Stable tag: 1.1.0
Requires PHP: 7.4
License: GPL-3.0-or-later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

WordPress security plugin with malware scanner, bulk cleanup, firewall, 2FA, vulnerability scanner, file integrity checker, and SEO spam detection. 100% free.

== Description ==

Turbo Guard is a comprehensive, 100% free WordPress security plugin built by a team that manages 40+ WordPress sites. It solves real problems: bulk malware removal, Japanese/Chinese SEO spam cleanup, vulnerability alerts, file integrity monitoring, and live traffic analysis — all with AI-powered guidance that explains what happened and exactly what to do.

= AI Security Advisor =

* After every scan, Turbo Guard AI identifies the attack campaign (Japanese SEO spam, web shell, brute force, database injection)
* Explains in plain English what happened and the business risk
* Provides numbered, step-by-step fix instructions tailored to your specific threats
* Optional OpenAI GPT integration for richer analysis (your own API key)
* Sends email advisory after every scan
* 30-day security score trend chart

= Malware Scanner =

* Full-site scan: PHP, JavaScript, HTML files across wp-content, wp-admin, wp-includes, and WordPress root
* WordPress Core File Manifest check — compares every file in wp-admin and wp-includes against the official WordPress.org checksums API
* Detects 30+ malware patterns: eval+base64, C99/R57/WSO web shells, hidden iframes, pharma spam, code obfuscation
* Detects Japanese, Chinese, and Korean SEO spam text inside PHP files
* Scans the WordPress database (wp_posts, wp_options) for injected content and rogue admin accounts
* PHP-in-uploads detection, PHP-in-core-asset-dirs detection
* Polyglot image backdoor detection — scans image files for embedded PHP
* Smart false-positive prevention: trusted plugins and themes are never flagged for translation text
* Chunked AJAX scanning with live progress bar — handles 10,000+ file sites without timeout

= File Integrity and Change Detection =

* Verifies every WordPress core file against official WordPress.org MD5 checksums
* Detects modified or missing core files
* File watcher runs every 6 hours via WP-Cron — detects new, modified, and deleted files
* Baseline snapshot of all wp-content PHP/JS files with MD5 comparison
* Email alert when new files appear

= One-Click Bulk Malware Cleanup =

* Shows every infected file with path, threat name, severity, and file size
* Select All Critical button — delete multiple files at once
* Automatic ZIP backup before any deletion
* Quarantine option — moves files to a protected directory

= Web Application Firewall =

* Blocks SQL injection, XSS, directory traversal in real time
* Prevents PHP file uploads
* Advanced IP blocking: exact IP, CIDR, ranges, wildcards
* Rate limiting (120 requests per minute per IP)
* Bad bot blocker: blocks 25+ vulnerability scanners and scrapers

= Geo-Fence and Trusted Location =

* Restrict WordPress admin access to specific IP addresses
* Country-based admin lock: only allow access from your country
* Block file uploads from untrusted countries
* One-click trusted IP setup

= Login Security =

* Brute force protection with configurable thresholds and lockout duration
* Login attempt logging with IP, timestamp, and user agent
* Email alert when admin logs in from unrecognised IP
* Auto-blocks attacker IPs in firewall after brute force detection

= Two-Factor Authentication (2FA) =

* TOTP/RFC 6238 — compatible with Google Authenticator, Authy, and all TOTP apps
* QR code setup on user profile page
* Recovery codes (8 single-use)
* Per-user enable/disable

= Vulnerability Scanner =

* Checks all plugins, themes, and WordPress core against WPScan vulnerability database
* CVSS severity scoring, CVE links, version-aware matching
* Works without API key (optional WPScan key for higher limits)
* Email alert when new vulnerabilities are found

= Live Traffic Monitor =

* Logs every HTTP request with bot/human detection
* Identifies 30+ bots including AI crawlers (GPTBot, ClaudeBot, PerplexityBot)
* 24-hour stats: total requests, humans, bots, blocked, errors
* Paginated — handles large traffic volumes
* One-click IP block from any traffic row

= Site Hardening =

* HTTP security headers (X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy)
* Hide WordPress version, block user enumeration
* Optional: disable XML-RPC, restrict REST API, disable file editor

= Google Search Console Cleanup =

* Connects to Google Search Console via OAuth
* Detects indexed SEO spam URLs even when files are deleted from server
* Bulk removal requests with one click
* Sitemap resubmission after cleanup

= Privacy =

Turbo Guard does not send your website files or personal data to any external server. Vulnerability checks use only plugin/theme slugs and versions sent to WPScan public API. GSC integration uses your own Google OAuth credentials. AI analysis (optional OpenAI) sends only anonymised threat type data. No telemetry. No tracking. No account required.

== Installation ==

1. Upload the `turbo-guard` folder to `/wp-content/plugins/`
2. Activate the plugin through the Plugins menu in WordPress
3. Go to Turbo Guard in your admin sidebar
4. Click "Start Full Scan" on the Scanner page
5. Review results and use "Select Critical Only" then "Delete Selected"
6. Check the AI Advisor page for personalised security guidance

== Frequently Asked Questions ==

= Is Turbo Guard completely free? =

Yes. All features are 100% free with no feature limits and no account required.

= Will it slow my website? =

No. Scanning runs via AJAX in your browser. The firewall adds negligible overhead. Live traffic logging uses PHP shutdown function (after the response is sent to the visitor).

= My site shows Japanese spam in Google but files are gone. What do I do? =

Use the GSC Cleanup page. Connect Google Search Console, fetch indexed URLs, and bulk-remove spam entries in one click.

= Does the File Integrity checker work without internet? =

It downloads checksums from the WordPress.org API on first use and caches them for 12 hours, so repeat checks work offline.

= Can I use this on all my sites? =

Yes. Install on each site. No per-site fees or licence limits.

= Does it conflict with other security plugins? =

Turbo Guard whitelists 15+ popular security plugins (Wordfence, Sucuri, MalCare, iThemes, etc.) to prevent false positive detections. It can run alongside other security plugins without issues.

== Screenshots ==

1. Security Dashboard — score, threats, firewall blocks, scan summary
2. AI Security Advisor — attack campaign analysis, step-by-step fix guide
3. Malware Scanner — live progress, severity badges, bulk delete with backup
4. File Integrity — core checksum verification, file watcher, baseline stats
5. Vulnerability Scanner — CVE listing with CVSS severity and fix versions
6. Live Traffic — paginated log, bot/human detection, filter tabs
7. Google Search Console Cleanup — OAuth setup, spam URL table, removal request
8. Geo-Fence Settings — trusted IP whitelist, country lock
9. Firewall Logs — blocked requests with IP blocking options
10. Settings Page — all features independently configurable

== External Services ==

This plugin connects to external services for certain features. All connections require explicit user action or opt-in.

= WordPress.org API =

Used to verify WordPress core file integrity by comparing checksums.
* Data sent: WordPress version and locale
* When: Only when user initiates a file integrity scan
* Service: https://api.wordpress.org/
* Privacy Policy: https://wordpress.org/about/privacy/

= WPScan Vulnerability Database =

Used to check plugins and themes for known security vulnerabilities.
* Data sent: Plugin/theme slugs and versions
* When: Only when user initiates a vulnerability scan (requires user-provided API key)
* Service: https://wpscan.com/
* Terms of Use: https://wpscan.com/terms
* Privacy Policy: https://wpscan.com/privacy

= OpenAI API =

Used to provide AI-powered security analysis and recommendations.
* Data sent: Anonymized scan results (no personal data or site content)
* When: Only when user explicitly clicks "AI Analysis" (requires user-provided API key)
* Service: https://api.openai.com/
* Terms of Use: https://openai.com/policies/terms-of-use
* Privacy Policy: https://openai.com/policies/privacy-policy

= Google APIs (Search Console) =

Used for Google Search Console integration to detect SEO spam and manage indexed URLs.
* Data sent: OAuth tokens, site URL for search analytics queries
* When: Only when user connects their Google account and initiates GSC features
* Service: https://googleapis.com/
* Terms of Service: https://developers.google.com/terms
* Privacy Policy: https://policies.google.com/privacy

= QR Code Generator (goqr.me) =

Used to generate QR codes for two-factor authentication setup.
* Data sent: TOTP authentication URI (contains site name and account identifier)
* When: Only when user enables 2FA and views the setup QR code
* Service: https://api.qrserver.com/
* Terms of Service: https://goqr.me/api/doc/
* Privacy Policy: https://goqr.me/privacy-policy/

= Turbo Addons Notifications =

Used to display important plugin notices and updates (opt-in only, disabled by default).
* Data sent: Site URL in User-Agent header
* When: Only when user enables remote notifications in settings
* Service: https://turbo-addons.com/
* Privacy Policy: https://turbo-addons.com/privacy-policy/

== Changelog ==

= 1.0.0 =
* Initial release
* Malware scanner with 30+ pattern signatures and WordPress core file manifest check
* AI Security Advisor with attack campaign analysis and step-by-step fix guide
* File Integrity Checker — verifies WordPress core files against WordPress.org checksums
* File Watcher — baseline snapshot, detects new/modified/deleted files every 6 hours
* Web Application Firewall — SQL injection, XSS, directory traversal blocking
* Login Security — brute force protection, lockout, IP blocking
* Two-Factor Authentication (TOTP/RFC 6238)
* Vulnerability Scanner (WPScan API, CVSS scoring)
* Live Traffic Monitor with bot/human detection
* Site Hardening (security headers, XML-RPC, user enumeration)
* Geo-Fence — restrict admin access to trusted IPs or countries
* Bot Protection — blocks 25+ vulnerability scanners and bad scrapers
* Google Search Console Cleanup (OAuth, bulk URL removal)
* One-click bulk malware cleanup with automatic ZIP backup
* Database scanning (wp_posts, wp_options, rogue admin users)
* Japanese/Chinese/Korean SEO spam detection
* Polyglot image backdoor detection

== Upgrade Notice ==

= 1.0.0 =
Initial release.
