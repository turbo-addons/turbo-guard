# Turbo Guard — Product Knowledge Base

> **Format:** Standard Product Knowledge Base (filled from the master template).
> **Source:** Plugin source code (free v1.1.7 + Pro v1.1.7), `readme.txt`, and general market knowledge.
> **Last verified:** Prices/claims marked **"to verify"** need confirmation on wp-turbo.com.
> **AI-ready:** This Markdown file can be uploaded to any LLM (Claude, ChatGPT, Cursor, Copilot) as the product's knowledge base.

---

## 01 — Product Overview

| Field | Value |
|-------|-------|
| **Product name** | Turbo Guard – Security & Malware Scanner (+ Turbo Guard Pro add-on) |
| **Brand and category** | Turbo Addons — WordPress security plugin (malware scanner + firewall + 2FA) |
| **Market or region** | Global (free via wordpress.org; Pro via wp-turbo.com); built by a WordPress management team |

**What is the product?**

Turbo Guard is a freemium, all-in-one WordPress security plugin delivered as **two plugins that work as one product**:

- **Turbo Guard (free)** — `turbo-guard` — the core plugin. Bundles a malware scanner, web application firewall (WAF), login security with two-factor authentication (2FA), vulnerability scanner, file-integrity checker, SEO-spam cleanup, Google Search Console cleanup, site hardening, and bot protection. Every scan and detection is free; cleanup is limited to 3 files. Runs locally, no account, no telemetry.
- **Turbo Guard Pro (paid add-on)** — `turbo-guard-pro` — a separate premium plugin that *requires* the free plugin to be active (`Requires Plugins: turbo-guard`). Unlocks unlimited malware cleanup, Live Traffic Monitor, AI Security Advisor, Geo-Fence, extended bot protection, advanced vulnerability details, scheduled vulnerability scans, and GSC scheduled monitoring. Licensed via **Freemius** (ID `39089`).

Both plugins are version `1.1.7`, by Turbo Addons (wp-turbo.com).

---

## 02 — Target Customers & ICPs

### Ideal Customer Profile — Segment A: Freelancers & solo site owners

| Field | Value |
|-------|-------|
| **Customer segment** | Independent site owners, bloggers, small businesses with 1–3 WordPress sites |
| **Ideal customer and why they fit** | A non-technical owner who has had a site hacked or seen strange SEO spam (Japanese/Chinese text) in Google results. They want protection without a developer or a subscription. |
| **Buyer and decision-maker** | The owner (same person) |
| **End user** | The owner |
| **Primary need and buying trigger** | An active infection or spam-indexing incident; "set it and forget it" free protection |

### Ideal Customer Profile — Segment B: WordPress agencies & freelancers

| Field | Value |
|-------|-------|
| **Customer segment** | Web agencies / freelancers managing many client WordPress sites |
| **Ideal customer and why they fit** | They already maintain dozens of sites and need a lightweight, no-account security layer they can roll out to every client without per-site fees. |
| **Buyer and decision-maker** | Agency owner / lead developer |
| **End user** | Site administrators and the agency's support staff |
| **Primary need and buying trigger** | Reduce client-site breach/cleanup support load; bulk deployment; white-label-ish simplicity |

---

## 03 — Competitor Analysis

> **Method note:** Researched from wordpress.org plugin listings (November 2026). Active-install counts, ratings, and pricing are as published by each vendor and shift over time. The six plugins below are the confirmed direct competitors for Turbo Guard.

**Competitor list** (all six confirmed direct competitors):

| Rank | Plugin | Developer | Est. active installs | Rating | Core pricing |
|------|--------|-----------|----------------------|--------|--------------|
| 1 | Wordfence | Defiant Inc. | 5M+ | 4.7★ (5,042 reviews) | Free + Premium $149/yr |
| 2 | Really Simple Security | Really Simple Plugins | 3M+ | 4.9★ (8,870 reviews) | Free + Pro (add-on) |
| 3 | All-In-One Security (AIOS) | Team Updraft | 1M+ | 4.7★ (1,720 reviews) | Free + Premium from $70/yr |
| 4 | MalCare | BlogVault | 100,000+ | 4.4★ (560 reviews) | Free + paid (Protect $99 / Repair $299 / Fortify $499) |
| 5 | Security by CleanTalk | CleanTalk Inc. | 100,000+ | — (398 reviews) | Free trial → $9/yr |
| 6 | Security Ninja | cleverplugins | 7,000+ | 4.7★ (101 reviews) | Free + Pro |

---

### Competitor Profile — Wordfence

| Field | Value |
|-------|-------|
| **Name, market and rank** | Wordfence — the global #1 / most-installed WordPress security plugin (Mark Maunder / Defiant Inc.) |
| **Strengths** | Largest threat-intel team + Threat Defense Feed; real-time firewall rules & malware signatures (Premium); **44,000+ malware signatures**; endpoint WAF that integrates with WP user identity; passkeys + TOTP 2FA + CAPTCHA; Live Traffic; Wordfence Central (free multi-site management); 24/7 incident-response team (Response tier) |
| **Weaknesses** | Free tier gets firewall rules/malware signatures **delayed 30 days**; local scans add server load; dense, config-heavy UI; Premium $149/yr feels steep; cleanup is manual (you delete files yourself) |
| **Opportunities** | Turbo Guard wins on **zero-account, no-telemetry, no 30-day delay** and built-in **SEO-spam de-indexing** (Wordfence detects SEO spam but produces no 410-Gone/GSC cleanup) |
| **Threats** | Default choice from brand trust; its free Live Traffic already covers a feature Turbo Guard gates to Pro |
| **Gap analysis** | Wordfence leads on real-time threat intel + brand; lags on SEO-spam removal workflow and lightweight footprint. Turbo Guard's clearest wins: SEO-spam cleanup + no-delay detection + no account. |
| **Positioning analysis** | Everyone from solo owners to enterprises; promise: "the most trusted firewall". |
| **Sources and date checked** | wordpress.org/plugins/wordfence (2026) |

---

### Competitor Profile — Really Simple Security (formerly Really Simple SSL)

| Field | Value |
|-------|-------|
| **Name, market and rank** | Really Simple Security — the #1 most lightweight / easy security plugin (Really Simple Plugins) |
| **Strengths** | **3M+ installs, 4.9★**; legendary ease-of-use (1-min onboarding); SSL generation + HTTPS enforcement (Let's Encrypt); hardening + 2FA + login protection free; modular (unused features load no code); strong brand from the SSL days |
| **Weaknesses** | Firewall, security headers, region blocking, and advanced hardening are **Pro-only**; no malware scanner/cleanup at all; SSL-centric heritage |
| **Opportunities** | Turbo Guard's **malware scanning + cleanup + SEO-spam** fills exactly what RSS doesn't do — RSS is hardening/SSL, not malware removal |
| **Threats** | RSS is often pre-installed/bundled and is the "easy" default for non-technical users |
| **Gap analysis** | RSS leads on ease + SSL + hardening; has **no malware scanning or cleanup**. Turbo Guard wins on detection depth + SEO-spam + cleanup. |
| **Positioning analysis** | Non-technical users wanting simple SSL + hardening. Promise: "simple and performant security". |
| **Sources and date checked** | wordpress.org/plugins/really-simple-ssl (2026) |

---

### Competitor Profile — All-In-One Security (AIOS)

| Field | Value |
|-------|-------|
| **Name, market and rank** | All-In-One Security (AIOS) — top-rated hardening/firewall plugin (David Anderson / Team Updraft, the UpdraftPlus team) |
| **Strengths** | 1M+ installs, 4.7★; broad free set (2FA/TFA, brute force, login lockdown, file-change scan, .htaccess/6G firewall, spam prevention, audit log); trusted UpdraftPlus team; malware scanning + uptime monitoring in Premium from $70/yr |
| **Weaknesses** | Malware scanning is **Premium-only**; large feature sprawl (basic/intermediate/advanced tiers); .htaccess-based firewall only works on Apache (not NGINX/IIS) |
| **Opportunities** | Turbo Guard gives **free malware scanning + free 3-file cleanup + SEO-spam de-indexing**, which AIOS gates behind Premium or omits entirely |
| **Threats** | Free 2FA + brute-force + hardening breadth is easy to substitute; UpdraftPlus brand trust |
| **Gap analysis** | AIOS leads on free hardening/2FA breadth; lags on free malware detection/cleanup and has **no SEO-spam cleanup**. |
| **Positioning analysis** | Beginners to experts; promise: "all-in-one" hardening with a security score. |
| **Sources and date checked** | wordpress.org/plugins/all-in-one-wp-security-and-firewall (2026) |

---

### Competitor Profile — MalCare

| Field | Value |
|-------|-------|
| **Name, market and rank** | MalCare (by BlogVault) — WordPress security focused on one-click malware removal; 400,000+ sites / 120 countries |
| **Strengths** | One-click cleanup in <60s (removes only malware, keeps content); **off-server scanning** (zero load); published 0.2% false-positive rate; 39,000+ vulnerabilities tracked + virtual patching; network intelligence across 400,000+ sites; firewall + geo-blocking; 2FA included (free: 2 admin users, scales to 5/15/all on paid plans) |
| **Weaknesses** | Cleanup is **paid-only** (Repair $299 or Fortify $499 — Free/Protect find malware but don't remove it); service-dependent (requires account); free tier scans only weekly; geo-blocking/bot protection/advanced firewall are paid |
| **Opportunities** | Turbo Guard's **free** 3-item cleanup + local scan vs MalCare's paid cleanup; Turbo Guard's **SEO-spam de-indexing** is a niche MalCare doesn't headline |
| **Threats** | MalCare's "we remove it in one click" simplicity + strong agency word-of-mouth |
| **Gap analysis** | MalCare leads on guaranteed low-effort cleanup + virtual patching; lags on free self-serve cleanup and GSC/SEO-spam de-indexing. |
| **Positioning analysis** | Owners & agencies who want malware removed without touching code. Promise: "safe from hackers" with zero slowdown. |
| **Sources and date checked** | wordpress.org/plugins/malcare-security + malcare.com (2026) |

---

### Competitor Profile — Security by CleanTalk (SPBCT)

| Field | Value |
|-------|-------|
| **Name, market and rank** | Security Plugin, Firewall & Malware Scanner (CleanTalk Inc.) — cloud security service |
| **Strengths** | Cloud WAF + malware scanner with **auto-cure**; 2FA, brute-force protection, change-login-URL, stop user enumeration; traffic control/DDoS mitigation; real-time traffic monitor; leaked-password check; active security research (CVE disclosures) |
| **Weaknesses** | **Not freemium — free trial then $9/yr** (no permanent free tier); requires CleanTalk cloud account; must-use plugin loader changes server config (some users report uninstall leaving the site broken) |
| **Opportunities** | Turbo Guard's **truly free** scan + 3-item cleanup + no-account is the direct counter to CleanTalk's subscription-only model |
| **Threats** | Low price ($9/yr) + strong spam-protection brand (CleanTalk anti-spam) |
| **Gap analysis** | CleanTalk leads on cloud auto-cure + DDoS; lags on free tier and has **no SEO-spam/GSC de-indexing**. |
| **Positioning analysis** | Budget cloud-security buyers; promise: enterprise features at a coffee-price subscription. |
| **Sources and date checked** | wordpress.org/plugins/security-malware-firewall (2026) |

---

### Competitor Profile — Security Ninja

| Field | Value |
|-------|-------|
| **Name, market and rank** | Security Ninja (cleverplugins) — lightweight security auditing/firewall toolkit |
| **Strengths** | 4.7★; 50+ security tests/audits with fix guidance; free 8G-based WAF; vulnerability scanner (NVD); core-integrity scanner; clean non-"cockpit" UI; AI Security Advisor on WP 7 |
| **Weaknesses** | Small install base (7,000+); **malware scanning/cleanup, 2FA, brute-force protection, cloud firewall are all Pro**; free tier is mostly auditing + basic firewall |
| **Opportunities** | Turbo Guard gives **free malware detection + cleanup + 2FA + brute force**, which Security Ninja gates behind Pro |
| **Threats** | Its "50+ security tests" auditing angle appeals to developers/agencies; MainWP integration |
| **Gap analysis** | Security Ninja leads on auditing tests + UX; lags on free malware detection/cleanup and has **no SEO-spam de-indexing**. |
| **Positioning analysis** | Developers/agencies wanting a lightweight security audit. Promise: security without a "cockpit". |
| **Sources and date checked** | wordpress.org/plugins/security-ninja (2026) |

---

## 03.1 — Competitor Summary Table (for quick comparison)

| Capability | Turbo Guard | Wordfence | Really Simple Security | AIOS | MalCare | CleanTalk | Security Ninja |
|------------|-------------|-----------|------------------------|------|---------|-----------|----------------|
| Malware detection | **Free, local** | Free (30-day delay) | No | Premium | Free (weekly) | Cloud | Pro |
| Malware cleanup | **Free (3) / Pro unlimited** | Manual | No | Premium | Paid 1-click | Auto-cure (paid) | Pro |
| SEO-spam cleanup + de-indexing | **Yes (unique)** | Detect only | No | No | No | No | No |
| Firewall (WAF) | Free | Free (delayed) | Pro | Free | Free (paid rules) | Cloud | Free (8G) |
| 2FA | Free | Free | Free | Free | **Free (2 admins)** / more on paid | Free | Pro |
| Login/brute-force protection | Free | Free | Free | Free | Free | Free | Pro |
| Live Traffic | Pro | Free | No | No | Paid | Free | No |
| Account required | **No** | Yes (key) | No | No | Yes | Yes | No |
| Scanning load | Local (chunked) | Local (heavy) | n/a | Local | Off-server | Cloud | Local |

**Key takeaway:** Turbo Guard is the **only** one of the six with built-in **SEO-spam cleanup + 410-Gone de-indexing**, and the only one offering **free malware cleanup (3 items) with no account and no 30-day rule delay**.

---

## 04 — Own Product SWOT & Gap Analysis

| Strengths | Weaknesses |
|-----------|------------|
| Detect-everything-free; pay only to clean beyond 3 files | Free cleanup quota (3 files) may frustrate during a large infection |
| Built by a team that runs WordPress sites (real-world focus) | Newer brand with little recognition vs Wordfence |
| Rare SEO-spam cleanup + 410-Gone de-indexing | Some advanced features gated to Pro (Live Traffic, Geo-Fence, AI) |
| Privacy-first: no account, no telemetry, local scanning | Requires manual user action to actually delete files |
| Lightweight: AJAX chunked scans, negligible firewall overhead | — |
| Plays well with other security plugins (whitelists 15+) | — |

| Opportunities | Threats |
|---------------|---------|
| SEO-spam (Japanese/Chinese) cleanup is a growing, underserved niche | Wordfence/others may copy SEO-spam features |
| Growing AI-crawler concerns → bot protection messaging | Platform changes (WPScan pricing/limits, Google GSC API limits) |
| Agencies needing a deploy-anywhere, no-account security layer | Price/feature pressure from free-tier competitors |
| "No telemetry / privacy" positioning vs account-heavy rivals | Plugin-review scrutiny on wordpress.org |

**Gap analysis (priority):**
1. **P1 — Brand trust:** biggest unmet need is recognition; counter with concrete SEO-spam before/after evidence and a lean performance story.
2. **P1 — Free cleanup cap:** 3-file limit can feel stingy during an active incident; consider a clearer path to Pro at that exact moment.
3. **P2 — Live Traffic in Pro:** Wordfence gives live traffic free; this is a common reason to switch — weigh moving it to free.

---

## 05 — Customer Needs & Pain Points

| Customer segment | Need or pain point | Customer impact |
|------------------|--------------------|-----------------|
| Solo owner | Site got hacked / defaced | Revenue + reputation loss, panic |
| Solo owner | Japanese/Chinese SEO spam in Google | Search ranking drop, spam indexing |
| Solo owner | Brute-force login attempts | Lockout risk, security fear |
| Agency | Many client sites to secure | Time drain, support burden |
| Agency | No budget for per-site security subscriptions | Cost pressure |
| All | Security tools slow the site down | Frustration, deactivation |
| All | Don't want to create accounts / give data | Privacy concerns, distrust |
| All | Fear of false positives deleting good files | Hesitation to clean |

---

## 06 — How the Product Solves Them

| Pain point | Feature or attribute | How it helps | Customer outcome |
|------------|----------------------|--------------|------------------|
| Site hacked | Malware Scanner (50+ patterns, web shells) | Finds every infected file free | Detect infection immediately |
| SEO spam in Google | SEO Spam Detector + GSC Cleanup + 410-Gone rules | Finds and de-indexes spam URLs | Spam removed from Google |
| Brute-force attacks | Login Security + Firewall rate limiting | Locks out attackers, blocks IPs | Site stays accessible |
| Account fatigue | No account required | Install and go | Zero-friction onboarding |
| Performance fear | AJAX chunked scanning | No timeout on big sites | Lightweight feel |
| False-positive fear | Known-files allowlist (trusted plugins) | Won't flag legitimate files | Safe to clean |
| Many sites | No per-site fees; install anywhere | Deploy to every client | Cost-effective |
| Privacy | Local scan, no telemetry | Data stays on site | Trust |

---

## 07 — Features, Specifications & Variants

| Feature or specification | Variant or scope | Key details and differences |
|--------------------------|------------------|-----------------------------|
| Malware scanning | Free | Full-site, 50+ signatures, web shells, DB scan, polyglot images |
| Malware + SEO-spam cleanup | Free (up to 3 items) / Pro (unlimited) | ZIP backup + quarantine on delete |
| Web Application Firewall | Free | SQLi/XSS/traversal, rate limit 120 req/min, IP blocklist |
| 2FA | Free | TOTP/RFC 6238, 8 recovery codes, role enforcement |
| Vulnerability scanner | Free (basic) / Pro (expanded details) | CVSS scoring, CVE links; Pro adds CVE IDs, fix versions, advisories |
| File integrity | Free | Core checksum verify + 6h file watcher |
| Site hardening | Free | Security headers, hide version, disable XML-RPC |
| Bot protection | Free / Pro (extended) | Pro adds 17 more bad-bot signatures (scrapers, harvesters, scanners) |
| SEO spam detector | Free | CJK spam, doorway URLs, whole `wp-content` scan |
| GSC cleanup | Free | Sitemap spam scan, 410-Gone de-indexing |
| Live Traffic Monitor | **Pro** | Logs every request; 30+ bot signatures incl. AI crawlers (GPTBot, ClaudeBot, PerplexityBot); 24h stats; one-click IP block |
| AI Security Advisor | **Pro** | Rule-based built-in analysis (6 named attack campaigns) + optional OpenAI enhancement (user key) |
| Geo-Fence | **Pro** | 3 modes: trusted-IP whitelist, country whitelist, upload country lock (ipapi.co) |
| Scheduled vulnerability checks | **Pro** | Automated WPScan scans + email alerts |
| GSC scheduled monitoring | **Pro** | Weekly re-check of indexed URLs; emails on newly-indexed spam; de-indexing verification |
| One-click .htaccess 410-Gone apply | **Pro** | Writes spam-block rules directly to `.htaccess` with automatic timestamped backup + rollback |
| Platform | — | WordPress 5.6+, PHP 7.4+ |

### 07.1 — Pro feature details (from `turbo-guard-pro-premium` source)

- **Live Traffic Monitor** (`Turbo_Guard_Live_Traffic`): logs every HTTP request at shutdown (skips CLI/cron), detects bots from 30+ user-agent signatures including AI crawlers (GPTBot, ClaudeBot, PerplexityBot, Cohere), records method/URI/status/user/bot name. 24-hour stats (total, humans, bots, blocked 403, errors 4xx). Auto-cleanup keeps last 7 days / 10,000 rows. One-click IP block from any row. Own DB table `turbo_guard_traffic`.
- **AI Security Advisor** (`Turbo_Guard_AI_Advisor`): maps scan results to 6 named attack campaigns (Japanese/Chinese SEO spam, web shell/backdoor, brute force, DB SEO-spam injection, rogue admin, PHP-in-uploads), each with plain-English explanation, impact list, and step-by-step remediation. Works **without any API key** (rule-based) out of the box; optional OpenAI (`gpt-4o-mini`) enrichment using the user's own key, sending only anonymized threat-type data. Produces a 30-day security-score trend.
- **Geo-Fence** (`Turbo_Guard_Geo_Fence`): three protection modes — (1) trusted-IP whitelist (exact IP/CIDR/range), (2) country whitelist, (3) upload country lock. Uses ipapi.co free tier (1,000 req/day, 24h per-IP cache). Enforces on `init` priority 1–2 with a friendly 403 block page and lockout-recovery instructions.
- **GSC Pro monitoring** (`Turbo_Guard_GSC_Pro`): weekly WP-Cron diff of indexed spam URLs vs the previous snapshot, emails on newly-indexed spam, and tracks de-indexed count (verifies 410-Gone worked).
- **Extended bot list**: adds 17 extra bad-bot signatures (ZGrab, MegaIndex, SputnikBot, CCBot, Barkrowler, DataForSeoBot, PetalBot, email harvesters, etc.) merged via the free plugin's `turbo_guard_bad_bots` filter.

### 07.2 — Licensing & dependency

- Pro is a **separate plugin** that requires the free plugin (`Requires Plugins: turbo-guard`). Activation is blocked (with a notice) unless the free plugin is active.
- Licensed through **Freemius** (`tgp_fs()`, SDK id `39089`, slug `turbo-guard-pro`). `turbo_guard_pro_is_licensed()` → `fs->can_use_premium_code()`; a `WP_DEBUG` dev fallback exists for testing only.
- On license expiry, Pro features lock but free protection keeps working; no data is deleted.

---

## 08 — Benefits & USPs

**Customer benefits:**
- One plugin replaces several (scanner + firewall + 2FA + hardening + bot blocking).
- Detect everything for free — pay only to clean beyond 3 files.
- Removes SEO spam from Google (rare, high-value outcome).
- No account, no telemetry, fully local — privacy-first.
- Lightweight and safe alongside other security plugins.

**Unique selling propositions & supporting evidence:**
1. **SEO-spam de-indexing** — 410-Gone rules + sitemap resubmission; rare among competitors.
2. **Built by WordPress operators** — solves problems the team hits in production (SEO spam, false positives).
3. **Free detection, no account** — Wordfence/Sucuri/MalCare all push accounts or paid tiers harder.
4. **False-positive safety** — trusted-plugin allowlist prevents good files from being flagged.

---

## 09 — Positioning & Tagline

| Field | Value |
|-------|-------|
| **Target segment** | Solo site owners + WordPress agencies |
| **Product category** | WordPress security & malware scanner |
| **Main promise and differentiator** | "Detect everything free; clean up to 3 files free — with the only SEO-spam de-indexing built in." |
| **Approved tagline** | Turbo Guard — All-in-one WordPress security. Detect free, protect always. |

---

## 10 — Pricing, Availability & How to Buy

**Pricing model:** site-based annual plans. Every Pro plan includes the same feature set; you only pick the activation/site limit.

| Plan | Price | Notes |
|------|-------|-------|
| Turbo Guard (Free) | $0 | All scanning/detection/protection free; cleanup up to 3 detected items; no account required |
| Pro — Up to 2 Sites | **$16 / year** (regularly $39) | Individual owners & small teams |
| Pro — 10 Sites | **$40 / year** (regularly $100) | Freelancers & agencies |
| Pro — 100 Sites | **$128 / year** (regularly $320) | Agencies with large portfolios |

*All Pro plans billed annually. Source: wp-turbo.com/turbo-guard/ (last verified 2026).*

**Included in every Pro plan:** unlimited malware cleanup, unlimited SEO-spam cleanup, expanded vulnerability details, Live Traffic Monitor, AI Security Advisor (own API key), Geo-Fence & trusted locations, scheduled vulnerability checks, extended bot protection, plugin support & updates.

**Purchase channel and process:**
1. Free: install directly from the WordPress plugin repository (`wordpress.org/plugins/turbo-guard/`). No account required.
2. Pro: visit `https://wp-turbo.com/turbo-guard/` → choose a plan (2/10/100 sites) → secure checkout **powered by Freemius** → activate the Pro license inside the plugin. The Pro add-on sets the `turbo_guard_is_pro` filter to `true`.

**License expiry:** when a Pro license expires, Pro-only features (unlimited cleanup, Live Traffic Monitor, AI Security Advisor, Geo-Fence, scheduled vulnerability checks) stop working and the plugin returns to the Free tier. Website files and settings are unchanged; scanning, firewall, login security, and 2FA remain fully functional.

---

## 11 — How to Use

**Free plugin:**
1. Upload `turbo-guard` to `/wp-content/plugins/` (or install from wordpress.org).
2. Activate through the WordPress Plugins menu.
3. Open **Turbo Guard** in the admin sidebar (shield icon).
4. On the **Scanner** page, click "Start Full Scan".
5. Review results; use "Select Critical Only" then "Delete Selected" (automatic ZIP backup).
6. Set up **2FA** under **Settings** (QR + recovery codes).
7. (Optional) Connect **GSC Cleanup** to de-index spam URLs.

**Pro add-on:**
1. Install + activate the free plugin first (Pro blocks activation without it).
2. Upload `turbo-guard-pro` and activate.
3. Follow the Freemius on-screen flow to connect your license.
4. Pro features unlock: Live Traffic, AI Advisor pages appear under the Turbo Guard menu; Geo-Fence + AI settings appear on the Settings page; cleanup quota becomes unlimited.

**Requirements:** WordPress 5.6+, PHP 7.4+, `manage_options` capability for all admin pages.

---

## 12 — FAQs

**Q: Is Turbo Guard completely free?**
A: All scanning, detection, and protection is free. Free cleanup is limited to 3 infected files. The Pro add-on unlocks unlimited cleanup plus Live Traffic Monitor, AI Security Advisor, Geo-Fence, extended bot protection, and scheduled vulnerability/GSC monitoring. No account required for the free plugin.

**Q: Does the AI Security Advisor require an API key?**
A: No — the built-in analysis (rule-based, 6 named attack campaigns) works without any key. An optional OpenAI integration (richer narrative) requires the user's own API key and is opt-in.

**Q: Will it slow my website?**
A: No. Scanning runs via AJAX in your browser; the firewall adds negligible overhead.

**Q: My site shows Japanese spam in Google but files are gone. What do I do?**
A: Use the GSC Cleanup page — connect Google Search Console, fetch indexed URLs, identify the spam, and submit for removal. Pro adds a one-click `.htaccess` 410-Gone apply with automatic backup.

**Q: Does the File Integrity checker work offline?**
A: Yes — it downloads checksums from WordPress.org on first use and caches them for 12 hours.

**Q: Can I use it on all my sites?**
A: Yes. Install on each site; Pro licenses are site-based (2/10/100-site plans).

**Q: Does it conflict with other security plugins?**
A: No — it whitelists 15+ popular security plugins (Wordfence, Sucuri, MalCare, iThemes, etc.) to prevent false positives.

**Q: What happens if I get locked out by 2FA?**
A: Use one of your 8 single-use recovery codes, or a "remembered" trusted device. If a secret is ever missing, login fails open to prevent lockout.

**Q: What happens if I get locked out by Geo-Fence?**
A: The 403 block page tells you how to recover — disable the `turbo_guard_trusted_ip_enabled` / country-lock option in the database. Geo-Fence also lets its own helper AJAX (Add My IP / Detect Country) through so setup can't lock you out.

**Q: Does Turbo Guard guarantee my site is completely secure?**
A: No. No security plugin can guarantee complete protection or identify every possible compromise. Turbo Guard detects supported patterns, reduces exposure to supported attack types, and provides tools for reviewing and cleaning identified issues.

**Q: Does Turbo Guard upload my website files?**
A: No — website files remain on your server. Optional features use external services only for their documented purpose (vulnerability lookup, Geo-Fence ipapi.co, AI analysis, GSC).

**Q: Does Pro work without the free plugin?**
A: No — the Pro add-on requires the free plugin to be active; activation is blocked until it is.

**Q: What happens when a Pro license expires?**
A: Pro-only features lock and the plugin returns to the Free tier. Your website files and settings are unchanged; scanning, firewall, login security, and 2FA remain fully functional. Renew to restore Pro.

---

## Appendix — Technical reference (for developers / support AI)

### Free plugin (`turbo-guard`)
- **Main class:** `Turbo_Guard` (singleton). Bootstrap in `turbo-guard.php`.
- **Classes:** `Turbo_Guard_Scanner`, `_Firewall`, `_Login_Security`, `_2FA`, `_Settings`, `_GSC`, `_Hardening`, `_Vuln_Scanner`, `_Integrity`, `_Bot_Protection`, `_SEO_Spam_Detector`, `_Installer`, `_Notices`, `_Cleaner`, `_Known_Files`.
- **Admin pages:** `turbo-guard` (Dashboard), `-scanner`, `-firewall`, `-settings`, `-gsc`, `-vulnerabilities`, `-integrity`, `-seo-spam`.
- **DB tables (prefixed):** `turbo_guard_scans`, `_scan_results`, `_firewall_log`, `_ip_blocklist`, `_events`, `_login_attempts`, `_rate_limit_log`.
- **Options prefix:** `turbo_guard_`.
- **Cron:** `turbo_guard_scheduled_scan`, `turbo_guard_file_watcher`, `turbo_guard_integrity_check`.
- **Extension points (Pro hooks into these):** filters `turbo_guard_is_pro`, `turbo_guard_pro_url`, `turbo_guard_free_cleanup_limit`, `turbo_guard_bad_bots`, `turbo_guard_aggressive_bots`, `turbo_guard_rate_limit`, `turbo_guard_rate_limit_404`, `turbo_guard_security_trend`; actions `turbo_guard_init_pro`, `turbo_guard_scan_completed`, `turbo_guard_settings_after`, `turbo_guard_settings_save`.
- **Repos:** gitlab.ibos.io/shariful/turbo-guard; github.com/turbo-addons/turbo-guard.

### Pro add-on (`turbo-guard-pro-premium` / slug `turbo-guard-pro`)
- **Bootstrap:** `Turbo_Guard_Pro` (singleton) in `turbo-guard-pro.php`; hooks into free plugin's `turbo_guard_is_pro` filter + `turbo_guard_init_pro` action.
- **Classes:** `Turbo_Guard_Live_Traffic`, `_AI_Advisor`, `_Geo_Fence`, `_GSC_Pro`, `_Pro_Installer`, `_Pro_Admin`.
- **Admin pages (added under Turbo Guard menu):** `turbo-guard-traffic` (Live Traffic), `turbo-guard-ai-report` (AI Advisor).
- **DB tables (prefixed):** `turbo_guard_traffic` (live traffic log).
- **Pro options:** `turbo_guard_live_traffic_enabled`, `turbo_guard_trusted_ip_enabled`, `turbo_guard_trusted_ips`, `turbo_guard_country_lock_enabled`, `turbo_guard_allowed_countries`, `turbo_guard_upload_country_lock`, `turbo_guard_openai_api_key`, `turbo_guard_gsc_monitoring_enabled`.
- **Cron:** `turbo_guard_traffic_cleanup` (daily), `turbo_guard_gsc_scheduled_check` (weekly), `turbo_guard_ai_analyse` (single, post-scan).
- **Licensing:** Freemius SDK id `39089`, `tgp_fs()`; `turbo_guard_pro_is_licensed()` = `fs->can_use_premium_code()` (plus `WP_DEBUG` dev fallback).
- **Dependency guard:** `turbo_guard_pro_check_dependency()` (admin_init priority 1) deactivates Pro if the free plugin is missing/inactive.
- **Geo-Fence geolocation:** ipapi.co free tier (`https://ipapi.co/{ip}/country/`), 1,000 req/day, 24h per-IP transient cache, `LOCAL` for private IPs.
- **Repo:** gitlab.ibos.io/shariful/turbo-guard-pro.
