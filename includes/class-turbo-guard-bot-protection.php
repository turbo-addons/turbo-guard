<?php
/**
 * Bot Protection Class.
 *
 * Blocks malicious bots (vulnerability scanners, spam bots, aggressive
 * scrapers) while reliably allowing legitimate search-engine crawlers
 * through — including protection against crawlers that spoof a trusted
 * user agent (e.g. a fake "Googlebot").
 *
 * Design principles:
 * - Verified crawlers are matched FIRST and always allowed. The good-bot
 *   list takes precedence over the block lists, so a legitimate crawler can
 *   never be caught by a broad bad-bot substring.
 * - The always-on block list contains only high-confidence attack tools.
 *   Generic clients (curl, python-requests, ...) live in a separate,
 *   opt-in "Aggressive Mode" list because they are frequently legitimate.
 * - Blocking an IP does not write to the database on every request: writes
 *   are de-duplicated for a short window so a bot flood cannot turn this
 *   feature into a write-amplification vector.
 *
 * @package TurboGuard
 * @since   1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Bot detection and protection.
 *
 * @since 1.2.0
 */
class Turbo_Guard_Bot_Protection {

	/**
	 * Singleton instance.
	 *
	 * @var Turbo_Guard_Bot_Protection|null
	 */
	private static $instance = null;

	/**
	 * Verified search-engine / social crawlers.
	 *
	 * signature => array( label, rDNS suffixes )
	 *
	 * When the rDNS suffix list is non-empty the source IP's reverse DNS is
	 * verified against it, so a spoofed user agent is detected and blocked.
	 * When the list is empty the crawler is trusted on its user agent alone
	 * (used for services whose reverse DNS is unreliable), which avoids
	 * breaking legitimate link previews.
	 *
	 * @var array
	 */
	private static $crawlers = array(
		'googlebot'            => array( 'Googlebot', array( 'googlebot.com', 'google.com' ) ),
		'adsbot-google'        => array( 'Google AdsBot', array( 'googlebot.com', 'google.com' ) ),
		'mediapartners-google' => array( 'Google Mediapartners', array( 'googlebot.com', 'google.com' ) ),
		'apis-google'          => array( 'Google APIs', array( 'googlebot.com', 'google.com' ) ),
		'google-inspectiontool' => array( 'Google Inspection Tool', array( 'googlebot.com', 'google.com' ) ),
		'bingbot'              => array( 'Bingbot', array( 'search.msn.com' ) ),
		'msnbot'               => array( 'MSN Bot', array( 'search.msn.com' ) ),
		'adidxbot'             => array( 'Bing Ads', array( 'search.msn.com' ) ),
		'duckduckbot'          => array( 'DuckDuckBot', array( 'duckduckgo.com' ) ),
		'baiduspider'          => array( 'Baiduspider', array( 'baidu.com' ) ),
		'yandexbot'            => array( 'YandexBot', array( 'yandex.com', 'yandex.ru', 'yandex.net' ) ),
		'sogou'                => array( 'Sogou Spider', array( 'sogou.com' ) ),
		'exabot'               => array( 'Exabot', array( 'exalead.com' ) ),
		'facebot'              => array( 'Facebook', array() ),
		'facebookexternalhit'  => array( 'Facebook', array() ),
		'ia_archiver'          => array( 'Alexa / Wayback', array( 'archive.org', 'alexa.com' ) ),
		'applebot'             => array( 'Applebot', array( 'apple.com' ) ),
		'ahrefsbot'            => array( 'AhrefsBot', array( 'ahrefs.com' ) ),
		'semrushbot'           => array( 'SemrushBot', array( 'semrush.com' ) ),
		'mj12bot'              => array( 'Majestic-12', array( 'majestic12.co.uk' ) ),
		'dotbot'               => array( 'DotBot', array() ),
		'rogerbot'             => array( 'Rogerbot', array( 'moz.com' ) ),
		'linkedinbot'          => array( 'LinkedIn', array() ),
		'twitterbot'           => array( 'Twitterbot', array() ),
		'embedly'              => array( 'Embedly', array() ),
		'quora link preview'   => array( 'Quora', array() ),
		'whatsapp'             => array( 'WhatsApp', array() ),
		'discordbot'           => array( 'Discord', array() ),
	);

	/**
	 * Always-on bad bots — high-confidence attack tools and scanners.
	 *
	 * These are matched regardless of Aggressive Mode because they have no
	 * legitimate reason to visit a WordPress site.
	 *
	 * @var array
	 */
	private static $bad_bots = array(
		'sqlmap'          => 'SQLMap (SQL injection scanner)',
		'nikto'           => 'Nikto (vulnerability scanner)',
		'nessus'          => 'Nessus (vulnerability scanner)',
		'masscan'         => 'Masscan (port scanner)',
		'nuclei'          => 'Nuclei (vulnerability scanner)',
		'acunetix'        => 'Acunetix (web scanner)',
		'nmap'            => 'Nmap scripting engine',
		'metasploit'      => 'Metasploit (exploit framework)',
		'openvas'         => 'OpenVAS (vulnerability scanner)',
		'owasp zap'       => 'OWASP ZAP (web scanner)',
		'dirbuster'       => 'DirBuster (path scanner)',
		'gobuster'        => 'Gobuster (path scanner)',
		'wfuzz'           => 'Wfuzz (fuzzer)',
		'hydra'           => 'Hydra (brute-force tool)',
		'zgrab'           => 'ZGrab (port scanner)',
		'xray'            => 'X-Ray (web scanner)',
		'wp-scan'         => 'WPScan (WordPress scanner)',
		'wpscan'          => 'WPScan (WordPress scanner)',
	);

	/**
	 * Opt-in aggressive block list — generic HTTP clients that may also be
	 * legitimate. Only matched when Aggressive Mode is enabled.
	 *
	 * @var array
	 */
	private static $aggressive_bots = array(
		'curl/'              => 'cURL (automated client)',
		'libcurl'            => 'libcurl (automated client)',
		'python-requests'    => 'Python requests (automated client)',
		'python-urllib'      => 'Python urllib (automated client)',
		'aiohttp'            => 'aiohttp (automated client)',
		'httpx'              => 'httpx (automated client)',
		'wget/'              => 'Wget (automated client)',
		'go-http-client'     => 'Go HTTP client',
		'okhttp'             => 'OkHttp client',
		'java/'              => 'Java HTTP client',
		'libwww-perl'        => 'libwww-perl (automated tool)',
		'phantomjs'          => 'PhantomJS (headless browser)',
		'headlesschrome'     => 'Headless Chrome',
		'puppeteer'          => 'Puppeteer (headless browser)',
		'blexbot'            => 'BLEXBot (scraper)',
		'scrapy'             => 'Scrapy (scraper)',
	);

	/**
	 * Get singleton.
	 *
	 * @since 1.2.0
	 * @return Turbo_Guard_Bot_Protection
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor — register hooks only when bot protection is enabled.
	 *
	 * @since 1.2.0
	 */
	private function __construct() {
		if ( 'yes' !== get_option( 'turbo_guard_bot_protection_enabled', 'yes' ) ) {
			return;
		}
		// Run very early — before WordPress loads most things.
		add_action( 'init', array( $this, 'check_bot' ), 2 );
	}

	// =========================================================
	// ENFORCEMENT
	// =========================================================

	/**
	 * Block the current request if it is a bad bot.
	 *
	 * Order of precedence:
	 *   1. Verified crawlers are always allowed (and spoofs are blocked).
	 *   2. Always-on bad bots.
	 *   3. Aggressive mode list (opt-in).
	 *   4. Admin-defined custom rules.
	 *
	 * @since 1.2.0
	 */
	public function check_bot() {
		// Never interfere with logged-in users, WP-Cron, or WP-CLI.
		if ( is_user_logged_in()
			|| ( defined( 'DOING_CRON' ) && DOING_CRON )
			|| ( defined( 'WP_CLI' ) && WP_CLI )
		) {
			return;
		}

		/**
		 * Short-circuit the bot check entirely.
		 *
		 * @since 1.2.0
		 * @param bool $bypass Return true to skip bot protection for this request.
		 */
		if ( apply_filters( 'turbo_guard_bot_protection_bypass', false ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized with sanitize_text_field() below.
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';
		$ua = sanitize_text_field( $ua );

		// 1. Verified crawlers take precedence over every block list.
		$claimed = self::detect_good_bot( $ua );
		if ( false !== $claimed ) {
			if ( 'yes' === get_option( 'turbo_guard_bot_verify_crawlers', 'yes' )
				&& ! $this->verify_crawler_ip( $ua )
			) {
				$this->block_bot( 'Spoofed crawler (claimed ' . $claimed . ')' );
				return;
			}
			return; // Genuine crawler (or verification disabled) — allow.
		}

		// 2. Always-on bad bots.
		$match = self::match_list( self::get_bad_bots(), $ua );
		if ( $match ) {
			$this->block_bot( $match['label'] );
			return;
		}

		// 3. Aggressive mode (opt-in) — generic clients and empty user agents.
		if ( 'yes' === get_option( 'turbo_guard_bot_aggressive_mode', 'no' ) ) {
			if ( '' === trim( $ua ) ) {
				$this->block_bot( 'Empty user agent' );
				return;
			}

			$match = self::match_list( self::get_aggressive_bots(), $ua );
			if ( $match ) {
				$this->block_bot( $match['label'] );
				return;
			}
		}

		// 4. Admin-defined custom rules.
		$custom = self::match_custom( $ua );
		if ( false !== $custom ) {
			$this->block_bot( 'Custom rule: ' . $custom );
		}
	}

	/**
	 * Block a bad bot and respond with 403.
	 *
	 * Database writes are de-duplicated per IP for 15 minutes so a flood of
	 * blocked requests cannot amplify into a flood of database writes.
	 *
	 * @since 1.2.0
	 * @param string $label Human-readable reason.
	 */
	private function block_bot( $label ) {
		$ip = Turbo_Guard_Scanner::get_client_ip();

		if ( $ip ) {
			$dedupe_key = 'turbo_guard_bot_block_' . md5( $ip );
			if ( false === get_transient( $dedupe_key ) ) {
				Turbo_Guard_Scanner::log_event(
					'bot_blocked',
					'warning',
					'Bad bot blocked: ' . $label . ' (IP: ' . $ip . ')'
				);
				Turbo_Guard_Firewall::block_ip( $ip, 'Bad bot: ' . $label, DAY_IN_SECONDS );
				set_transient( $dedupe_key, 1, 15 * MINUTE_IN_SECONDS );
			}
		} else {
			Turbo_Guard_Scanner::log_event(
				'bot_blocked',
				'warning',
				'Bad bot blocked: ' . $label
			);
		}

		if ( ! headers_sent() ) {
			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
		}

		echo 'Access denied.'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static plain-text response.
		exit;
	}

	/**
	 * Verify that a request claiming to be a known crawler really is one.
	 *
	 * Resolves the source IP's reverse DNS and checks the hostname against the
	 * crawler's registered domain suffix. Results are cached per IP for 12
	 * hours. If reverse DNS is unavailable (disabled by the host or the record
	 * does not exist) the check fails open — we never risk blocking a genuine
	 * crawler just because the server cannot resolve DNS.
	 *
	 * @since 1.2.0
	 * @param string $ua User agent string.
	 * @return bool True if the request is a genuine crawler.
	 */
	private function verify_crawler_ip( $ua ) {
		$domains = self::crawler_domains_for_ua( $ua );

		// No verifiable domain on file — trust the user agent.
		if ( empty( $domains ) ) {
			return true;
		}

		$ip = Turbo_Guard_Scanner::get_client_ip();
		if ( ! $ip ) {
			return true; // No IP to check — fail open.
		}

		// If a proxy/CDN is in front of the site but its address is not
		// registered as a trusted proxy, get_client_ip() returns the proxy IP
		// rather than the real client. Reverse DNS on a proxy IP would never
		// match the crawler's domain, so we must fail open here instead of
		// blocking genuine crawlers.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only presence is checked.
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
		$forwarded = ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] )
			|| ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			|| ! empty( $_SERVER['HTTP_X_REAL_IP'] );        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( $forwarded && $ip === $remote ) {
			return true; // Likely behind an untrusted proxy — fail open.
		}

		if ( ! function_exists( 'gethostbyaddr' ) ) {
			return true; // Reverse DNS disabled on this host — fail open.
		}

		$cache_key = 'turbo_guard_bot_rdns_' . md5( $ip );
		$cached    = get_transient( $cache_key );
		if ( is_string( $cached ) && '' !== $cached ) {
			return '1' === $cached;
		}

		$host = gethostbyaddr( $ip );

		// Unresolvable (returns the IP itself or empty) — fail open.
		if ( ! $host || $host === $ip ) {
			set_transient( $cache_key, 'x', 12 * HOUR_IN_SECONDS );
			return true;
		}

		$host   = strtolower( trim( $host, '.' ) );
		$genuine = false;
		foreach ( $domains as $domain ) {
			$domain = strtolower( $domain );
			if ( $host === $domain || substr( $host, -strlen( '.' . $domain ) ) === '.' . $domain ) {
				$genuine = true;
				break;
			}
		}

		set_transient( $cache_key, $genuine ? '1' : '0', 12 * HOUR_IN_SECONDS );

		return $genuine;
	}

	// =========================================================
	// DETECTION HELPERS
	// =========================================================

	/**
	 * Match a user agent against a signature => label map.
	 *
	 * @since 1.2.0
	 * @param array  $list Signature => label map.
	 * @param string $ua   User agent string.
	 * @return array|false { signature, label } on match, false otherwise.
	 */
	private static function match_list( array $list, $ua ) {
		if ( '' === $ua ) {
			return false;
		}
		foreach ( $list as $signature => $label ) {
			if ( false !== stripos( $ua, $signature ) ) {
				return array(
					'signature' => $signature,
					'label'     => $label,
				);
			}
		}
		return false;
	}

	/**
	 * Match a user agent against the admin-defined custom rules.
	 *
	 * @since 1.2.0
	 * @param string $ua User agent string.
	 * @return string|false The matched rule, or false.
	 */
	private static function match_custom( $ua ) {
		$raw = (string) get_option( 'turbo_guard_bot_custom_blocked', '' );
		$raw = trim( $raw );
		if ( '' === $raw || '' === $ua ) {
			return false;
		}

		$lines = preg_split( '/\r\n|\r|\n/', $raw );
		if ( ! is_array( $lines ) ) {
			return false;
		}

		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			if ( false !== stripos( $ua, $line ) ) {
				return $line;
			}
		}

		return false;
	}

	/**
	 * Resolve the verifiable rDNS suffixes for the first crawler matched in a UA.
	 *
	 * @since 1.2.0
	 * @param string $ua User agent string.
	 * @return string[] Domain suffixes, or an empty array.
	 */
	private static function crawler_domains_for_ua( $ua ) {
		if ( '' === $ua ) {
			return array();
		}
		foreach ( self::$crawlers as $signature => $data ) {
			if ( false !== stripos( $ua, $signature ) ) {
				return $data[1];
			}
		}
		return array();
	}

	// =========================================================
	// PUBLIC LISTS + STATS
	// =========================================================

	/**
	 * Get the always-on bad-bot list (filterable by the Pro add-on).
	 *
	 * @since 1.2.0
	 * @return array Signature => label map.
	 */
	public static function get_bad_bots() {
		return apply_filters( 'turbo_guard_bad_bots', self::$bad_bots );
	}

	/**
	 * Get the opt-in aggressive bot list.
	 *
	 * @since 1.2.0
	 * @return array Signature => label map.
	 */
	public static function get_aggressive_bots() {
		return apply_filters( 'turbo_guard_aggressive_bots', self::$aggressive_bots );
	}

	/**
	 * Get the good-bot list as signature => label.
	 *
	 * @since 1.2.0
	 * @return array
	 */
	public static function get_good_bots() {
		$good = array();
		foreach ( self::$crawlers as $signature => $data ) {
			$good[ $signature ] = $data[0];
		}
		return $good;
	}

	/**
	 * Detect if a user agent is a known good bot.
	 *
	 * @since 1.2.0
	 * @param string $ua User agent string.
	 * @return string|false Bot name or false.
	 */
	public static function detect_good_bot( $ua ) {
		if ( '' === $ua ) {
			return false;
		}
		foreach ( self::$crawlers as $signature => $data ) {
			if ( false !== stripos( $ua, $signature ) ) {
				return $data[0];
			}
		}
		return false;
	}

	/**
	 * Detect if a user agent is a known bad bot (always-on list).
	 *
	 * @since 1.2.0
	 * @param string $ua User agent string.
	 * @return string|false Bot label or false.
	 */
	public static function detect_bad_bot( $ua ) {
		if ( '' === $ua ) {
			return false;
		}
		$match = self::match_list( self::get_bad_bots(), $ua );
		return $match ? $match['label'] : false;
	}

	/**
	 * Get bot lists for the admin UI.
	 *
	 * @since 1.2.0
	 * @return array { good: array, bad: array, aggressive: array }
	 */
	public static function get_bot_lists() {
		return array(
			'good'       => self::get_good_bots(),
			'bad'        => self::get_bad_bots(),
			'aggressive' => self::get_aggressive_bots(),
		);
	}

	/**
	 * Get recent block statistics for the admin UI.
	 *
	 * @since 1.2.0
	 * @return array { total: int, unique: int }
	 */
	public static function get_stats() {
		global $wpdb;

		$since = gmdate( 'Y-m-d H:i:s', time() - ( 7 * DAY_IN_SECONDS ) );

		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_events
				 WHERE event_type = %s AND created_at >= %s",
				'bot_blocked',
				$since
			)
		);

		$unique = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT ip_address) FROM {$wpdb->prefix}turbo_guard_events
				 WHERE event_type = %s AND created_at >= %s",
				'bot_blocked',
				$since
			)
		);

		return array(
			'total'  => $total,
			'unique' => $unique,
		);
	}
}
