<?php
/**
 * Web Application Firewall Class.
 *
 * Protects against common attacks: SQL injection, XSS, rate limiting, IP blocking.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Security scanner requires direct database access.

/**
 * Firewall protection class.
 *
 * @since 1.0.0
 */
class Turbo_Guard_Firewall {

	/**
	 * Single instance.
	 *
	 * @var Turbo_Guard_Firewall|null
	 */
	private static $instance = null;

	/**
	 * Cached list of active IP blocklist rules (flat array of rule strings).
	 *
	 * Kept in a static so the blocklist is resolved at most once per request,
	 * and in the object cache (when a persistent cache is installed) so it is
	 * not re-queried on every page view. Cleared whenever the blocklist changes.
	 *
	 * @var array|null
	 */
	private static $blocklist_entries = null;

	/**
	 * Cached raw request body (read at most once per request).
	 *
	 * @var string|null
	 */
	private static $raw_body = null;

	/**
	 * Get instance.
	 *
	 * @since 1.0.0
	 * @return Turbo_Guard_Firewall
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 *
	 * @since 1.0.0
	 */
	private function __construct() {
		// Only run if firewall is enabled.
		if ( 'yes' !== get_option( 'turbo_guard_firewall_enabled', 'yes' ) ) {
			return;
		}

		add_action( 'init', array( $this, 'check_request' ), 1 );
		add_action( 'wp_loaded', array( $this, 'cleanup_old_logs' ), 10 );

		// 404 rate limiting — fires after WordPress resolves the request, which
		// is the earliest point `is_404()` is reliable.
		if ( $this->rate_limiting_enabled() ) {
			add_action( 'template_redirect', array( $this, 'check_404_rate_limit' ), 1 );
		}
	}

	/**
	 * Check incoming request for threats.
	 *
	 * @since 1.0.0
	 */
	public function check_request() {
		// Skip for admin users (but still log).
		$is_admin = is_user_logged_in() && current_user_can( 'manage_options' );

		// Check if IP is blocked.
		if ( $this->is_ip_blocked() ) {
			$this->block_request( __( 'IP address is blocked', 'turbo-guard' ) );
			return;
		}

		// Rate limiting check — exempt ALL logged-in users. Bots and attackers
		// are anonymous, so throttling is applied only to unauthenticated
		// visitors. This prevents real, authenticated users (editors, shop
		// managers, customers) from being locked out by heavy but legitimate
		// browsing. Brute-force login protection is handled separately.
		if ( ! is_user_logged_in() && $this->rate_limiting_enabled() && $this->is_rate_limited() ) {
			$this->block_request( __( 'Too many requests - rate limit exceeded', 'turbo-guard' ) );
			return;
		}

		// SQL injection detection.
		if ( ! $is_admin && $this->detect_sql_injection() ) {
			$this->block_request( __( 'SQL injection attempt detected', 'turbo-guard' ) );
			return;
		}

		// XSS detection.
		if ( ! $is_admin && $this->detect_xss() ) {
			$this->block_request( __( 'Cross-site scripting (XSS) attempt detected', 'turbo-guard' ) );
			return;
		}

		// Directory traversal.
		if ( ! $is_admin && $this->detect_directory_traversal() ) {
			$this->block_request( __( 'Directory traversal attempt detected', 'turbo-guard' ) );
			return;
		}

		// File upload attacks.
		// phpcs:ignore WordPress.Security.NonceVerification -- WAF inspects raw request data for attack patterns; not a state-changing form action.
		if ( ! empty( $_FILES ) && ! $is_admin && $this->detect_malicious_upload() ) {
			$this->block_request( __( 'Malicious file upload attempt detected', 'turbo-guard' ) );
			return;
		}
	}

	/**
	 * Check if current IP is in blocklist.
	 *
	 * Supports exact match, CIDR notation (192.168.1.0/24),
	 * IP ranges (10.0.0.1-10.0.0.255), and wildcards (192.168.*).
	 *
	 * @since 1.0.0
	 * @return bool True if blocked.
	 */
	private function is_ip_blocked() {
		$ip = Turbo_Guard_Scanner::get_client_ip();
		if ( ! $ip ) {
			return false;
		}

		// Rules are cached (see get_blocklist_entries()) so this loop runs
		// against an in-memory/object-cached list instead of a fresh DB query.
		foreach ( $this->get_blocklist_entries() as $ip_address ) {
			if ( self::ip_matches_rule( $ip, $ip_address ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Fetch the active IP blocklist rules, with caching.
	 *
	 * Returns a flat array of rule strings (exact IPs, CIDR, ranges, wildcards).
	 * The result is cached in a static (once per request) and in the object cache
	 * for 60 seconds when a persistent object cache is installed, so the firewall
	 * does not perform a full-table scan on every page view. The cache is
	 * invalidated immediately whenever the blocklist is modified.
	 *
	 * @since 1.1.4
	 * @return string[] Active blocklist rules.
	 */
	private function get_blocklist_entries() {
		if ( null !== self::$blocklist_entries ) {
			return self::$blocklist_entries;
		}

		$cache_key = 'turbo_guard_blocklist';
		$entries   = wp_cache_get( $cache_key, 'turbo_guard' );

		if ( ! is_array( $entries ) ) {
			global $wpdb;

			$rows = $wpdb->get_col(
				"SELECT ip_address FROM {$wpdb->prefix}turbo_guard_ip_blocklist
				 WHERE (expires_at IS NULL OR expires_at > NOW())"
			);

			$entries = is_array( $rows ) ? $rows : array();
			wp_cache_set( $cache_key, $entries, 'turbo_guard', 60 );
		}

		self::$blocklist_entries = $entries;

		return self::$blocklist_entries;
	}

	/**
	 * Invalidate the cached blocklist (static + object cache).
	 *
	 * Called after any block/unblock/expiry mutation so the next request sees the
	 * updated list immediately.
	 *
	 * @since 1.1.4
	 */
	private static function clear_blocklist_cache() {
		self::$blocklist_entries = null;
		wp_cache_delete( 'turbo_guard_blocklist', 'turbo_guard' );
	}

	/**
	 * Test whether an IP address matches a blocklist rule.
	 *
	 * Supports:
	 *   - Exact:   "1.2.3.4"
	 *   - CIDR:    "1.2.3.0/24"
	 *   - Range:   "1.2.3.1-1.2.3.100"
	 *   - Wildcard:"1.2.3.*" or "1.2.*.*"
	 *
	 * @since 1.1.0
	 * @param string $ip   The client IP address.
	 * @param string $rule The blocklist rule string.
	 * @return bool True if the IP matches the rule.
	 */
	public static function ip_matches_rule( $ip, $rule ) {
		$rule = trim( $rule );

		// CIDR notation — e.g. 192.168.0.0/16.
		if ( strpos( $rule, '/' ) !== false ) {
			return self::ip_in_cidr( $ip, $rule );
		}

		// IP range — e.g. 10.0.0.1-10.0.0.255.
		if ( strpos( $rule, '-' ) !== false ) {
			return self::ip_in_range( $ip, $rule );
		}

		// Wildcard — e.g. 192.168.*.* or 10.*.
		if ( strpos( $rule, '*' ) !== false ) {
			return self::ip_matches_wildcard( $ip, $rule );
		}

		// Exact match.
		return ( $ip === $rule );
	}

	/**
	 * CIDR match.
	 *
	 * @since 1.1.0
	 * @param string $ip   Client IP.
	 * @param string $cidr CIDR block, e.g. "192.168.0.0/24".
	 * @return bool
	 */
	private static function ip_in_cidr( $ip, $cidr ) {
		list( $subnet, $bits ) = explode( '/', $cidr, 2 );
		$bits      = absint( $bits );
		$ip_long   = ip2long( $ip );
		$sub_long  = ip2long( $subnet );

		if ( false === $ip_long || false === $sub_long || $bits < 0 || $bits > 32 ) {
			return false;
		}

		$mask = $bits > 0 ? ( ~0 << ( 32 - $bits ) ) : 0;
		return ( ( $ip_long & $mask ) === ( $sub_long & $mask ) );
	}

	/**
	 * IP range match.
	 *
	 * @since 1.1.0
	 * @param string $ip    Client IP.
	 * @param string $range Range, e.g. "10.0.0.1-10.0.0.255".
	 * @return bool
	 */
	private static function ip_in_range( $ip, $range ) {
		list( $start, $end ) = explode( '-', $range, 2 );
		$ip_long    = ip2long( trim( $ip ) );
		$start_long = ip2long( trim( $start ) );
		$end_long   = ip2long( trim( $end ) );

		if ( false === $ip_long || false === $start_long || false === $end_long ) {
			return false;
		}

		return ( $ip_long >= $start_long && $ip_long <= $end_long );
	}

	/**
	 * Wildcard match.
	 *
	 * @since 1.1.0
	 * @param string $ip      Client IP.
	 * @param string $pattern Wildcard pattern, e.g. "192.168.*" or "10.*.*.*".
	 * @return bool
	 */
	private static function ip_matches_wildcard( $ip, $pattern ) {
		$regex = '/^' . str_replace(
			array( '.', '*' ),
			array( '\\.', '[0-9]{1,3}' ),
			$pattern
		) . '$/';
		return (bool) preg_match( $regex, $ip );
	}

	/**
	 * Rate limiting check for normal page requests.
	 *
	 * The requests-per-minute limit is configured on the Firewall screen
	 * (default 120). Uses a true fixed 60-second window — not a self-renewing
	 * sliding window, which under continuous traffic would never expire.
	 * Prefers the object cache (Redis/Memcached) so a busy site does not pay a
	 * database write on every request, and falls back to a transient only when
	 * no persistent object cache is installed. Offenders are auto-blocked.
	 *
	 * @since 1.0.0
	 * @return bool True if rate limit exceeded.
	 */
	private function is_rate_limited() {
		$ip = Turbo_Guard_Scanner::get_client_ip();
		if ( ! $ip ) {
			return false;
		}

		$limit  = max( 1, absint( apply_filters( 'turbo_guard_rate_limit', get_option( 'turbo_guard_rate_limit', 120 ) ) ) );
		$window = MINUTE_IN_SECONDS;
		$key    = 'turbo_guard_rate_' . md5( $ip );

		$result = $this->check_rate_window( $key, $window, $limit );

		// On the exact request that crosses the limit, auto-block the IP for the
		// configured duration so the offender stops hitting the WAF entirely.
		if ( $result['crossed'] ) {
			self::block_ip(
				$ip,
				__( 'Rate limit exceeded — too many requests per minute', 'turbo-guard' ),
				$this->rate_limit_block_duration()
			);
			self::log_rate_limit( $ip, 'requests', $result['count'], $limit );
		}

		return $result['exceeded'];
	}

	/**
	 * Whether rate limiting (and 404 throttling) is enabled.
	 *
	 * @since 1.1.4
	 * @return bool
	 */
	private function rate_limiting_enabled() {
		return 'yes' === get_option( 'turbo_guard_rate_limiting_enabled', 'yes' );
	}

	/**
	 * How long (in seconds) an IP is auto-blocked when it breaks a rate limit.
	 *
	 * @since 1.1.4
	 * @return int
	 */
	private function rate_limit_block_duration() {
		return max( 60, absint( get_option( 'turbo_guard_rate_limit_block_duration', 300 ) ) );
	}

	/**
	 * Advance a fixed-window request counter for the current IP.
	 *
	 * Uses a true fixed 60-second window — not a self-renewing sliding window,
	 * which under continuous traffic would never expire. Prefers the object
	 * cache (Redis/Memcached) so a busy site does not pay a database write on
	 * every request, and falls back to a transient only when no persistent
	 * object cache is installed.
	 *
	 * @since 1.1.4
	 * @param string $key    Cache key for this counter.
	 * @param int    $window Window size in seconds.
	 * @param int    $limit  Requests allowed per window.
	 * @return array { exceeded: bool, crossed: bool, count: int } crossed = this
	 *               request pushed the counter over the limit; count = the
	 *               current request count for the window.
	 */
	private function check_rate_window( $key, $window, $limit ) {
		$state = wp_using_ext_object_cache()
			? wp_cache_get( $key, 'turbo_guard' )
			: get_transient( $key );

		$now     = time();
		$crossed = false;

		if ( is_array( $state ) && ( $now - (int) $state['start'] ) < $window ) {
			$previous = (int) $state['count'];
			++$state['count'];
			$crossed = ( $previous <= $limit && (int) $state['count'] > $limit );
		} else {
			// New window (or first request) — reset the counter.
			$state = array(
				'start' => $now,
				'count' => 1,
			);
		}

		if ( wp_using_ext_object_cache() ) {
			wp_cache_set( $key, $state, 'turbo_guard', $window );
		} else {
			set_transient( $key, $state, $window );
		}

		return array(
			'exceeded' => (int) $state['count'] > $limit,
			'crossed'  => $crossed,
			'count'    => (int) $state['count'],
		);
	}

	/**
	 * Throttle IPs that trigger an abnormal number of 404s per minute.
	 *
	 * Wordfence-style: a burst of requests for non-existent URLs is a hallmark
	 * of scanners and bots. When an IP crosses the configured 404 limit it is
	 * blocked for the configured duration.
	 *
	 * @since 1.1.4
	 */
	public function check_404_rate_limit() {
		// Only act on genuine 404s from anonymous visitors — never throttle
		// logged-in users (they are authenticated and trusted).
		if ( ! is_404() || is_user_logged_in() ) {
			return;
		}

		$ip = Turbo_Guard_Scanner::get_client_ip();
		if ( ! $ip ) {
			return;
		}

		$limit  = max( 1, absint( apply_filters( 'turbo_guard_rate_limit_404', get_option( 'turbo_guard_rate_limit_404', 60 ) ) ) );
		$window = MINUTE_IN_SECONDS;
		$key    = 'turbo_guard_rate404_' . md5( $ip );

		$result = $this->check_rate_window( $key, $window, $limit );

		if ( $result['crossed'] ) {
			self::block_ip(
				$ip,
				__( 'Too many 404 requests — possible scanner', 'turbo-guard' ),
				$this->rate_limit_block_duration()
			);
			self::log_rate_limit( $ip, '404', $result['count'], $limit );
		}

		if ( $result['exceeded'] ) {
			$this->block_request( __( 'Too many 404 requests - rate limit exceeded', 'turbo-guard' ) );
		}
	}

	/**
	 * Record a rate-limit violation for the Firewall activity log.
	 *
	 * @since 1.1.4
	 * @param string $ip       Client IP.
	 * @param string $rule     'requests' or '404'.
	 * @param int    $requests Number of requests made in the window.
	 * @param int    $limit    Configured limit.
	 */
	private static function log_rate_limit( $ip, $rule, $requests, $limit ) {
		global $wpdb;

		$wpdb->insert(
			$wpdb->prefix . 'turbo_guard_rate_limit_log',
			array(
				'ip_address' => $ip,
				'rule_type'  => sanitize_key( $rule ),
				'requests'   => absint( $requests ),
				'limit'      => absint( $limit ),
			),
			array( '%s', '%s', '%d', '%d' )
		);
	}

	/**
	 * Build the flat list of request values inspected by the WAF.
	 *
	 * Covers $_GET, $_POST, $_COOKIE, and the raw request body (JSON, XML and
	 * other unparsed payloads). Headers are excluded by default because they are
	 * far more prone to false positives (user-agent, referer, etc.); a Pro
	 * add-on can opt specific headers in via the `turbo_guard_inspect_headers`
	 * filter.
	 *
	 * @since 1.1.5
	 * @return string[] Flat list of scalar string values to inspect.
	 */
	private function get_inspection_values() {
		// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- WAF inspects raw request data for attack patterns; not a state-changing form action.
		$values = array();

		foreach ( array( $_GET, $_POST, $_COOKIE ) as $source ) {
			$this->flatten_values( $source, $values );
		}

		$raw = $this->get_raw_body();
		if ( '' !== $raw ) {
			$values[] = $raw;

			// Inspect the decoded JSON structure too, so nested strings are seen
			// individually and not just as one serialized blob.
			$decoded = json_decode( $raw, true );
			if ( is_array( $decoded ) ) {
				$this->flatten_values( $decoded, $values );
			}
		}

		foreach ( (array) apply_filters( 'turbo_guard_inspect_headers', array() ) as $header ) {
			$key = 'HTTP_' . strtoupper( str_replace( '-', '_', (string) $header ) );
			if ( isset( $_SERVER[ $key ] ) ) {
				$values[] = wp_unslash( $_SERVER[ $key ] );
			}
		}
		// phpcs:enable

		return $values;
	}

	/**
	 * Recursively collect scalar string values from a mixed structure.
	 *
	 * @since 1.1.5
	 * @param mixed $value Array, object or scalar to flatten.
	 * @param array $out   Accumulator (passed by reference).
	 */
	private function flatten_values( $value, &$out ) {
		if ( is_string( $value ) ) {
			$out[] = $value;
			return;
		}

		if ( is_array( $value ) || is_object( $value ) ) {
			foreach ( (array) $value as $child ) {
				$this->flatten_values( $child, $out );
			}
		}
	}

	/**
	 * Fetch the raw request body once per request.
	 *
	 * WordPress does not mirror application/json (REST/headless) or XML bodies
	 * into $_POST, so those requests would otherwise bypass every signature
	 * below. The body is read once, cached in a static, and capped to a sane
	 * size so an attacker cannot exhaust memory with an oversized payload.
	 *
	 * @since 1.1.5
	 * @return string Raw request body (empty when there is nothing to inspect).
	 */
	private function get_raw_body() {
		if ( null !== self::$raw_body ) {
			return self::$raw_body;
		}

		self::$raw_body = '';

		// Skip immediately when there is no body, so we never read php://input
		// on ordinary GET page views.
		if ( empty( $_SERVER['CONTENT_LENGTH'] ) || absint( $_SERVER['CONTENT_LENGTH'] ) <= 0 ) {
			return self::$raw_body;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- WAF inspects raw request data.
		$content_type = isset( $_SERVER['CONTENT_TYPE'] )
			? strtolower( sanitize_text_field( wp_unslash( $_SERVER['CONTENT_TYPE'] ) ) )
			: '';

		// Form-encoded and multipart bodies are already parsed into $_POST (and
		// multipart is not readable via php://input), so only raw bodies need
		// explicit reading.
		if ( false !== strpos( $content_type, 'multipart/' )
			|| false !== strpos( $content_type, 'application/x-www-form-urlencoded' ) ) {
			return self::$raw_body;
		}

		$max_bytes = (int) apply_filters( 'turbo_guard_max_body_inspect_bytes', 1048576 );
		$body      = @file_get_contents( 'php://input', false, null, 0, $max_bytes ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		self::$raw_body = is_string( $body ) ? $body : '';

		return self::$raw_body;
	}

	/**
	 * Detect SQL injection patterns in request.
	 *
	 * @since 1.0.0
	 * @return bool True if SQL injection detected.
	 */
	private function detect_sql_injection() {
		$patterns = array(
			'/(\bUNION\b[\s\S]*\bSELECT\b)/i',
			'/(\bSELECT\b[\s\S]*\bFROM\b[\s\S]*\bWHERE\b)/i',
			'/(\bINSERT\b[\s\S]*\bINTO\b[\s\S]*\bVALUES\b)/i',
			'/(\bUPDATE\b[\s\S]*\bSET\b)/i',
			'/(\bDELETE\b[\s\S]*\bFROM\b)/i',
			'/(\bDROP\b[\s\S]*\bTABLE\b)/i',
			'/(\bSHOW\b[\s\S]*\bTABLES\b)/i',
			"/(\bor\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+)/i",
			"/(\band\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+)/i",
			'/(\bEXEC\b\s*\()/i',
			'/(\bCONCAT\s*\([\s\S]*\bCHAR\s*\()/i',
			"/(['\"`])\s*0x[0-9a-f]{2,}/i",
			'/(\bCHAR\s*\(\s*0x[0-9a-f]{2,})/i',
			'/\b0x[0-9a-f]{10,}\b/i',
		);

		foreach ( $this->get_inspection_values() as $value ) {
			foreach ( $patterns as $pattern ) {
				if ( preg_match( $pattern, $value ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Detect XSS (Cross-Site Scripting) patterns.
	 *
	 * @since 1.0.0
	 * @return bool True if XSS detected.
	 */
	private function detect_xss() {
		$patterns = array(
			'/<script[^>]*>.*<\/script>/is',
			'/<iframe[^>]*>/i',
			'/javascript\s*:/i',
			'/on(load|error|click|mouse)\s*=/i',
			'/<embed[^>]*>/i',
			'/<object[^>]*>/i',
		);

		foreach ( $this->get_inspection_values() as $value ) {
			// Normalize a single round of URL encoding so percent-encoded
			// payloads are still seen, then match against the signatures.
			$decoded = urldecode( $value );
			foreach ( $patterns as $pattern ) {
				if ( preg_match( $pattern, $decoded ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Detect directory traversal attempts (../, ..\\).
	 *
	 * @since 1.0.0
	 * @return bool True if detected.
	 */
	private function detect_directory_traversal() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		if ( preg_match( '/(\.\.[\/\\\\]){2,}/', $request_uri ) ) {
			return true;
		}

		// phpcs:ignore WordPress.Security.NonceVerification -- WAF inspects raw request data for attack patterns; not a state-changing form action.
		foreach ( $this->get_inspection_values() as $value ) {
			if ( preg_match( '/(\.\.[\/\\\\]){2,}/', $value ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Detect malicious file uploads (PHP, EXE, etc.).
	 *
	 * @since 1.0.0
	 * @return bool True if malicious file detected.
	 */
	private function detect_malicious_upload() {
		$dangerous_extensions = array( 'php', 'php3', 'php4', 'php5', 'phtml', 'pht', 'exe', 'com', 'bat', 'sh', 'cgi' );

		// phpcs:ignore WordPress.Security.NonceVerification -- WAF inspects raw request data for attack patterns; not a state-changing form action.
		foreach ( $_FILES as $file ) {
			if ( empty( $file['name'] ) ) {
				continue;
			}

			$filename  = sanitize_file_name( $file['name'] );
			$extension = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

			// Check double extensions (e.g., file.php.jpg).
			$parts = explode( '.', $filename );
			if ( count( $parts ) > 2 ) {
				$second_ext = strtolower( $parts[ count( $parts ) - 2 ] );
				if ( in_array( $second_ext, $dangerous_extensions, true ) ) {
					return true;
				}
			}

			if ( in_array( $extension, $dangerous_extensions, true ) ) {
				return true;
			}

			// Check file content for PHP tags.
			if ( ! empty( $file['tmp_name'] ) && is_uploaded_file( $file['tmp_name'] ) ) {
				$content = file_get_contents( $file['tmp_name'], false, null, 0, 1024 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				if ( false !== $content && preg_match( '/<\?php/i', $content ) ) {
					return true;
				}

				// Block files containing Japanese/Chinese/Korean SEO spam text.
				if ( false !== $content && preg_match( '/[\x{3040}-\x{30FF}\x{4E00}-\x{9FFF}\x{AC00}-\x{D7A3}]{5,}/u', $content ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Block the request and send 403 response.
	 *
	 * @since 1.0.0
	 * @param string $reason Block reason.
	 */
	private function block_request( $reason ) {
		global $wpdb;

		$ip = Turbo_Guard_Scanner::get_client_ip();

		// Log to firewall table.
		$wpdb->insert(
			$wpdb->prefix . 'turbo_guard_firewall_log',
			array(
				'ip_address'     => $ip,
				'request_uri'    => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
				'request_method' => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
				'block_reason'   => sanitize_text_field( $reason ),
				'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '',
			),
			array( '%s', '%s', '%s', '%s', '%s' )
		);

		// Log security event.
		Turbo_Guard_Scanner::log_event( 'firewall_block', 'warning', $reason );

		// Send 403 response and exit.
		wp_die(
			esc_html__( 'Access Denied', 'turbo-guard' ),
			esc_html__( 'Turbo Guard Firewall', 'turbo-guard' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Add an IP or IP rule to the blocklist.
	 *
	 * Accepts exact IPs, CIDR notation, IP ranges, and wildcards.
	 *
	 * @since 1.0.0
	 * @param string   $ip_address IP or rule string to block.
	 * @param string   $reason     Reason for blocking.
	 * @param int|null $duration   Duration in seconds (null = permanent).
	 * @return bool Success.
	 */
	public static function block_ip( $ip_address, $reason = '', $duration = null ) {
		global $wpdb;

		$ip_address = trim( $ip_address );

		// Validate: must be a valid IP, CIDR, range, or wildcard.
		$is_valid = filter_var( $ip_address, FILTER_VALIDATE_IP )
			|| strpos( $ip_address, '/' ) !== false    // CIDR
			|| strpos( $ip_address, '-' ) !== false    // range
			|| strpos( $ip_address, '*' ) !== false;   // wildcard

		if ( ! $is_valid ) {
			return false;
		}

		$expires_at = null;
		if ( $duration ) {
			$expires_at = gmdate( 'Y-m-d H:i:s', time() + absint( $duration ) );
		}

		$inserted = $wpdb->replace(
			$wpdb->prefix . 'turbo_guard_ip_blocklist',
			array(
				'ip_address' => sanitize_text_field( $ip_address ),
				'reason'     => sanitize_text_field( $reason ),
				'expires_at' => $expires_at,
			),
			array( '%s', '%s', '%s' )
		);

		// Reflect the change immediately for the current and future requests.
		self::clear_blocklist_cache();

		if ( $inserted ) {
			Turbo_Guard_Scanner::log_event(
				'ip_blocked',
				'warning',
				sprintf(
					/* translators: %s: IP/rule */
					__( 'IP/rule blocked: %s', 'turbo-guard' ),
					$ip_address
				)
			);
		}

		return (bool) $inserted;
	}

	/**
	 * Remove an IP or rule from the blocklist.
	 *
	 * @since 1.0.0
	 * @param string $ip_address IP or rule to unblock.
	 * @return bool Success.
	 */
	public static function unblock_ip( $ip_address ) {
		global $wpdb;

		$ip_address = sanitize_text_field( trim( $ip_address ) );
		if ( ! $ip_address ) {
			return false;
		}

		$deleted = $wpdb->delete(
			$wpdb->prefix . 'turbo_guard_ip_blocklist',
			array( 'ip_address' => $ip_address ),
			array( '%s' )
		);

		if ( $deleted ) {
			self::clear_blocklist_cache();
		}

		return (bool) $deleted;
	}

	/**
	 * Cleanup old firewall logs (keep last 30 days).
	 *
	 * Gated by a 24-hour transient so the two DELETE statements run at most once
	 * per day, instead of on every single page view.
	 *
	 * @since 1.0.0
	 */
	public function cleanup_old_logs() {
		if ( get_transient( 'turbo_guard_cleanup_lock' ) ) {
			return;
		}
		set_transient( 'turbo_guard_cleanup_lock', 1, DAY_IN_SECONDS );

		global $wpdb;

		$wpdb->query(
			"DELETE FROM {$wpdb->prefix}turbo_guard_firewall_log
			 WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)"
		);

		// Delete expired IP blocks.
		$wpdb->query(
			"DELETE FROM {$wpdb->prefix}turbo_guard_ip_blocklist
			 WHERE expires_at IS NOT NULL AND expires_at < NOW()"
		);

		// Expired entries are gone — refresh the cached list on the next read.
		self::clear_blocklist_cache();
	}
}
