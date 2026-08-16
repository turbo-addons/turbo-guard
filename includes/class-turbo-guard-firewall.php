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

		// Rate limiting check.
		if ( ! $is_admin && $this->is_rate_limited() ) {
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
		global $wpdb;

		$ip = Turbo_Guard_Scanner::get_client_ip();
		if ( ! $ip ) {
			return false;
		}

		// Fetch all active blocklist entries.
		$entries = $wpdb->get_results(
			"SELECT ip_address FROM {$wpdb->prefix}turbo_guard_ip_blocklist
			 WHERE (expires_at IS NULL OR expires_at > NOW())"
		);

		if ( empty( $entries ) ) {
			return false;
		}

		foreach ( $entries as $entry ) {
			if ( self::ip_matches_rule( $ip, $entry->ip_address ) ) {
				return true;
			}
		}

		return false;
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
	 * Rate limiting check (max 120 requests per minute per IP).
	 *
	 * @since 1.0.0
	 * @return bool True if rate limit exceeded.
	 */
	private function is_rate_limited() {
		$ip = Turbo_Guard_Scanner::get_client_ip();
		if ( ! $ip ) {
			return false;
		}

		$transient_key = 'turbo_guard_rate_' . md5( $ip );
		$requests      = get_transient( $transient_key );

		if ( false === $requests ) {
			$requests = 0;
		}

		++$requests;
		set_transient( $transient_key, $requests, MINUTE_IN_SECONDS );

		// Allow 120 requests per minute (2 per second average).
		return $requests > 120;
	}

	/**
	 * Detect SQL injection patterns in request.
	 *
	 * @since 1.0.0
	 * @return bool True if SQL injection detected.
	 */
	private function detect_sql_injection() {
		$patterns = array(
			'/(\bUNION\b.*\bSELECT\b)/i',
			'/(\bSELECT\b.*\bFROM\b.*\bWHERE\b)/i',
			'/(\bINSERT\b.*\bINTO\b.*\bVALUES\b)/i',
			'/(\bUPDATE\b.*\bSET\b)/i',
			'/(\bDELETE\b.*\bFROM\b)/i',
			'/(\bDROP\b.*\bTABLE\b)/i',
			'/(\bSHOW\b.*\bTABLES\b)/i',
			'/(\bOR\b.*1\s*=\s*1)/i',
			'/(\bAND\b.*1\s*=\s*1)/i',
			'/(\bEXEC\b\s*\()/i',
			'/(CONCAT\s*\(.*CHAR)/i',
			'/0x[0-9a-f]{2,}/i', // Hex encoding.
		);

		// phpcs:ignore WordPress.Security.NonceVerification -- WAF inspects raw request data for attack patterns; not a state-changing form action.
		$check_vars = array_merge( $_GET, $_POST );

		foreach ( $check_vars as $value ) {
			if ( ! is_string( $value ) ) {
				continue;
			}

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

		// phpcs:ignore WordPress.Security.NonceVerification -- WAF inspects raw request data for attack patterns; not a state-changing form action.
		$check_vars = array_merge( $_GET, $_POST );

		foreach ( $check_vars as $value ) {
			if ( ! is_string( $value ) ) {
				continue;
			}

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
		$check_vars = array_merge( $_GET, $_POST );
		foreach ( $check_vars as $value ) {
			if ( is_string( $value ) && preg_match( '/(\.\.[\/\\\\]){2,}/', $value ) ) {
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

		return (bool) $deleted;
	}

	/**
	 * Cleanup old firewall logs (keep last 30 days).
	 *
	 * @since 1.0.0
	 */
	public function cleanup_old_logs() {
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
	}
}
