<?php
/**
 * Live Traffic Monitor Class.
 *
 * Logs every HTTP request with bot/human detection, geo info, and
 * user-agent parsing. Inspired by Wordfence's wfLog live traffic system.
 *
 * @package TurboGuard
 * @since 1.1.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Live traffic request logging and bot detection.
 *
 * @since 1.1.0
 */
class Turbo_Guard_Live_Traffic {

	/**
	 * Singleton instance.
	 *
	 * @var Turbo_Guard_Live_Traffic|null
	 */
	private static $instance = null;

	/**
	 * Known bot user-agent substrings (lowercase).
	 *
	 * @var string[]
	 */
	private static $bot_signatures = array(
		'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
		'yandexbot', 'sogou', 'exabot', 'facebot', 'ia_archiver',
		'semrushbot', 'ahrefsbot', 'mj12bot', 'dotbot', 'rogerbot',
		'facebookexternalhit', 'twitterbot', 'linkedinbot', 'whatsapp',
		'applebot', 'petalbot', 'bytespider', 'gptbot', 'chatgpt-user',
		'anthropic-ai', 'claudebot', 'cohere-ai', 'perplexitybot',
		'curl/', 'python-requests', 'go-http-client', 'libwww-perl',
		'wget/', 'scrapy/', 'httpie/', 'okhttp/', 'java/', 'php/',
	);

	/**
	 * Get singleton.
	 *
	 * @since 1.1.0
	 * @return Turbo_Guard_Live_Traffic
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
	 * @since 1.1.0
	 */
	private function __construct() {
		if ( 'yes' !== get_option( 'turbo_guard_live_traffic_enabled', 'yes' ) ) {
			return;
		}

		// Log at shutdown so we capture the final HTTP status code.
		if ( function_exists( 'register_shutdown_function' ) ) {
			register_shutdown_function( array( $this, 'log_request' ) );
		}

		// Scheduled cleanup (keep last 10,000 rows / 7 days).
		add_action( 'turbo_guard_traffic_cleanup', array( $this, 'cleanup_old_traffic' ) );
		if ( ! wp_next_scheduled( 'turbo_guard_traffic_cleanup' ) ) {
			wp_schedule_event( time(), 'daily', 'turbo_guard_traffic_cleanup' );
		}
	}

	/**
	 * Log the current HTTP request to the traffic table.
	 *
	 * Called at shutdown — so http_response_code() gives the real status.
	 *
	 * @since 1.1.0
	 */
	public function log_request() {
		global $wpdb;

		// Skip CLI, cron, and admin-ajax (to reduce noise — keep option to re-enable).
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		$ip         = Turbo_Guard_Scanner::get_client_ip();
		$ua         = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 512 ) : '';
		$method     = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
		$uri        = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		$referer    = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';
		$status     = http_response_code() ?: 200;
		$user_id    = get_current_user_id();
		$is_bot     = self::detect_bot( $ua );
		$bot_name   = $is_bot ? self::identify_bot( $ua ) : '';

		$wpdb->insert(
			$wpdb->prefix . 'turbo_guard_traffic',
			array(
				'ip_address'  => $ip,
				'user_agent'  => $ua,
				'method'      => $method,
				'request_uri' => substr( $uri, 0, 512 ),
				'referer'     => substr( $referer, 0, 512 ),
				'status_code' => absint( $status ),
				'user_id'     => $user_id,
				'is_bot'      => $is_bot ? 1 : 0,
				'bot_name'    => $bot_name,
				'created_at'  => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%s', '%s' )
		);
	}

	/**
	 * Detect whether a user-agent string belongs to a bot.
	 *
	 * @since 1.1.0
	 * @param string $ua User-agent string.
	 * @return bool
	 */
	public static function detect_bot( $ua ) {
		if ( '' === $ua ) {
			return true; // No UA = almost certainly a bot/scanner.
		}

		$ua_lower = strtolower( $ua );
		foreach ( self::$bot_signatures as $sig ) {
			if ( false !== strpos( $ua_lower, $sig ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Identify a specific bot name from its user-agent.
	 *
	 * @since 1.1.0
	 * @param string $ua User-agent string.
	 * @return string Bot name or empty string.
	 */
	private static function identify_bot( $ua ) {
		$ua_lower = strtolower( $ua );

		$named_bots = array(
			'googlebot'           => 'Googlebot',
			'bingbot'             => 'Bingbot',
			'slurp'               => 'Yahoo! Slurp',
			'duckduckbot'         => 'DuckDuckBot',
			'baiduspider'         => 'Baiduspider',
			'yandexbot'           => 'YandexBot',
			'semrushbot'          => 'SEMrushBot',
			'ahrefsbot'           => 'AhrefsBot',
			'mj12bot'             => 'Majestic-12',
			'facebookexternalhit' => 'Facebook',
			'twitterbot'          => 'Twitterbot',
			'linkedinbot'         => 'LinkedInBot',
			'applebot'            => 'Applebot',
			'gptbot'              => 'GPTBot (OpenAI)',
			'chatgpt-user'        => 'ChatGPT User',
			'claudebot'           => 'ClaudeBot',
			'perplexitybot'       => 'PerplexityBot',
			'curl/'               => 'cURL',
			'python-requests'     => 'Python Requests',
			'wget/'               => 'Wget',
			'scrapy/'             => 'Scrapy',
		);

		foreach ( $named_bots as $sig => $name ) {
			if ( false !== strpos( $ua_lower, $sig ) ) {
				return $name;
			}
		}

		return 'Bot';
	}

	/**
	 * Get recent traffic entries for the admin table.
	 *
	 * @since 1.1.0
	 * @param int    $limit  Max rows.
	 * @param string $filter 'all' | 'bots' | 'humans' | '404' | 'blocked'.
	 * @return array
	 */
	public static function get_traffic( $limit = 100, $filter = 'all' ) {
		return self::get_traffic_paged( $limit, 0, $filter );
	}

	/**
	 * Get paginated traffic entries.
	 *
	 * @since 1.1.0
	 * @param int    $per_page Rows per page.
	 * @param int    $offset   Row offset.
	 * @param string $filter   Filter key.
	 * @return array
	 */
	public static function get_traffic_paged( $per_page = 50, $offset = 0, $filter = 'all' ) {
		global $wpdb;

		$where = self::build_where( $filter );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}turbo_guard_traffic {$where} ORDER BY id DESC LIMIT %d OFFSET %d",
				absint( $per_page ),
				absint( $offset )
			)
		);
	}

	/**
	 * Get total traffic count for a given filter (used for pagination).
	 *
	 * @since 1.1.0
	 * @param string $filter Filter key.
	 * @return int
	 */
	public static function get_traffic_count( $filter = 'all' ) {
		global $wpdb;
		$where = self::build_where( $filter );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_traffic {$where}" );
	}

	/**
	 * Build WHERE clause for traffic queries.
	 *
	 * Returns a validated safe WHERE string — only allows known filter values
	 * so there is no SQL injection risk from the interpolation.
	 *
	 * @since 1.1.0
	 * @param string $filter Filter key.
	 * @return string SQL WHERE clause (empty string for 'all').
	 */
	private static function build_where( $filter ) {
		// Allowlist — only these exact values produce a WHERE clause.
		// Any unexpected value falls through to empty (show all).
		$allowed = array(
			'bots'    => 'WHERE is_bot = 1',
			'humans'  => 'WHERE is_bot = 0',
			'404'     => 'WHERE status_code = 404',
			'blocked' => 'WHERE status_code = 403',
		);
		return isset( $allowed[ $filter ] ) ? $allowed[ $filter ] : '';
	}

	/**
	 * Get traffic summary stats (last 24 hours).
	 *
	 * @since 1.1.0
	 * @return array
	 */
	public static function get_stats() {
		global $wpdb;

		// Cache for 5 minutes — stats are approximate, no need to hit DB every page load.
		$cache_key = 'turbo_guard_traffic_stats';
		$cached    = wp_cache_get( $cache_key, 'turbo_guard' );
		if ( false !== $cached ) {
			return $cached;
		}

		$since = gmdate( 'Y-m-d H:i:s', strtotime( '-24 hours' ) );

		$stats = array(
			'total'   => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_traffic WHERE created_at > %s", $since ) ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'humans'  => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_traffic WHERE is_bot = 0 AND created_at > %s", $since ) ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'bots'    => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_traffic WHERE is_bot = 1 AND created_at > %s", $since ) ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'blocked' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_traffic WHERE status_code = 403 AND created_at > %s", $since ) ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'errors'  => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_traffic WHERE status_code >= 400 AND created_at > %s", $since ) ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		);

		wp_cache_set( $cache_key, $stats, 'turbo_guard', 5 * MINUTE_IN_SECONDS );

		return $stats;
	}

	/**
	 * Delete traffic older than 7 days, and cap the table at 10,000 rows.
	 *
	 * @since 1.1.0
	 */
	public function cleanup_old_traffic() {
		global $wpdb;

		// Delete rows older than 7 days.
		$wpdb->query(
			"DELETE FROM {$wpdb->prefix}turbo_guard_traffic
			 WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)"
		);

		// Cap at 10,000 most recent rows.
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_traffic" );
		if ( $count > 10000 ) {
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->prefix}turbo_guard_traffic
					 ORDER BY id ASC LIMIT %d",
					$count - 10000
				)
			);
		}
	}
}
