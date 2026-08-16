<?php
/**
 * Bot Protection Class.
 *
 * Blocks bad bots (scrapers, spam bots, vulnerability scanners) while
 * allowing good bots (Googlebot, Bingbot, etc.) through.
 * Matches MalCare's Bot Protection feature.
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
	 * Known good bots — allowed through always.
	 *
	 * @var array
	 */
	private static $good_bots = array(
		'Googlebot'          => 'googlebot',
		'Bingbot'            => 'bingbot',
		'Slurp'              => 'Yahoo! Slurp',
		'DuckDuckBot'        => 'duckduckbot',
		'Baiduspider'        => 'baiduspider',
		'YandexBot'          => 'yandexbot',
		'facebot'            => 'facebot',
		'ia_archiver'        => 'Alexa',
		'AhrefsBot'          => 'ahrefsbot',
		'SemrushBot'         => 'semrushbot',
		'MJ12bot'            => 'mj12bot',
		'DotBot'             => 'dotbot',
		'rogerbot'           => 'rogerbot',
	);

	/**
	 * Bad bots — blocked when bot protection is enabled.
	 *
	 * @var array
	 */
	private static $bad_bots = array(
		// Vulnerability scanners.
		'sqlmap'             => 'SQLMap (SQL injection scanner)',
		'nikto'              => 'Nikto (vulnerability scanner)',
		'nessus'             => 'Nessus (vulnerability scanner)',
		'masscan'            => 'Masscan (port scanner)',
		'zgrab'              => 'ZGrab (web scanner)',
		'nuclei'             => 'Nuclei (vulnerability scanner)',
		'acunetix'           => 'Acunetix (web scanner)',
		'nmap'               => 'Nmap scripting engine',
		// Scrapers / spam bots.
		'BLEXBot'            => 'BLEXBot (scraper)',
		'MegaIndex'          => 'MegaIndex (scraper)',
		'SputnikBot'         => 'SputnikBot (scraper)',
		'CCBot'              => 'CCBot (scraper)',
		'Barkrowler'         => 'Barkrowler (scraper)',
		'serpstatbot'        => 'SerpstatBot (scraper)',
		'DataForSeoBot'      => 'DataForSeoBot (scraper)',
		'PetalBot'           => 'PetalBot (scraper)',
		'proximic'           => 'Proximic (scraper)',
		'spbot'              => 'SPBot (spam bot)',
		'EmailCollector'     => 'Email harvester',
		'EmailSiphon'        => 'Email harvester',
		'WebBandit'          => 'WebBandit (scraper)',
		'WebEMailExtrac'     => 'Email harvester',
		// Exploit kits / attack tools.
		'WPScan'             => 'WPScan (WordPress scanner)',
		'Jorgee'             => 'Jorgee (vulnerability scanner)',
		'ZmEu'               => 'ZmEu (exploit scanner)',
		'libwww-perl'        => 'libwww-perl (automated attack tool)',
		'python-requests'    => 'Python requests (automated scanner)',
		'Go-http-client'     => 'Go HTTP client (automated scanner)',
		'curl'               => 'cURL (automated scanner — non-browser)',
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
	 * Constructor.
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

	/**
	 * Check if the current request is from a bad bot and block it.
	 *
	 * @since 1.2.0
	 */
	public function check_bot() {
		// Skip for logged-in admins and cron.
		if ( is_user_logged_in() || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$ua = isset( $_SERVER['HTTP_USER_AGENT'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
			: '';

		if ( empty( $ua ) ) {
			// Empty user agent — block silently.
			$this->block_bot( 'Empty user agent', 'empty_ua' );
			return;
		}

		// Check bad bots first.
		foreach ( self::$bad_bots as $signature => $label ) {
			if ( false !== stripos( $ua, $signature ) ) {
				$this->block_bot( $label, $signature );
				return;
			}
		}
	}

	/**
	 * Block a bad bot — log and return 403.
	 *
	 * @since 1.2.0
	 * @param string $label     Human-readable bot name.
	 * @param string $signature Matched signature.
	 */
	private function block_bot( $label, $signature ) {
		$ip = Turbo_Guard_Scanner::get_client_ip();

		Turbo_Guard_Scanner::log_event(
			'bot_blocked',
			'warning',
			'Bad bot blocked: ' . $label . ' (IP: ' . $ip . ')'
		);

		// Auto-add to firewall blocklist for 24 hours.
		Turbo_Guard_Firewall::block_ip( $ip, 'Bad bot: ' . $label, DAY_IN_SECONDS );

		http_response_code( 403 );
		header( 'Content-Type: text/plain' );
		echo 'Access denied.'; // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

	/**
	 * Detect if a user agent is a known good bot.
	 *
	 * @since 1.2.0
	 * @param string $ua User agent string.
	 * @return string|false Bot name or false.
	 */
	public static function detect_good_bot( $ua ) {
		foreach ( self::$good_bots as $signature => $name ) {
			if ( false !== stripos( $ua, $signature ) ) {
				return $name;
			}
		}
		return false;
	}

	/**
	 * Detect if a user agent is a known bad bot.
	 *
	 * @since 1.2.0
	 * @param string $ua User agent string.
	 * @return string|false Bot label or false.
	 */
	public static function detect_bad_bot( $ua ) {
		if ( empty( $ua ) ) {
			return 'Empty user agent';
		}
		foreach ( self::$bad_bots as $signature => $label ) {
			if ( false !== stripos( $ua, $signature ) ) {
				return $label;
			}
		}
		return false;
	}

	/**
	 * Get bot lists for the admin UI.
	 *
	 * @since 1.2.0
	 * @return array { good: array, bad: array }
	 */
	public static function get_bot_lists() {
		return array(
			'good' => self::$good_bots,
			'bad'  => self::$bad_bots,
		);
	}

	/**
	 * Get bot traffic stats from the live traffic table.
	 *
	 * @since 1.2.0
	 * @return array { total_bots: int, blocked_bots: int, good_bots: int }
	 */
	public static function get_stats() {
		global $wpdb;

		$total = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_traffic WHERE is_bot = 1"
		);

		$blocked = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_events
			 WHERE event_type = 'bot_blocked'
			 AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)"
		);

		return array(
			'total_bots'   => $total,
			'blocked_bots' => $blocked,
		);
	}
}
