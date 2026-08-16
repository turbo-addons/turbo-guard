<?php
/**
 * Login Security Class.
 *
 * Brute force protection, login attempt tracking, 2FA support.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles login security.
 *
 * @since 1.0.0
 */
class Turbo_Guard_Login_Security {

	/**
	 * Single instance.
	 *
	 * @var Turbo_Guard_Login_Security|null
	 */
	private static $instance = null;

	/**
	 * Get instance.
	 *
	 * @since 1.0.0
	 * @return Turbo_Guard_Login_Security
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
		// Only run if enabled.
		if ( 'yes' !== get_option( 'turbo_guard_login_security_enabled', 'yes' ) ) {
			return;
		}

		// Brute force protection.
		add_filter( 'authenticate', array( $this, 'check_brute_force' ), 30, 3 );
		add_action( 'wp_login', array( $this, 'log_successful_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'log_failed_login' ), 10, 2 );

		// Alert on first-time admin login from new IP.
		add_action( 'wp_login', array( $this, 'notify_new_admin_login' ), 10, 2 );
	}

	/**
	 * Check for brute force attempts before authentication.
	 *
	 * @since 1.0.0
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error
	 */
	public function check_brute_force( $user, $username, $password ) {
		// Skip if brute force protection disabled.
		if ( 'yes' !== get_option( 'turbo_guard_brute_force_protection', 'yes' ) ) {
			return $user;
		}

		$ip = Turbo_Guard_Scanner::get_client_ip();
		if ( ! $ip ) {
			return $user;
		}

		// Check if this IP is locked out.
		$lockout_key  = 'turbo_guard_lockout_' . md5( $ip );
		$locked_until = get_transient( $lockout_key );

		if ( false !== $locked_until ) {
			$remaining = $locked_until - time();
			return new WP_Error(
				'turbo_guard_locked_out',
				sprintf(
					/* translators: %d: minutes remaining */
					__( 'Too many failed login attempts. Please try again in %d minutes.', 'turbo-guard-security-malware-scanner' ),
					ceil( $remaining / 60 )
				)
			);
		}

		// Check failed attempts in last hour.
		$max_attempts = absint( get_option( 'turbo_guard_max_login_attempts', 5 ) );
		$failed_count = $this->count_failed_attempts( $ip, HOUR_IN_SECONDS );

		if ( $failed_count >= $max_attempts ) {
			// Lock out this IP.
			$lockout_duration = absint( get_option( 'turbo_guard_lockout_duration', 3600 ) );
			set_transient( $lockout_key, time() + $lockout_duration, $lockout_duration );

			// Auto-block IP temporarily.
			Turbo_Guard_Firewall::block_ip(
				$ip,
				__( 'Too many failed login attempts', 'turbo-guard-security-malware-scanner' ),
				$lockout_duration
			);

			Turbo_Guard_Scanner::log_event(
				'brute_force_detected',
				'critical',
				sprintf(
					/* translators: %s: IP address */
					__( 'Brute force attack detected from IP: %s', 'turbo-guard-security-malware-scanner' ),
					$ip
				)
			);

			return new WP_Error(
				'turbo_guard_locked_out',
				sprintf(
					/* translators: %d: minutes */
					__( 'Too many failed login attempts. Please try again in %d minutes.', 'turbo-guard-security-malware-scanner' ),
					ceil( $lockout_duration / 60 )
				)
			);
		}

		return $user;
	}

	/**
	 * Log successful login.
	 *
	 * @since 1.0.0
	 * @param string  $username Username.
	 * @param WP_User $user     User object.
	 */
	public function log_successful_login( $username, $user ) {
		global $wpdb;

		$wpdb->insert(
			$wpdb->prefix . 'turbo_guard_login_attempts',
			array(
				'username'   => sanitize_user( $username ),
				'ip_address' => Turbo_Guard_Scanner::get_client_ip(),
				'success'    => 1,
				'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '',
			),
			array( '%s', '%s', '%d', '%s' )
		);
	}

	/**
	 * Log failed login attempt.
	 *
	 * @since 1.0.0
	 * @param string   $username Username.
	 * @param WP_Error $error    Error object.
	 */
	public function log_failed_login( $username, $error ) {
		global $wpdb;

		$wpdb->insert(
			$wpdb->prefix . 'turbo_guard_login_attempts',
			array(
				'username'   => sanitize_user( $username ),
				'ip_address' => Turbo_Guard_Scanner::get_client_ip(),
				'success'    => 0,
				'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '',
			),
			array( '%s', '%s', '%d', '%s' )
		);
	}

	/**
	 * Notify admin of new login from unknown IP.
	 *
	 * @since 1.0.0
	 * @param string  $username Username.
	 * @param WP_User $user     User object.
	 */
	public function notify_new_admin_login( $username, $user ) {
		// Only for admin users.
		if ( ! user_can( $user, 'manage_options' ) ) {
			return;
		}

		$ip = Turbo_Guard_Scanner::get_client_ip();
		if ( ! $ip ) {
			return;
		}

		// Check if we've seen this IP before for this user.
		global $wpdb;
		$seen_before = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_login_attempts
				 WHERE username = %s AND ip_address = %s AND success = 1
				 AND created_at < DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
				$username,
				$ip
			)
		);

		if ( $seen_before > 0 ) {
			return; // Known IP.
		}

		// Send email notification.
		$admin_email = get_option( 'turbo_guard_notify_admin_email', get_option( 'admin_email' ) );
		$subject     = sprintf(
			/* translators: %s: Site name */
			__( '[%s] New Administrator Login from Unknown IP', 'turbo-guard-security-malware-scanner' ),
			get_bloginfo( 'name' )
		);

		$message = sprintf(
			/* translators: 1: Username, 2: IP address, 3: Date/time */
			__( "Hello,\n\nA new administrator login was detected:\n\nUsername: %1\$s\nIP Address: %2\$s\nTime: %3\$s\n\nIf this wasn't you, please secure your account immediately.\n\n-- Turbo Guard Security", 'turbo-guard-security-malware-scanner' ),
			$username,
			$ip,
			current_time( 'mysql' )
		);

		wp_mail( $admin_email, $subject, $message );

		// Log event.
		Turbo_Guard_Scanner::log_event(
			'new_admin_login',
			'info',
			sprintf(
				/* translators: 1: Username, 2: IP address */
				__( 'New admin login: %1$s from IP %2$s', 'turbo-guard-security-malware-scanner' ),
				$username,
				$ip
			)
		);
	}

	/**
	 * Count failed login attempts from an IP within time period.
	 *
	 * @since 1.0.0
	 * @param string $ip      IP address.
	 * @param int    $seconds Time period in seconds.
	 * @return int Number of failed attempts.
	 */
	private function count_failed_attempts( $ip, $seconds ) {
		global $wpdb;

		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_login_attempts
				 WHERE ip_address = %s
				 AND success = 0
				 AND created_at > DATE_SUB(NOW(), INTERVAL %d SECOND)",
				$ip,
				$seconds
			)
		);

		return absint( $count );
	}

	/**
	 * Get recent login attempts (last 50).
	 *
	 * @since 1.0.0
	 * @return array Login attempt rows.
	 */
	public static function get_recent_attempts() {
		global $wpdb;

		return $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}turbo_guard_login_attempts
			 ORDER BY id DESC
			 LIMIT 50"
		);
	}
}
