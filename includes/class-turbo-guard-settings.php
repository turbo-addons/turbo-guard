<?php
/**
 * Settings Management Class.
 *
 * Manages all plugin settings and options.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings management class.
 *
 * @since 1.0.0
 */
class Turbo_Guard_Settings {

	/**
	 * Get all plugin settings.
	 *
	 * @since 1.0.0
	 * @return array Settings array.
	 */
	public static function get_all() {
		return array(
			'scan_enabled'                => get_option( 'turbo_guard_scan_enabled', 'yes' ),
			'scan_schedule'               => get_option( 'turbo_guard_scan_schedule', 'daily' ),
			'scan_images'                 => get_option( 'turbo_guard_scan_images', 'no' ),
			'scan_outside_wp'             => get_option( 'turbo_guard_scan_outside_wp', 'no' ),
			'enable_scheduled_vuln_scan'  => get_option( 'turbo_guard_enable_scheduled_vuln_scan', 'no' ),
			'firewall_enabled'            => get_option( 'turbo_guard_firewall_enabled', 'yes' ),
			'login_security_enabled'      => get_option( 'turbo_guard_login_security_enabled', 'yes' ),
			'brute_force_protection'      => get_option( 'turbo_guard_brute_force_protection', 'yes' ),
			'max_login_attempts'          => absint( get_option( 'turbo_guard_max_login_attempts', 5 ) ),
			'lockout_duration'            => absint( get_option( 'turbo_guard_lockout_duration', 3600 ) ),
			'notify_admin_email'          => get_option( 'turbo_guard_notify_admin_email', get_option( 'admin_email' ) ),
			'notify_on_threats'           => get_option( 'turbo_guard_notify_on_threats', 'yes' ),
			'notify_on_scan_complete'     => get_option( 'turbo_guard_notify_on_scan_complete', 'no' ),
			'quarantine_malware'          => get_option( 'turbo_guard_quarantine_malware', 'yes' ),
			'remove_data_on_uninstall'    => get_option( 'turbo_guard_remove_data_on_uninstall', 'no' ),
		);
	}

	/**
	 * Update multiple settings at once.
	 *
	 * @since 1.0.0
	 * @param array $settings Settings array.
	 * @return bool Success.
	 */
	public static function update( array $settings ) {
		$allowed_keys = array(
			'scan_enabled',
			'scan_schedule',
			'scan_images',
			'scan_outside_wp',
			'enable_scheduled_vuln_scan',
			'firewall_enabled',
			'login_security_enabled',
			'brute_force_protection',
			'max_login_attempts',
			'lockout_duration',
			'notify_admin_email',
			'notify_on_threats',
			'notify_on_scan_complete',
			'quarantine_malware',
			'remove_data_on_uninstall',
		);

		foreach ( $settings as $key => $value ) {
			if ( ! in_array( $key, $allowed_keys, true ) ) {
				continue;
			}

			$option_name = 'turbo_guard_' . $key;

			// Sanitize based on type.
			if ( in_array( $key, array( 'max_login_attempts', 'lockout_duration' ), true ) ) {
				$value = absint( $value );
			} elseif ( 'notify_admin_email' === $key ) {
				$value = sanitize_email( $value );
			} elseif ( 'scan_schedule' === $key ) {
				$value = in_array( $value, array( 'hourly', 'twicedaily', 'daily', 'weekly' ), true ) ? $value : 'daily';
			} else {
				$value = ( 'yes' === $value || 'on' === $value || true === $value ) ? 'yes' : 'no';
			}

			update_option( $option_name, $value );
		}

		// Reschedule cron if scan schedule changed.
		if ( isset( $settings['scan_schedule'] ) ) {
			wp_clear_scheduled_hook( 'turbo_guard_scheduled_scan' );
			wp_schedule_event( time(), $settings['scan_schedule'], 'turbo_guard_scheduled_scan' );
		}

		return true;
	}

	/**
	 * Get security score (0-100).
	 *
	 * @since 1.0.0
	 * @return int Security score.
	 */
	public static function calculate_security_score() {
		$score = 0;

		// Scanner enabled and recent scan (30 points).
		if ( 'yes' === get_option( 'turbo_guard_scan_enabled' ) ) {
			$latest_scan = Turbo_Guard_Scanner::get_latest_scan();
			if ( $latest_scan && strtotime( $latest_scan->completed_at ) > ( time() - WEEK_IN_SECONDS ) ) {
				$score += 30;
			} else {
				$score += 15; // Half points if no recent scan.
			}
		}

		// Firewall enabled (20 points).
		if ( 'yes' === get_option( 'turbo_guard_firewall_enabled' ) ) {
			$score += 20;
		}

		// Login security enabled (20 points).
		if ( 'yes' === get_option( 'turbo_guard_login_security_enabled' ) ) {
			$score += 20;
		}

		// Brute force protection (15 points).
		if ( 'yes' === get_option( 'turbo_guard_brute_force_protection' ) ) {
			$score += 15;
		}

		// Email notifications enabled (5 points).
		if ( 'yes' === get_option( 'turbo_guard_notify_on_threats' ) ) {
			$score += 5;
		}

		// WordPress and plugins up to date (10 points).
		$updates = get_site_transient( 'update_plugins' );
		if ( empty( $updates->response ) ) {
			$score += 10;
		}

		return min( 100, $score );
	}

	/**
	 * Get dashboard statistics.
	 *
	 * @since 1.0.0
	 * @return array Dashboard stats.
	 */
	public static function get_dashboard_stats() {
		global $wpdb;

		// Latest scan info.
		$latest_scan = Turbo_Guard_Scanner::get_latest_scan();

		// Count threats from latest scan.
		$threats_count = 0;
		if ( $latest_scan ) {
			$threats_count = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_scan_results
					 WHERE scan_id = %d AND status = 'pending'",
					$latest_scan->id
				)
			);
		}

		// Firewall blocks today.
		$blocks_today = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_firewall_log
			 WHERE DATE(created_at) = CURDATE()"
		);

		// Failed login attempts today.
		$failed_logins_today = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_login_attempts
			 WHERE success = 0 AND DATE(created_at) = CURDATE()"
		);

		// Recent events (last 10).
		$recent_events = $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}turbo_guard_events
			 ORDER BY id DESC
			 LIMIT 10"
		);

		return array(
			'security_score'      => self::calculate_security_score(),
			'latest_scan'         => $latest_scan,
			'threats_count'       => absint( $threats_count ),
			'blocks_today'        => absint( $blocks_today ),
			'failed_logins_today' => absint( $failed_logins_today ),
			'recent_events'       => $recent_events,
		);
	}
}
