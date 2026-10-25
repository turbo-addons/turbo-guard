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

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Security scanner requires direct database access.

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
			'scan_enabled'             => get_option( 'turbo_guard_scan_enabled', 'yes' ),
			'scan_schedule'            => get_option( 'turbo_guard_scan_schedule', 'daily' ),
			'scan_images'              => get_option( 'turbo_guard_scan_images', 'no' ),
			'scan_outside_wp'          => get_option( 'turbo_guard_scan_outside_wp', 'no' ),
			'enable_scheduled_vuln_scan' => get_option( 'turbo_guard_enable_scheduled_vuln_scan', 'no' ),
			'enable_scheduled_seo_spam_scan' => get_option( 'turbo_guard_enable_scheduled_seo_spam_scan', 'no' ),
			'seo_allow_cjk_content'   => get_option( 'turbo_guard_seo_allow_cjk_content', 'no' ),
			'firewall_enabled'         => get_option( 'turbo_guard_firewall_enabled', 'yes' ),
			'bot_protection_enabled'   => get_option( 'turbo_guard_bot_protection_enabled', 'yes' ),
			'bot_aggressive_mode'      => get_option( 'turbo_guard_bot_aggressive_mode', 'no' ),
			'bot_verify_crawlers'      => get_option( 'turbo_guard_bot_verify_crawlers', 'yes' ),
			'bot_custom_blocked'       => get_option( 'turbo_guard_bot_custom_blocked', '' ),
			'login_security_enabled'   => get_option( 'turbo_guard_login_security_enabled', 'yes' ),
			'brute_force_protection'   => get_option( 'turbo_guard_brute_force_protection', 'yes' ),
			'max_login_attempts'       => absint( get_option( 'turbo_guard_max_login_attempts', 5 ) ),
			'lockout_duration'         => absint( get_option( 'turbo_guard_lockout_duration', 3600 ) ),
			'2fa_enabled_global'       => get_option( 'turbo_guard_2fa_enabled_global', 'yes' ),
			'2fa_enforce_roles'        => (array) get_option( 'turbo_guard_2fa_enforce_roles', array() ),
			'2fa_grace_days'           => absint( get_option( 'turbo_guard_2fa_grace_days', 0 ) ),
			'2fa_remember_days'        => absint( get_option( 'turbo_guard_2fa_remember_days', 0 ) ),
			'notify_admin_email'       => get_option( 'turbo_guard_notify_admin_email', get_option( 'admin_email' ) ),
			'notify_on_threats'        => get_option( 'turbo_guard_notify_on_threats', 'yes' ),
			'notify_on_scan_complete'  => get_option( 'turbo_guard_notify_on_scan_complete', 'no' ),
			'remove_data_on_uninstall' => get_option( 'turbo_guard_remove_data_on_uninstall', 'no' ),
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
			'enable_scheduled_seo_spam_scan',
			'seo_allow_cjk_content',
			'firewall_enabled',
			'bot_protection_enabled',
			'bot_aggressive_mode',
			'bot_verify_crawlers',
			'bot_custom_blocked',
			'login_security_enabled',
			'brute_force_protection',
			'max_login_attempts',
			'lockout_duration',
			'2fa_enabled_global',
			'2fa_enforce_roles',
			'2fa_grace_days',
			'2fa_remember_days',
			'notify_admin_email',
			'notify_on_threats',
			'notify_on_scan_complete',
			'remove_data_on_uninstall',
		);

		foreach ( $settings as $key => $value ) {
			if ( ! in_array( $key, $allowed_keys, true ) ) {
				continue;
			}

			$option_name = 'turbo_guard_' . $key;

			// Sanitize based on type.
			if ( in_array( $key, array( 'max_login_attempts', 'lockout_duration', '2fa_grace_days', '2fa_remember_days' ), true ) ) {
				$value = absint( $value );
			} elseif ( '2fa_enforce_roles' === $key ) {
				$value = self::sanitize_roles( $value );
			} elseif ( 'notify_admin_email' === $key ) {
				$value = sanitize_email( $value );
			} elseif ( 'bot_custom_blocked' === $key ) {
				$value = sanitize_textarea_field( $value );
			} elseif ( 'scan_schedule' === $key ) {
				$value = in_array( $value, array( 'hourly', 'twicedaily', 'daily' ), true ) ? $value : 'daily';
			} else {
				$value = ( 'yes' === $value || 'on' === $value || true === $value ) ? 'yes' : 'no';
			}

			update_option( $option_name, $value );
		}

		// Track when 2FA became required for roles, so the grace period can be
		// calculated. Cleared when no roles are required.
		if ( array_key_exists( '2fa_enforce_roles', $settings ) ) {
			$enforced_roles = (array) get_option( 'turbo_guard_2fa_enforce_roles', array() );
			if ( empty( $enforced_roles ) ) {
				delete_option( 'turbo_guard_2fa_required_since' );
			} elseif ( ! get_option( 'turbo_guard_2fa_required_since' ) ) {
				update_option( 'turbo_guard_2fa_required_since', time() );
			}
		}

		// Reschedule cron if scan schedule changed. Only valid WordPress
		// intervals (hourly, twicedaily, daily) are accepted so the scheduled
		// event always fires.
		if ( isset( $settings['scan_schedule'] ) ) {
			$schedule = in_array( $settings['scan_schedule'], array( 'hourly', 'twicedaily', 'daily' ), true )
				? $settings['scan_schedule']
				: 'daily';

			wp_clear_scheduled_hook( 'turbo_guard_scheduled_scan' );
			wp_schedule_event( time(), $schedule, 'turbo_guard_scheduled_scan' );
		}

		return true;
	}

	/**
	 * Sanitize a list of role slugs against the site's registered roles.
	 *
	 * @since 1.1.5
	 * @param mixed $roles Raw role slugs (array or scalar).
	 * @return string[] Valid, unique role slugs.
	 */
	private static function sanitize_roles( $roles ) {
		if ( ! is_array( $roles ) ) {
			$roles = array( $roles );
		}

		$valid = array_keys( wp_roles()->get_names() );
		$clean = array();

		foreach ( $roles as $role ) {
			$role = sanitize_key( $role );
			if ( '' !== $role && in_array( $role, $valid, true ) ) {
				$clean[] = $role;
			}
		}

		return array_values( array_unique( $clean ) );
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
	 * Get environment (WordPress + PHP) version status for the dashboard.
	 *
	 * @since 1.1.6
	 * @return array {
	 *     @type array $wordpress WordPress status data.
	 *     @type array $php       PHP status data.
	 * }
	 */
	public static function get_environment_status() {
		return array(
			'wordpress' => self::get_wordpress_status(),
			'php'       => self::get_php_status(),
		);
	}

	/**
	 * WordPress core version status.
	 *
	 * Compares the installed version against the newest version offered by
	 * the core update transient.
	 *
	 * @since 1.1.6
	 * @return array Status data.
	 */
	public static function get_wordpress_status() {
		$current    = get_bloginfo( 'version' );
		$latest     = $current;
		$has_update = false;

		$core_updates = get_site_transient( 'update_core' );

		if ( $core_updates && ! empty( $core_updates->updates ) && is_array( $core_updates->updates ) ) {
			foreach ( $core_updates->updates as $update ) {
				if (
					isset( $update->response, $update->current ) &&
					'upgrade' === $update->response &&
					version_compare( $update->current, $current, '>' )
				) {
					$latest     = $update->current;
					$has_update = true;
					break;
				}
			}
		}

		return array(
			'name'        => __( 'WordPress', 'turbo-guard' ),
			'current'     => $current,
			'latest'      => $latest,
			'status'      => $has_update ? 'warning' : 'good',
			'message'     => $has_update
				? sprintf(
					/* translators: %s: latest WordPress version */
					__( 'A newer WordPress version (%s) is available. Please update to keep your site secure.', 'turbo-guard' ),
					$latest
				)
				: __( 'You are running the latest version of WordPress.', 'turbo-guard' ),
			'action_url'  => $has_update ? admin_url( 'update-core.php' ) : '',
			'action_text' => $has_update ? __( 'Update WordPress', 'turbo-guard' ) : '',
		);
	}

	/**
	 * PHP version status.
	 *
	 * Prefers WordPress' own PHP compatibility check when available, falling
	 * back to conservative version thresholds on failure.
	 *
	 * @since 1.1.6
	 * @return array Status data.
	 */
	public static function get_php_status() {
		$current      = PHP_VERSION;
		$recommended  = '8.3';
		$is_secure    = version_compare( $current, '8.2', '>=' );
		$is_supported = $is_secure;

		if ( function_exists( 'wp_check_php_version' ) ) {
			$check = wp_check_php_version();

			if ( is_array( $check ) ) {
				if ( ! empty( $check['recommended_version'] ) ) {
					$recommended = $check['recommended_version'];
				}
				$is_secure    = ! empty( $check['is_secure'] );
				$is_supported = ! empty( $check['is_supported'] );
			}
		}

		$is_current = ( $is_secure && $is_supported && ! version_compare( $recommended, $current, '>' ) );

		if ( $is_current ) {
			$message = sprintf(
				/* translators: %s: current PHP version */
				__( 'You are running the latest supported PHP version (%s).', 'turbo-guard' ),
				$current
			);
		} elseif ( ! $is_secure ) {
			$message = sprintf(
				/* translators: 1: current PHP version, 2: recommended PHP version */
				__( 'Your PHP version (%1$s) is outdated and no longer receiving security updates. Upgrade to PHP %2$s or newer.', 'turbo-guard' ),
				$current,
				$recommended
			);
		} elseif ( ! $is_supported ) {
			$message = sprintf(
				/* translators: 1: current PHP version, 2: recommended PHP version */
				__( 'Your PHP version (%1$s) is no longer fully supported. Upgrade to PHP %2$s or newer.', 'turbo-guard' ),
				$current,
				$recommended
			);
		} else {
			$message = sprintf(
				/* translators: 1: current PHP version, 2: recommended PHP version */
				__( 'A newer PHP version (%2$s) is available. You are running %1$s.', 'turbo-guard' ),
				$current,
				$recommended
			);
		}

		return array(
			'name'        => __( 'PHP', 'turbo-guard' ),
			'current'     => $current,
			'latest'      => $recommended,
			'status'      => $is_current ? 'good' : 'warning',
			'message'     => $message,
			'action_url'  => $is_current ? '' : 'https://www.php.net/supported-versions.php',
			'action_text' => $is_current ? '' : __( 'Learn how to upgrade PHP', 'turbo-guard' ),
		);
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
			'environment'         => self::get_environment_status(),
			'latest_scan'         => $latest_scan,
			'threats_count'       => absint( $threats_count ),
			'blocks_today'        => absint( $blocks_today ),
			'failed_logins_today' => absint( $failed_logins_today ),
			'recent_events'       => $recent_events,
		);
	}
}
