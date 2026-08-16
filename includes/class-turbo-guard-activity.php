<?php
/**
 * User Activity Tracker
 *
 * Silently records how the current site admin uses Turbo Guard.
 * All data is stored locally in wp_options — nothing is ever sent
 * to an external server. This data is only read by the notification
 * system to evaluate behavior_rule targeting on the local site.
 *
 * TRACKED DATA (stored in 'turbo_guard_activity' option):
 *  - first_seen          Unix timestamp of first dashboard visit
 *  - last_seen           Unix timestamp of last dashboard visit
 *  - visit_count         Total number of dashboard visits
 *  - pages_visited       Array of plugin page slugs visited
 *  - scan_count          Number of scans ever completed
 *  - last_scan_at        Unix timestamp of last completed scan
 *  - last_scan_threats   Number of threats found in last scan
 *  - threats_unresolved  Whether last scan threats are still unresolved
 *  - firewall_enabled    Whether firewall is currently on
 *  - last_score          Last known security score (0-100)
 *  - days_since_visit    Computed: days since last_seen
 *
 * WORDPRESS.ORG COMPLIANCE:
 *  - No data leaves the user's server
 *  - No HTTP requests to external URLs
 *  - No user PII collected
 *  - Data can be deleted on uninstall via turbo_guard_flush_activity()
 *
 * @package TurboGuard
 * @since   1.3.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turbo_Guard_Activity — local behavior tracker.
 *
 * @since 1.3.0
 */
class Turbo_Guard_Activity {

	/**
	 * WordPress option key where activity data is stored.
	 *
	 * @var string
	 */
	const OPTION_KEY = 'turbo_guard_activity';

	/**
	 * Singleton instance.
	 *
	 * @var Turbo_Guard_Activity|null
	 */
	private static $instance = null;

	/**
	 * In-memory copy of activity data for current request.
	 *
	 * @var array
	 */
	private $data = array();

	/**
	 * Get singleton instance.
	 *
	 * @since 1.3.0
	 * @return Turbo_Guard_Activity
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor — loads existing activity data.
	 *
	 * @since 1.3.0
	 */
	private function __construct() {
		$saved      = get_option( self::OPTION_KEY, array() );
		$this->data = is_array( $saved ) ? $saved : array();

		// Set defaults for any missing keys.
		$this->data = wp_parse_args( $this->data, array(
			'first_seen'         => 0,
			'last_seen'          => 0,
			'visit_count'        => 0,
			'pages_visited'      => array(),
			'scan_count'         => 0,
			'last_scan_at'       => 0,
			'last_scan_threats'  => 0,
			'threats_unresolved' => false,
			'firewall_enabled'   => true,
			'last_score'         => 0,
		) );

		// Backfill activated_at for existing users who installed before v1.3.0.
		// Without this, new_users/aged_users/behavior rules never fire on old installs.
		if ( ! get_option( 'turbo_guard_activated_at' ) ) {
			// Try multiple sources to estimate real install date:
			// 1. turbo_guard_installed_at (set by installer since v1.0)
			// 2. turbo_guard_db_version option creation time (indirect)
			// 3. Plugin file modification time as last resort
			// 4. Fallback: 90 days ago (conservative — treat as established user)
			$estimated_install = 0;

			$installed_opt = get_option( 'turbo_guard_installed_at', 0 );
			if ( $installed_opt && (int) $installed_opt > 0 ) {
				$estimated_install = (int) $installed_opt;
			} else {
				// For users who installed before the installer set this option,
				// estimate using the plugin file's mtime or default to 90 days ago.
				// This prevents existing long-term users from being falsely tagged as "new".
				$plugin_file = TURBO_GUARD_PLUGIN_DIR . 'turbo-guard.php';
				if ( file_exists( $plugin_file ) ) {
					$mtime = filemtime( $plugin_file );
					if ( $mtime && $mtime < time() ) {
						$estimated_install = $mtime;
					}
				}

				// If still nothing, assume they've been around at least 90 days.
				if ( ! $estimated_install ) {
					$estimated_install = time() - ( 90 * DAY_IN_SECONDS );
				}
			}

			update_option( 'turbo_guard_activated_at', $estimated_install, false );

			// Also set installed_at if it was missing.
			if ( ! get_option( 'turbo_guard_installed_at' ) ) {
				update_option( 'turbo_guard_installed_at', $estimated_install, false );
			}
		}

		// Backfill first_seen for existing users.
		if ( empty( $this->data['first_seen'] ) ) {
			$activated = get_option( 'turbo_guard_activated_at', 0 );
			$this->data['first_seen'] = $activated ? (int) $activated : time();
			$this->save();
		}

		// Backfill scan_count from existing scan records (only once).
		if ( empty( $this->data['scan_count'] ) ) {
			global $wpdb;

			// Check if the scans table exists first (avoids DB errors on fresh installs
			// where the table hasn't been created yet).
			$table_name = $wpdb->prefix . 'turbo_guard_scans';
			$table_exists = $wpdb->get_var( $wpdb->prepare(
				"SHOW TABLES LIKE %s", $table_name
			) );

			if ( $table_exists ) {
				$count = $wpdb->get_var(
					"SELECT COUNT(*) FROM {$wpdb->prefix}turbo_guard_scans WHERE status = 'completed'"
				);
				if ( $count > 0 ) {
					$this->data['scan_count'] = (int) $count;
					// Get last scan timestamp.
					$last = $wpdb->get_var(
						"SELECT completed_at FROM {$wpdb->prefix}turbo_guard_scans 
						 WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 1"
					);
					if ( $last ) {
						$this->data['last_scan_at'] = strtotime( $last );
					}
					$this->save();
				}
			}
		}
	}

	// =========================================================
	// RECORD EVENTS
	// =========================================================

	/**
	 * Record a dashboard page visit.
	 * Call this from each admin view render method.
	 *
	 * @since 1.3.0
	 * @param string $page_slug E.g. 'dashboard', 'scanner', 'firewall'.
	 */
	public function record_visit( $page_slug ) {
		$now = time();

		if ( empty( $this->data['first_seen'] ) ) {
			$this->data['first_seen'] = $now;
		}

		$this->data['last_seen']   = $now;
		$this->data['visit_count'] = (int) $this->data['visit_count'] + 1;

		// Track unique pages visited.
		if ( ! in_array( $page_slug, $this->data['pages_visited'], true ) ) {
			$this->data['pages_visited'][] = sanitize_key( $page_slug );
		}

		// Refresh firewall status on each visit — cheap option read.
		$this->data['firewall_enabled'] = ( 'yes' === get_option( 'turbo_guard_firewall_enabled', 'yes' ) );

		$this->save();
	}

	/**
	 * Record a completed scan.
	 * Call this after a scan finishes (scan_chunk done=true).
	 *
	 * @since 1.3.0
	 * @param int $threats_found Number of threats found in the scan.
	 */
	public function record_scan( $threats_found = 0 ) {
		$this->data['scan_count']        = (int) $this->data['scan_count'] + 1;
		$this->data['last_scan_at']      = time();
		$this->data['last_scan_threats'] = (int) $threats_found;

		// Mark unresolved if threats were found.
		if ( $threats_found > 0 ) {
			$this->data['threats_unresolved'] = true;
		}

		$this->save();
	}

	/**
	 * Mark threats as resolved (called after delete/quarantine action).
	 *
	 * @since 1.3.0
	 */
	public function record_threats_resolved() {
		$this->data['threats_unresolved'] = false;
		$this->save();
	}

	/**
	 * Update the last known security score.
	 *
	 * @since 1.3.0
	 * @param int $score Security score 0-100.
	 */
	public function record_score( $score ) {
		$this->data['last_score'] = absint( $score );
		$this->save();
	}

	// =========================================================
	// READ DATA
	// =========================================================

	/**
	 * Get the full activity snapshot for rule evaluation.
	 *
	 * @since 1.3.0
	 * @return array
	 */
	public function get_snapshot() {
		$now  = time();
		$data = $this->data;

		// Compute derived values.
		$data['days_since_visit'] = $data['last_seen']
			? (int) floor( ( $now - (int) $data['last_seen'] ) / DAY_IN_SECONDS )
			: 999;

		$data['days_since_scan'] = $data['last_scan_at']
			? (int) floor( ( $now - (int) $data['last_scan_at'] ) / DAY_IN_SECONDS )
			: 999;

		$activated_at = (int) get_option( 'turbo_guard_activated_at', 0 );
		if ( $activated_at && $activated_at <= $now ) {
			$data['days_since_install'] = (int) floor( ( $now - $activated_at ) / DAY_IN_SECONDS );
		} else {
			// Safety: if activated_at is missing or in the future, assume established user.
			$data['days_since_install'] = 90;
		}

		// Live firewall check (always fresh).
		$data['firewall_enabled'] = ( 'yes' === get_option( 'turbo_guard_firewall_enabled', 'yes' ) );

		// Live score from settings if we don't have one stored.
		if ( empty( $data['last_score'] ) ) {
			$stats = Turbo_Guard_Settings::get_dashboard_stats();
			if ( isset( $stats['security_score'] ) ) {
				$data['last_score'] = (int) $stats['security_score'];
			}
		}

		return $data;
	}

	/**
	 * Evaluate a behavior rule against current activity.
	 *
	 * Rules supported:
	 *  never_scanned           — scan_count === 0
	 *  scan_found_threats      — threats_unresolved === true
	 *  firewall_disabled       — firewall_enabled === false
	 *  low_score               — last_score < 70
	 *  very_low_score          — last_score < 50
	 *  inactive_30_days        — days_since_visit >= 30
	 *  inactive_7_days         — days_since_visit >= 7
	 *  first_week              — days_since_install <= 7
	 *  first_day               — days_since_install === 0
	 *  never_visited_firewall  — 'firewall' not in pages_visited
	 *  never_visited_scanner   — 'scanner' not in pages_visited
	 *  scan_overdue            — days_since_scan >= 30
	 *  long_term_user          — days_since_install >= 90
	 *  new_user                — days_since_install <= 30
	 *
	 * @since 1.3.0
	 * @param string $rule Rule identifier from JSON notice.
	 * @return bool True if rule matches current site activity.
	 */
	public static function evaluate_rule( $rule ) {
		$snap = self::get_instance()->get_snapshot();

		switch ( $rule ) {

			case 'never_scanned':
				return (int) $snap['scan_count'] === 0;

			case 'scan_found_threats':
				return (bool) $snap['threats_unresolved'];

			case 'firewall_disabled':
				return ! (bool) $snap['firewall_enabled'];

			case 'low_score':
				return $snap['last_score'] > 0 && $snap['last_score'] < 70;

			case 'very_low_score':
				return $snap['last_score'] > 0 && $snap['last_score'] < 50;

			case 'inactive_30_days':
				return (int) $snap['days_since_visit'] >= 30;

			case 'inactive_7_days':
				return (int) $snap['days_since_visit'] >= 7;

			case 'first_week':
				return (int) $snap['days_since_install'] <= 7;

			case 'first_day':
				return (int) $snap['days_since_install'] === 0;

			case 'never_visited_firewall':
				return ! in_array( 'firewall', (array) $snap['pages_visited'], true );

			case 'never_visited_scanner':
				return ! in_array( 'scanner', (array) $snap['pages_visited'], true );

			case 'scan_overdue':
				return (int) $snap['days_since_scan'] >= 30;

			case 'long_term_user':
				return (int) $snap['days_since_install'] >= 90;

			case 'new_user':
				return (int) $snap['days_since_install'] <= 30;

			default:
				// Unknown rule — don't show the notice.
				return false;
		}
	}

	// =========================================================
	// PERSISTENCE
	// =========================================================

	/**
	 * Persist activity data to wp_options.
	 *
	 * @since 1.3.0
	 */
	private function save() {
		update_option( self::OPTION_KEY, $this->data, false ); // false = non-autoload.
	}

	/**
	 * Delete all activity data (called on plugin uninstall).
	 *
	 * @since 1.3.0
	 */
	public static function flush() {
		delete_option( self::OPTION_KEY );
	}
}
