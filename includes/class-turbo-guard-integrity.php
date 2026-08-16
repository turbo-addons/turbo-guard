<?php
/**
 * File Integrity Checker.
 *
 * Compares WordPress core files against the official MD5 checksums
 * published by WordPress.org. Any modified core file is flagged —
 * this catches attackers who inject code into wp-login.php, wp-settings.php,
 * or other core files that signature scanners miss.
 *
 * Also maintains a baseline snapshot of wp-content files so new/changed
 * files are detected between scans (real-time file watcher via WP cron).
 *
 * @package TurboGuard
 * @since   1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * File integrity and change detection.
 *
 * @since 1.2.0
 */
class Turbo_Guard_Integrity {

	/**
	 * WordPress.org checksums API endpoint.
	 */
	const CHECKSUMS_API = 'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s';

	/**
	 * How often the file watcher cron runs (in seconds).
	 * Default: every 6 hours.
	 */
	const WATCHER_INTERVAL = 6 * HOUR_IN_SECONDS;

	/**
	 * Option key storing the wp-content file baseline snapshot.
	 */
	const BASELINE_OPTION = 'turbo_guard_file_baseline';

	/**
	 * Singleton instance.
	 *
	 * @var Turbo_Guard_Integrity|null
	 */
	private static $instance = null;

	/**
	 * Get singleton.
	 *
	 * @since 1.2.0
	 * @return Turbo_Guard_Integrity
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor — registers cron hooks.
	 *
	 * @since 1.2.0
	 */
	private function __construct() {
		add_action( 'turbo_guard_file_watcher', array( $this, 'run_file_watcher' ) );
		add_action( 'turbo_guard_integrity_check', array( $this, 'run_core_integrity_check' ) );

		// Schedule if not already scheduled.
		if ( ! wp_next_scheduled( 'turbo_guard_file_watcher' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'twicedaily', 'turbo_guard_file_watcher' );
		}
		if ( ! wp_next_scheduled( 'turbo_guard_integrity_check' ) ) {
			wp_schedule_event( time() + 2 * HOUR_IN_SECONDS, 'daily', 'turbo_guard_integrity_check' );
		}

		// AJAX: manual trigger from admin.
		add_action( 'wp_ajax_turbo_guard_run_integrity_check', array( $this, 'ajax_run_integrity_check' ) );
		add_action( 'wp_ajax_turbo_guard_rebuild_baseline', array( $this, 'ajax_rebuild_baseline' ) );
	}

	// =========================================================================
	// CORE FILE INTEGRITY CHECK
	// =========================================================================

	/**
	 * Check WordPress core files against official WordPress.org checksums.
	 *
	 * Downloads the official MD5 list for the current WP version and locale,
	 * then compares every core file. Modified files are logged as threats.
	 *
	 * @since 1.2.0
	 * @param int $scan_id Optional scan ID to attach results to (0 = standalone).
	 * @return array { modified: int, missing: int, results: array[] }
	 */
	public static function run_core_integrity_check( $scan_id = 0 ) {
		$version  = get_bloginfo( 'version' );
		$locale   = get_locale();
		$checksums = self::fetch_checksums( $version, $locale );

		if ( is_wp_error( $checksums ) || empty( $checksums ) ) {
			Turbo_Guard_Scanner::log_event(
				'integrity_check_failed',
				'warning',
				'Core integrity check failed: could not fetch checksums from WordPress.org.'
			);
			return array( 'modified' => 0, 'missing' => 0, 'results' => array() );
		}

		$modified = 0;
		$missing  = 0;
		$results  = array();

		foreach ( $checksums as $relative_path => $expected_md5 ) {
			// Only check wp-admin and wp-includes (not wp-content).
			if ( strpos( $relative_path, 'wp-content' ) === 0 ) {
				continue;
			}

			// Justification: resolving a site core file to verify against official
			// WordPress.org checksums (wp-admin/wp-includes) — legitimate for a security plugin.
			$full_path = wp_normalize_path( ABSPATH . $relative_path );

			if ( ! file_exists( $full_path ) ) {
				++$missing;
				$results[] = array(
					'path'   => $relative_path,
					'status' => 'missing',
					'detail' => 'Core file is missing — may have been deleted by an attacker.',
				);
				if ( $scan_id ) {
					self::log_integrity_result( $scan_id, $full_path, 'missing', 'critical',
						'Missing Core File',
						'Core file ' . $relative_path . ' is missing. This may indicate tampering.'
					);
				}
				continue;
			}

			$actual_md5 = md5_file( $full_path );
			if ( $actual_md5 !== $expected_md5 ) {
				++$modified;
				$results[] = array(
					'path'   => $relative_path,
					'status' => 'modified',
					'detail' => 'MD5 mismatch — file has been modified from the official WordPress version.',
				);
				if ( $scan_id ) {
					self::log_integrity_result( $scan_id, $full_path, 'core_file_modified', 'critical',
						'Modified Core File: ' . basename( $relative_path ),
						'File ' . $relative_path . ' has been modified. Expected MD5: ' . $expected_md5 . ', actual: ' . $actual_md5 . '. This is a strong indicator of a hack.'
					);
				}
			}
		}

		$total = $modified + $missing;
		if ( $total > 0 ) {
			Turbo_Guard_Scanner::log_event(
				'integrity_check_complete',
				'critical',
				sprintf( 'Core integrity check: %d modified, %d missing core files detected.', $modified, $missing )
			);
		} else {
			Turbo_Guard_Scanner::log_event(
				'integrity_check_complete',
				'info',
				sprintf( 'Core integrity check passed. All %d core files match WordPress.org checksums.', count( $checksums ) )
			);
		}

		// Cache results for dashboard display.
		set_transient( 'turbo_guard_integrity_results', array(
			'modified'    => $modified,
			'missing'     => $missing,
			'results'     => array_slice( $results, 0, 50 ), // cap for storage.
			'checked'     => count( $checksums ),
			'checked_at'  => current_time( 'mysql' ),
			'wp_version'  => $version,
		), DAY_IN_SECONDS );

		return array( 'modified' => $modified, 'missing' => $missing, 'results' => $results );
	}

	/**
	 * Fetch official checksums from WordPress.org API.
	 *
	 * @since 1.2.0
	 * @param string $version WP version string.
	 * @param string $locale  WP locale string.
	 * @return array|WP_Error Associative array of path => md5, or WP_Error.
	 */
	private static function fetch_checksums( $version, $locale ) {
		$cache_key = 'turbo_guard_checksums_' . md5( $version . $locale );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return $cached;
		}

		$url      = sprintf( self::CHECKSUMS_API, rawurlencode( $version ), rawurlencode( $locale ) );
		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body['checksums'] ) ) {
			// Try en_US fallback.
			if ( 'en_US' !== $locale ) {
				$url      = sprintf( self::CHECKSUMS_API, rawurlencode( $version ), 'en_US' );
				$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
				if ( ! is_wp_error( $response ) ) {
					$body = json_decode( wp_remote_retrieve_body( $response ), true );
				}
			}
		}

		if ( empty( $body['checksums'] ) ) {
			return new WP_Error( 'no_checksums', 'WordPress.org did not return checksums.' );
		}

		$checksums = $body['checksums'];
		// Cache for 12 hours — checksums don't change for a given version.
		set_transient( $cache_key, $checksums, 12 * HOUR_IN_SECONDS );

		return $checksums;
	}

	/**
	 * Insert a scan result row for an integrity finding.
	 *
	 * @since 1.2.0
	 */
	private static function log_integrity_result( $scan_id, $file_path, $threat_type, $severity, $name, $detail ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
		$wpdb->insert(
			$wpdb->prefix . 'turbo_guard_scan_results',
			array(
				'scan_id'        => absint( $scan_id ),
				'file_path'      => $file_path,
				'threat_type'    => $threat_type,
				'severity'       => $severity,
				'threat_name'    => $name,
				'threat_details' => $detail,
				'status'         => 'pending',
				'file_size'      => file_exists( $file_path ) ? filesize( $file_path ) : 0,
				'file_hash'      => file_exists( $file_path ) ? md5_file( $file_path ) : '',
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
		);
	}

	// =========================================================================
	// FILE WATCHER — BASELINE + CHANGE DETECTION
	// =========================================================================

	/**
	 * Build a baseline snapshot of all wp-content files.
	 *
	 * Stores: path => [ size, mtime, md5 ] for every PHP/JS file.
	 * Called once on activation and manually via "Rebuild Baseline" button.
	 *
	 * @since 1.2.0
	 * @return int Number of files in baseline.
	 */
	public static function build_baseline() {
		$baseline  = array();
		// Justification: baselining installed plugins/themes/uploads/mu-plugins to
		// detect new/modified/deleted files — legitimate for a security plugin.
		$scan_dirs = array(
			get_theme_root(),
			WP_PLUGIN_DIR,
			wp_upload_dir()['basedir'],
			WPMU_PLUGIN_DIR,
		);

		$own_plugin = realpath( TURBO_GUARD_PLUGIN_DIR );

		foreach ( $scan_dirs as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}
			try {
				$iterator = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS )
				);
				foreach ( $iterator as $file ) {
					if ( ! $file->isFile() ) {
						continue;
					}
					$ext = strtolower( $file->getExtension() );
					if ( ! in_array( $ext, array( 'php', 'js', 'html', 'htm' ), true ) ) {
						continue;
					}
					$path = $file->getPathname();
					// Skip our own plugin.
					if ( $own_plugin && strpos( realpath( $path ), $own_plugin ) === 0 ) {
						continue;
					}
					$baseline[ $path ] = array(
						'size'  => $file->getSize(),
						'mtime' => $file->getMTime(),
						'md5'   => md5_file( $path ),
					);
				}
			} catch ( Exception $e ) {
				// Skip unreadable directories.
			}
		}

		update_option( self::BASELINE_OPTION, $baseline, false );
		update_option( 'turbo_guard_baseline_built_at', current_time( 'mysql' ) );

		return count( $baseline );
	}

	/**
	 * Compare current files against the stored baseline.
	 *
	 * Detects: new files, modified files, deleted files.
	 * New PHP files in uploads = always critical.
	 *
	 * @since 1.2.0
	 * @return array { new: int, modified: int, deleted: int, changes: array[] }
	 */
	public function run_file_watcher() {
		$baseline = get_option( self::BASELINE_OPTION, array() );

		// If no baseline yet, build one silently and return.
		if ( empty( $baseline ) ) {
			self::build_baseline();
			return array( 'new' => 0, 'modified' => 0, 'deleted' => 0, 'changes' => array() );
		}

		$current   = array();
		// Justification: baselining installed plugins/themes/uploads/mu-plugins to
		// detect new/modified/deleted files — legitimate for a security plugin.
		$scan_dirs = array(
			get_theme_root(),
			WP_PLUGIN_DIR,
			wp_upload_dir()['basedir'],
			WPMU_PLUGIN_DIR,
		);

		$own_plugin = realpath( TURBO_GUARD_PLUGIN_DIR );

		foreach ( $scan_dirs as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}
			try {
				$iterator = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS )
				);
				foreach ( $iterator as $file ) {
					if ( ! $file->isFile() ) {
						continue;
					}
					$ext = strtolower( $file->getExtension() );
					if ( ! in_array( $ext, array( 'php', 'js', 'html', 'htm' ), true ) ) {
						continue;
					}
					$path = $file->getPathname();
					if ( $own_plugin && strpos( realpath( $path ), $own_plugin ) === 0 ) {
						continue;
					}
					$current[ $path ] = array(
						'size'  => $file->getSize(),
						'mtime' => $file->getMTime(),
					);
				}
			} catch ( Exception $e ) {
				// Skip.
			}
		}

		$new_count      = 0;
		$modified_count = 0;
		$deleted_count  = 0;
		$changes        = array();
		$upload_base    = realpath( wp_upload_dir()['basedir'] );

		// Detect new and modified files.
		foreach ( $current as $path => $info ) {
			if ( ! isset( $baseline[ $path ] ) ) {
				// New file.
				++$new_count;
				$ext      = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
				$in_uploads = $upload_base && strpos( realpath( $path ), $upload_base ) === 0;
				$severity = ( in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'phtml' ), true ) && $in_uploads )
					? 'critical' : 'high';

				$changes[] = array( 'path' => $path, 'status' => 'new', 'severity' => $severity );
				Turbo_Guard_Scanner::log_event(
					'file_watcher_new',
					$severity,
					'New file detected: ' . str_replace( ABSPATH, '', $path ) // Display-only relative path.
				);
			} elseif (
				$info['mtime'] !== $baseline[ $path ]['mtime'] ||
				$info['size']  !== $baseline[ $path ]['size']
			) {
				// Size or mtime changed — verify with MD5 to avoid false positives from cache plugins.
				$current_md5 = md5_file( $path );
				if ( $current_md5 !== $baseline[ $path ]['md5'] ) {
					++$modified_count;
					$changes[] = array( 'path' => $path, 'status' => 'modified', 'severity' => 'high' );
					Turbo_Guard_Scanner::log_event(
						'file_watcher_modified',
						'high',
						'File modified: ' . str_replace( ABSPATH, '', $path ) // Display-only relative path.
					);
				}
			}
		}

		// Detect deleted files (only flag plugin/theme PHP files — not uploads).
		foreach ( $baseline as $path => $info ) {
			if ( ! isset( $current[ $path ] ) && file_exists( $path ) === false ) {
				$in_uploads = $upload_base && strpos( realpath( dirname( $path ) ), $upload_base ) === 0;
				if ( ! $in_uploads ) {
					++$deleted_count;
					$changes[] = array( 'path' => $path, 'status' => 'deleted', 'severity' => 'medium' );
				}
			}
		}

		$total_changes = $new_count + $modified_count;
		if ( $total_changes > 0 ) {
			Turbo_Guard_Scanner::log_event(
				'file_watcher_complete',
				$new_count > 0 ? 'critical' : 'warning',
				sprintf( 'File watcher: %d new, %d modified, %d deleted files since last baseline.', $new_count, $modified_count, $deleted_count )
			);

			// Send email alert if new PHP files found.
			if ( $new_count > 0 ) {
				self::send_watcher_alert( $changes, $new_count, $modified_count );
			}
		}

		// Update baseline with current snapshot.
		$new_baseline = $baseline;
		foreach ( $current as $path => $info ) {
			$new_baseline[ $path ] = array(
				'size'  => $info['size'],
				'mtime' => $info['mtime'],
				'md5'   => isset( $baseline[ $path ] ) ? $baseline[ $path ]['md5'] : md5_file( $path ),
			);
		}
		update_option( self::BASELINE_OPTION, $new_baseline, false );
		update_option( 'turbo_guard_watcher_last_run', current_time( 'mysql' ) );

		return array(
			'new'      => $new_count,
			'modified' => $modified_count,
			'deleted'  => $deleted_count,
			'changes'  => $changes,
		);
	}

	/**
	 * Send email alert when new files are detected.
	 *
	 * @since 1.2.0
	 * @param array $changes    List of change entries.
	 * @param int   $new        New file count.
	 * @param int   $modified   Modified file count.
	 */
	private static function send_watcher_alert( $changes, $new, $modified ) {
		if ( 'yes' !== get_option( 'turbo_guard_notify_on_threats', 'yes' ) ) {
			return;
		}

		$email   = get_option( 'turbo_guard_notify_admin_email', get_option( 'admin_email' ) );
		$site    = get_bloginfo( 'name' );
		$subject = '[' . $site . '] File Change Alert: ' . $new . ' new file(s) detected';

		$body  = "Turbo Guard File Watcher Alert\n\n";
		$body .= $new . " new file(s) and " . $modified . " modified file(s) were detected on your site.\n\n";
		$body .= "New/modified files:\n";

		foreach ( array_slice( $changes, 0, 20 ) as $change ) {
			$body .= '  [' . strtoupper( $change['status'] ) . '] ' . str_replace( ABSPATH, '', $change['path'] ) . "\n"; // Display-only relative path.
		}

		if ( count( $changes ) > 20 ) {
			$body .= '  ... and ' . ( count( $changes ) - 20 ) . " more.\n";
		}

		$body .= "\nView your security dashboard: " . admin_url( 'admin.php?page=turbo-guard' );

		wp_mail( $email, $subject, $body );
	}

	// =========================================================================
	// AJAX HANDLERS
	// =========================================================================

	/**
	 * AJAX: Run core integrity check manually.
	 *
	 * @since 1.2.0
	 */
	public function ajax_run_integrity_check() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ) );
		}

		$result = self::run_core_integrity_check();

		wp_send_json_success( array(
			'modified' => $result['modified'],
			'missing'  => $result['missing'],
			'message'  => sprintf(
				'Integrity check complete. %d modified, %d missing core files.',
				$result['modified'],
				$result['missing']
			),
		) );
	}

	/**
	 * AJAX: Rebuild file baseline.
	 *
	 * @since 1.2.0
	 */
	public function ajax_rebuild_baseline() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ) );
		}

		$count = self::build_baseline();

		wp_send_json_success( array(
			'count'   => $count,
			'message' => sprintf( 'Baseline rebuilt. %d files tracked.', $count ),
		) );
	}

	/**
	 * Get cached integrity check results for dashboard display.
	 *
	 * @since 1.2.0
	 * @return array|false
	 */
	public static function get_last_results() {
		return get_transient( 'turbo_guard_integrity_results' );
	}
}
