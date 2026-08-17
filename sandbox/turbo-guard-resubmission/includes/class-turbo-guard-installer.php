<?php
/**
 * Plugin Installer - Creates database tables and default settings.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles plugin installation and database setup.
 *
 * @since 1.0.0
 */
class Turbo_Guard_Installer {

	/**
	 * Run on plugin activation.
	 *
	 * @since 1.0.0
	 */
	public static function activate() {
		self::create_tables();
		self::set_default_options();
		self::schedule_cron_jobs();
		self::create_quarantine_directory();

		// Build initial file baseline for the file watcher.
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-integrity.php';
		Turbo_Guard_Integrity::build_baseline();

		// Write uploads .htaccess PHP block immediately on activation.
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-hardening.php';
		Turbo_Guard_Hardening::write_uploads_htaccess();

		flush_rewrite_rules();
	}

	/**
	 * Create database tables.
	 *
	 * @since 1.0.0
	 */
	private static function create_tables() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		// Scans table.
		$sql_scans = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}turbo_guard_scans (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			status varchar(20) NOT NULL DEFAULT 'pending',
			total_files int(11) UNSIGNED NOT NULL DEFAULT 0,
			scanned_files int(11) UNSIGNED NOT NULL DEFAULT 0,
			threats_found int(11) UNSIGNED NOT NULL DEFAULT 0,
			started_at datetime DEFAULT NULL,
			completed_at datetime DEFAULT NULL,
			PRIMARY KEY (id),
			KEY status (status),
			KEY started_at (started_at)
		) $charset_collate;";

		// Scan results table.
		$sql_results = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}turbo_guard_scan_results (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			scan_id bigint(20) UNSIGNED NOT NULL,
			file_path text NOT NULL,
			threat_type varchar(50) DEFAULT NULL,
			severity varchar(20) NOT NULL DEFAULT 'info',
			threat_name varchar(255) DEFAULT NULL,
			threat_details text DEFAULT NULL,
			status varchar(20) NOT NULL DEFAULT 'pending',
			file_size bigint(20) UNSIGNED DEFAULT 0,
			file_hash varchar(64) DEFAULT NULL,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY scan_id (scan_id),
			KEY severity (severity),
			KEY status (status)
		) $charset_collate;";

		// Firewall log table.
		$sql_firewall = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}turbo_guard_firewall_log (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			country_code varchar(2) DEFAULT NULL,
			request_uri text DEFAULT NULL,
			request_method varchar(10) DEFAULT NULL,
			block_reason varchar(255) DEFAULT NULL,
			user_agent text DEFAULT NULL,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY ip_address (ip_address),
			KEY created_at (created_at)
		) $charset_collate;";

		// IP blocklist table.
		$sql_blocklist = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}turbo_guard_ip_blocklist (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			ip_mask int(3) DEFAULT NULL,
			reason varchar(255) DEFAULT NULL,
			expires_at datetime DEFAULT NULL,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY ip_address (ip_address),
			KEY expires_at (expires_at)
		) $charset_collate;";

		// Security events table.
		$sql_events = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}turbo_guard_events (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type varchar(50) NOT NULL,
			severity varchar(20) NOT NULL DEFAULT 'info',
			message text NOT NULL,
			user_id bigint(20) UNSIGNED DEFAULT NULL,
			ip_address varchar(45) DEFAULT NULL,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY event_type (event_type),
			KEY severity (severity),
			KEY created_at (created_at),
			KEY user_id (user_id)
		) $charset_collate;";

		// Login attempts table.
		$sql_logins = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}turbo_guard_login_attempts (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			username varchar(255) NOT NULL,
			ip_address varchar(45) NOT NULL,
			success tinyint(1) NOT NULL DEFAULT 0,
			user_agent text DEFAULT NULL,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY username (username),
			KEY ip_address (ip_address),
			KEY success (success),
			KEY created_at (created_at)
		) $charset_collate;";

		// Execute table creation.
		dbDelta( $sql_scans );
		dbDelta( $sql_results );
		dbDelta( $sql_firewall );
		dbDelta( $sql_blocklist );
		dbDelta( $sql_events );
		dbDelta( $sql_logins );

		// Live traffic table (added in v1.1.0).
		$sql_traffic = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}turbo_guard_traffic (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL DEFAULT '',
			user_agent varchar(512) NOT NULL DEFAULT '',
			method varchar(10) NOT NULL DEFAULT 'GET',
			request_uri varchar(512) NOT NULL DEFAULT '/',
			referer varchar(512) NOT NULL DEFAULT '',
			status_code smallint(5) UNSIGNED NOT NULL DEFAULT 200,
			user_id bigint(20) UNSIGNED NOT NULL DEFAULT 0,
			is_bot tinyint(1) NOT NULL DEFAULT 0,
			bot_name varchar(80) NOT NULL DEFAULT '',
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY ip_address (ip_address),
			KEY is_bot (is_bot),
			KEY status_code (status_code),
			KEY created_at (created_at)
		) $charset_collate;";

		dbDelta( $sql_traffic );

		// Update database version.
		update_option( 'turbo_guard_db_version', '1.1.0' );
	}

	/**
	 * Set default plugin options.
	 *
	 * @since 1.0.0
	 */
	private static function set_default_options() {
		$defaults = array(
			'turbo_guard_scan_enabled'             => 'yes',
			'turbo_guard_scan_schedule'            => 'daily',
			'turbo_guard_firewall_enabled'         => 'yes',
			'turbo_guard_login_security_enabled'   => 'yes',
			'turbo_guard_brute_force_protection'   => 'yes',
			'turbo_guard_max_login_attempts'       => 5,
			'turbo_guard_lockout_duration'         => 3600,
			'turbo_guard_notify_admin_email'       => get_option( 'admin_email' ),
			'turbo_guard_notify_on_threats'        => 'yes',
			'turbo_guard_notify_on_scan_complete'  => 'no',
			'turbo_guard_quarantine_malware'       => 'yes',
			'turbo_guard_remove_data_on_uninstall' => 'no',
			// v1.1.0 defaults.
			'turbo_guard_2fa_enabled_global'       => 'yes',
			'turbo_guard_live_traffic_enabled'     => 'yes',
			'turbo_guard_security_headers'         => 'yes',
			'turbo_guard_hide_wp_version'          => 'yes',
			'turbo_guard_prevent_user_enum'        => 'yes',
			'turbo_guard_remove_readme_links'      => 'yes',
			'turbo_guard_disable_xmlrpc'           => 'no',
			'turbo_guard_protect_rest_api'         => 'no',
			'turbo_guard_disable_file_edit'        => 'no',
			// v1.2.0 defaults.
			'turbo_guard_block_php_uploads'        => 'yes',
			'turbo_guard_file_watcher_enabled'     => 'yes',
			'turbo_guard_integrity_check_enabled'  => 'yes',
		);

		foreach ( $defaults as $key => $value ) {
			if ( false === get_option( $key ) ) {
				add_option( $key, $value );
			}
		}

		// Set installation timestamp.
		add_option( 'turbo_guard_installed_at', current_time( 'timestamp' ) );
		add_option( 'turbo_guard_version', TURBO_GUARD_VERSION );

		// Record activation timestamp for notification segmentation (new_users / aged_users).
		// Only set once — never overwrite so we track the true original install date.
		if ( ! get_option( 'turbo_guard_activated_at' ) ) {
			add_option( 'turbo_guard_activated_at', time() );
		}
	}

	/**
	 * Schedule cron jobs.
	 *
	 * @since 1.0.0
	 */
	private static function schedule_cron_jobs() {
		if ( ! wp_next_scheduled( 'turbo_guard_scheduled_scan' ) ) {
			wp_schedule_event( time(), 'daily', 'turbo_guard_scheduled_scan' );
		}
	}

	/**
	 * Create quarantine directory for suspicious files.
	 *
	 * @since 1.0.0
	 */
	private static function create_quarantine_directory() {
		$upload_dir     = wp_upload_dir();
		$quarantine_dir = $upload_dir['basedir'] . '/turbo-guard-quarantine';

		if ( ! file_exists( $quarantine_dir ) ) {
			wp_mkdir_p( $quarantine_dir );
		}

		// Create .htaccess to prevent execution.
		$htaccess_file = $quarantine_dir . '/.htaccess';
		if ( ! file_exists( $htaccess_file ) ) {
			$htaccess_content  = "# Turbo Guard Quarantine - Deny all access\n";
			$htaccess_content .= "Order deny,allow\n";
			$htaccess_content .= "Deny from all\n";
			file_put_contents( $htaccess_file, $htaccess_content ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		}

		// Create index.php to prevent directory listing.
		$index_file = $quarantine_dir . '/index.php';
		if ( ! file_exists( $index_file ) ) {
			file_put_contents( $index_file, '<?php // Silence is golden.' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		}
	}
}
