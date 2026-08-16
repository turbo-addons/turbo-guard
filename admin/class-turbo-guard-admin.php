<?php
/**
 * Admin Interface Class.
 *
 * Handles admin menu, pages, and AJAX endpoints.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin interface management.
 *
 * @since 1.0.0
 */
class Turbo_Guard_Admin {

	/**
	 * Single instance.
	 *
	 * @var Turbo_Guard_Admin|null
	 */
	private static $instance = null;

	/**
	 * Get instance.
	 *
	 * @since 1.0.0
	 * @return Turbo_Guard_Admin
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
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );

		// AJAX endpoints.
		add_action( 'wp_ajax_turbo_guard_start_scan', array( $this, 'ajax_start_scan' ) );
		add_action( 'wp_ajax_turbo_guard_scan_chunk', array( $this, 'ajax_scan_chunk' ) );
		add_action( 'wp_ajax_turbo_guard_get_results', array( $this, 'ajax_get_results' ) );
		add_action( 'wp_ajax_turbo_guard_delete_files', array( $this, 'ajax_delete_files' ) );
		add_action( 'wp_ajax_turbo_guard_quarantine_files', array( $this, 'ajax_quarantine_files' ) );
		add_action( 'wp_ajax_turbo_guard_save_settings', array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_turbo_guard_get_dashboard_stats', array( $this, 'ajax_get_dashboard_stats' ) );

		// GSC AJAX endpoints.
		add_action( 'wp_ajax_turbo_guard_gsc_get_urls', array( $this, 'ajax_gsc_get_urls' ) );
		add_action( 'wp_ajax_turbo_guard_gsc_remove_urls', array( $this, 'ajax_gsc_remove_urls' ) );
		add_action( 'wp_ajax_turbo_guard_gsc_submit_sitemap', array( $this, 'ajax_gsc_submit_sitemap' ) );
		add_action( 'wp_ajax_turbo_guard_gsc_disconnect', array( $this, 'ajax_gsc_disconnect' ) );
		add_action( 'wp_ajax_turbo_guard_block_ip', array( $this, 'ajax_block_ip' ) );
		add_action( 'wp_ajax_turbo_guard_unblock_ip', array( $this, 'ajax_unblock_ip' ) );

		// Vulnerability scanner + live traffic AJAX are registered via
		// turbo_guard_register_v110_ajax() standalone function (see bottom of this file).
		// They use standalone functions, not class methods.

		// Integrity + file watcher AJAX.
		add_action( 'wp_ajax_turbo_guard_run_integrity_check', array( $this, 'ajax_run_integrity_check' ) );
		add_action( 'wp_ajax_turbo_guard_rebuild_baseline', array( $this, 'ajax_rebuild_baseline' ) );
		add_action( 'wp_ajax_turbo_guard_run_file_watcher', array( $this, 'ajax_run_file_watcher' ) );

		// SEO Spam Detector AJAX.
		add_action( 'wp_ajax_turbo_guard_run_seo_spam_scan', array( $this, 'ajax_run_seo_spam_scan' ) );
		add_action( 'wp_ajax_turbo_guard_delete_spam_post',  array( $this, 'ajax_delete_spam_post' ) );

		// Scanner: ignore / unignore file.
		add_action( 'wp_ajax_turbo_guard_ignore_file',   array( $this, 'ajax_ignore_file' ) );
		add_action( 'wp_ajax_turbo_guard_unignore_file', array( $this, 'ajax_unignore_file' ) );

		// Remote notices: dismiss is handled inside Turbo_Guard_Notices itself,
		// but we enqueue the nonce data here so JS can access it.
		add_action( 'admin_footer', array( $this, 'print_notices_nonce_data' ) );
	}

	/**
	 * Add admin menu.
	 *
	 * @since 1.0.0
	 */
	public function add_admin_menu() {
		add_menu_page(
			__( 'Turbo Guard', 'turbo-guard' ),
			__( 'Turbo Guard', 'turbo-guard' ),
			'manage_options',
			'turbo-guard',
			array( $this, 'render_dashboard_page' ),
			'dashicons-shield',
			80
		);

		add_submenu_page(
			'turbo-guard',
			__( 'Dashboard', 'turbo-guard' ),
			__( 'Dashboard', 'turbo-guard' ),
			'manage_options',
			'turbo-guard',
			array( $this, 'render_dashboard_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'Scanner', 'turbo-guard' ),
			__( 'Scanner', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-scanner',
			array( $this, 'render_scanner_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'Firewall', 'turbo-guard' ),
			__( 'Firewall', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-firewall',
			array( $this, 'render_firewall_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'Settings', 'turbo-guard' ),
			__( 'Settings', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-settings',
			array( $this, 'render_settings_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'GSC Cleanup', 'turbo-guard' ),
			__( 'GSC Cleanup', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-gsc',
			array( $this, 'render_gsc_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'Vulnerabilities', 'turbo-guard' ),
			__( 'Vulnerabilities', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-vulnerabilities',
			array( $this, 'render_vulnerabilities_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'Live Traffic', 'turbo-guard' ),
			__( 'Live Traffic', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-traffic',
			array( $this, 'render_live_traffic_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'AI Advisor', 'turbo-guard' ),
			'🤖 ' . __( 'AI Advisor', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-ai-report',
			array( $this, 'render_ai_report_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'File Integrity', 'turbo-guard' ),
			'🔒 ' . __( 'File Integrity', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-integrity',
			array( $this, 'render_integrity_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'SEO Spam Detector', 'turbo-guard' ),
			'🔎 ' . __( 'SEO Spam', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-seo-spam',
			array( $this, 'render_seo_spam_page' )
		);
	}

	/**
	 * Enqueue admin assets.
	 *
	 * @since 1.0.0
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue_admin_assets( $hook ) {
		// Only load on Turbo Guard pages.
		if ( strpos( $hook, 'turbo-guard' ) === false ) {
			return;
		}

		// Enqueue CSS.
		wp_enqueue_style(
			'turbo-guard-admin',
			TURBO_GUARD_PLUGIN_URL . 'admin/css/turbo-guard-admin.css',
			array(),
			TURBO_GUARD_VERSION
		);

		// Enqueue JS.
		wp_enqueue_script(
			'turbo-guard-admin',
			TURBO_GUARD_PLUGIN_URL . 'admin/js/turbo-guard-admin-v3.js',
			array( 'jquery' ),
			TURBO_GUARD_VERSION,
			true
		);

		// Page-specific data: security score trend for the AI Advisor chart.
		$trend = array();
		if ( strpos( $hook, 'turbo-guard-ai-report' ) !== false ) {
			$trend = Turbo_Guard_AI_Advisor::get_security_trend();
		}

		// Pass data to JS.
		wp_localize_script(
			'turbo-guard-admin',
			'turboGuardAdmin',
			array(
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				'nonce'      => wp_create_nonce( 'turbo_guard_admin' ),
				'flushNonce' => wp_create_nonce( 'turbo_guard_flush_notices' ),
				'trend'      => $trend,
				'strings' => array(
					'scanning'       => __( 'Scanning...', 'turbo-guard' ),
					'scanComplete'   => __( 'Scan Complete!', 'turbo-guard' ),
					'confirmDelete'  => __( 'Are you sure you want to delete these files? A backup will be created automatically.', 'turbo-guard' ),
					'deleteSuccess'  => __( 'Files deleted successfully!', 'turbo-guard' ),
					'deleteFailed'   => __( 'Failed to delete some files.', 'turbo-guard' ),
					'selectFiles'    => __( 'Please select at least one file.', 'turbo-guard' ),
					'savingSettings' => __( 'Saving...', 'turbo-guard' ),
					'settingsSaved'  => __( 'Settings saved successfully!', 'turbo-guard' ),

					// Live Traffic.
					'blockIpConfirm' => __( 'Block IP %s?', 'turbo-guard' ),
					'blocking'       => __( 'Blocking...', 'turbo-guard' ),
					'blocked'        => __( 'Blocked', 'turbo-guard' ),
					'block'          => __( 'Block', 'turbo-guard' ),

					// SEO Spam Detector.
					'seoSpamFound'              => __( 'spam indicator(s) found.', 'turbo-guard' ),
					'noSeoSpamFound'            => __( 'No SEO spam found.', 'turbo-guard' ),
					'seoScanFailed'             => __( 'Scan failed.', 'turbo-guard' ),
					'confirmDeleteSpamPost'     => __( 'Permanently delete this spam post?', 'turbo-guard' ),
					'deleting'                  => __( 'Deleting...', 'turbo-guard' ),
					'deleteFree'                => __( 'Delete (Free)', 'turbo-guard' ),
					'confirmDeleteAllSpamPosts' => __( 'Delete all spam posts? This cannot be undone.', 'turbo-guard' ),

					// File Integrity.
					'checking'               => __( 'Checking...', 'turbo-guard' ),
					'runCheckNow'            => __( 'Run Check Now', 'turbo-guard' ),
					'runNow'                 => __( 'Run Now', 'turbo-guard' ),
					'building'               => __( 'Building...', 'turbo-guard' ),
					'rebuildBaseline'        => __( 'Rebuild Baseline', 'turbo-guard' ),
					'confirmRebuildBaseline' => __( 'Rebuild baseline? This marks all current files as trusted. Only do this on a clean site.', 'turbo-guard' ),
				),
			)
		);
	}

	/**
	 * Render dashboard page.
	 *
	 * @since 1.0.0
	 */
	public function render_dashboard_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'dashboard' );
		$stats = Turbo_Guard_Settings::get_dashboard_stats();
		// Update stored score from live stats.
		if ( isset( $stats['security_score'] ) ) {
			Turbo_Guard_Activity::get_instance()->record_score( $stats['security_score'] );
		}
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/dashboard.php';
	}

	/**
	 * Render scanner page.
	 *
	 * @since 1.0.0
	 */
	public function render_scanner_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'scanner' );
		$latest_scan = Turbo_Guard_Scanner::get_latest_scan();
		$results     = array();

		if ( $latest_scan ) {
			$results = Turbo_Guard_Scanner::get_scan_results( $latest_scan->id );
		}

		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/scanner.php';
	}

	/**
	 * Render firewall page.
	 *
	 * @since 1.0.0
	 */
	public function render_firewall_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'firewall' );
		global $wpdb;

		// Cache for 60 seconds — firewall logs are time-sensitive but OK to be slightly stale.
		$cache_key     = 'turbo_guard_firewall_page_data';
		$tg_cache_data = wp_cache_get( $cache_key, 'turbo_guard' );

		if ( false === $tg_cache_data ) {
			$recent_blocks = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"SELECT * FROM {$wpdb->prefix}turbo_guard_firewall_log ORDER BY id DESC LIMIT 50"
			);
			$blocked_ips = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"SELECT * FROM {$wpdb->prefix}turbo_guard_ip_blocklist ORDER BY id DESC"
			);
			$tg_cache_data = array( 'blocks' => $recent_blocks, 'ips' => $blocked_ips );
			wp_cache_set( $cache_key, $tg_cache_data, 'turbo_guard', 60 );
		}

		$recent_blocks = $tg_cache_data['blocks'];
		$blocked_ips   = $tg_cache_data['ips'];

		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/firewall.php';
	}

	/**
	 * Render settings page.
	 *
	 * @since 1.0.0
	 */
	public function render_settings_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'settings' );
		$settings = Turbo_Guard_Settings::get_all();
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/settings.php';
	}
	/**
	 * Render GSC cleanup page.
	 *
	 * @since 1.1.0
	 */
	public function render_gsc_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'gsc' );
		$gsc = new Turbo_Guard_GSC();
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/gsc-cleanup.php';
	}

	/**
	 * Render vulnerabilities page.
	 *
	 * @since 1.1.0
	 */
	public function render_vulnerabilities_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'vulnerabilities' );
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/vulnerabilities.php';
	}

	/**
	 * Render live traffic page.
	 *
	 * @since 1.1.0
	 */
	public function render_live_traffic_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'traffic' );
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/live-traffic.php';
	}

	/**
	 * Render AI Advisor page.
	 *
	 * @since 1.2.0
	 */
	public function render_ai_report_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'ai-report' );
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/ai-report.php';
	}

	/**
	 * Render SEO Spam Detector page.
	 *
	 * @since 1.2.0
	 */
	public function render_seo_spam_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'seo-spam' );
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/seo-spam.php';
	}

	/**
	 * Render File Integrity page.
	 *
	 * @since 1.2.0
	 */
	public function render_integrity_page() {
		Turbo_Guard_Activity::get_instance()->record_visit( 'integrity' );
		$integrity_results = Turbo_Guard_Integrity::get_last_results();
		$baseline_built_at = get_option( 'turbo_guard_baseline_built_at', '' );
		$watcher_last_run  = get_option( 'turbo_guard_watcher_last_run', '' );
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/integrity.php';
	}

	/**
	 * AJAX: Run core integrity check.
	 *
	 * @since 1.2.0
	 */
	public function ajax_run_integrity_check() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ) );
		}
		$result = Turbo_Guard_Integrity::run_core_integrity_check();
		wp_send_json_success( array(
			'modified' => $result['modified'],
			'missing'  => $result['missing'],
			'message'  => sprintf( 'Done. %d modified, %d missing core files.', $result['modified'], $result['missing'] ),
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
		$count = Turbo_Guard_Integrity::build_baseline();
		wp_send_json_success( array(
			'count'   => $count,
			'message' => sprintf( 'Baseline rebuilt. %d files are now tracked.', $count ),
		) );
	}

	/**
	 * AJAX: Run file watcher manually.
	 *
	 * @since 1.2.0
	 */
	public function ajax_run_file_watcher() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ) );
		}
		$instance = Turbo_Guard_Integrity::get_instance();
		$result   = $instance->run_file_watcher();
		wp_send_json_success( array(
			'new'      => $result['new'],
			'modified' => $result['modified'],
			'deleted'  => $result['deleted'],
			'message'  => sprintf( 'Done. %d new, %d modified, %d deleted files.', $result['new'], $result['modified'], $result['deleted'] ),
		) );
	}

	/**
	 * AJAX: Start a new scan.
	 *
	 * @since 1.0.0
	 */
	public function ajax_start_scan() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$scanner = new Turbo_Guard_Scanner();
		$scan_id = $scanner->start_scan();

		wp_send_json_success(
			array(
				'scan_id' => $scan_id,
				'message' => __( 'Scan started successfully.', 'turbo-guard' ),
			)
		);
	}

	/**
	 * AJAX: Scan a chunk of files.
	 *
	 * @since 1.0.0
	 */
	public function ajax_scan_chunk() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$scan_id = isset( $_POST['scan_id'] ) ? absint( $_POST['scan_id'] ) : 0;
		$offset  = isset( $_POST['offset'] ) ? absint( $_POST['offset'] ) : 0;

		if ( ! $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid scan ID.', 'turbo-guard' ) ) );
		}

		$scanner = new Turbo_Guard_Scanner();
		$result  = $scanner->scan_chunk( $scan_id, $offset, 100 );

		// If scan is done, trigger AI analysis in background.
		if ( ! empty( $result['done'] ) ) {
			wp_schedule_single_event( time() + 2, 'turbo_guard_ai_analyse', array( $scan_id ) );
			// Record scan completion in activity tracker.
			$scan_row = Turbo_Guard_Scanner::get_latest_scan();
			$threats  = $scan_row ? (int) $scan_row->threats_found : 0;
			Turbo_Guard_Activity::get_instance()->record_scan( $threats );
		}

		wp_send_json_success( $result );
	}

	/**
	 * AJAX: Get scan results.
	 *
	 * @since 1.0.0
	 */
	public function ajax_get_results() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$scan_id  = isset( $_POST['scan_id'] ) ? absint( $_POST['scan_id'] ) : 0;
		$severity = isset( $_POST['severity'] ) ? sanitize_key( $_POST['severity'] ) : '';

		if ( ! $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid scan ID.', 'turbo-guard' ) ) );
		}

		$results = Turbo_Guard_Scanner::get_scan_results( $scan_id, $severity );

		wp_send_json_success( array( 'results' => $results ) );
	}

	/**
	 * AJAX: Delete selected files.
	 *
	 * @since 1.0.0
	 */
	public function ajax_delete_files() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$result_ids = isset( $_POST['result_ids'] ) ? array_map( 'absint', (array) $_POST['result_ids'] ) : array();

		if ( empty( $result_ids ) ) {
			wp_send_json_error( array( 'message' => __( 'No files selected.', 'turbo-guard' ) ) );
		}

		$result = Turbo_Guard_Cleaner::delete_files( $result_ids );

		// If files were cleaned, mark threats as resolved in activity tracker.
		if ( ! empty( $result['deleted'] ) && (int) $result['deleted'] > 0 ) {
			Turbo_Guard_Activity::get_instance()->record_threats_resolved();
		}

		wp_send_json_success( $result );
	}

	/**
	 * AJAX: Quarantine selected files.
	 *
	 * @since 1.0.0
	 */
	public function ajax_quarantine_files() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$result_ids = isset( $_POST['result_ids'] ) ? array_map( 'absint', (array) $_POST['result_ids'] ) : array();

		if ( empty( $result_ids ) ) {
			wp_send_json_error( array( 'message' => __( 'No files selected.', 'turbo-guard' ) ) );
		}

		$results = Turbo_Guard_Cleaner::quarantine_files( $result_ids );

		wp_send_json_success( array( 'results' => $results ) );
	}

	/**
	 * AJAX: Save settings.
	 *
	 * @since 1.0.0
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- each value is sanitized per-key against an allowlist in Turbo_Guard_Settings::update().
		$settings = isset( $_POST['settings'] ) ? wp_unslash( (array) $_POST['settings'] ) : array();

		// Save OpenAI API key.
		if ( isset( $settings['openai_api_key'] ) ) {
			if ( ! empty( $settings['openai_api_key'] ) ) {
				update_option( 'turbo_guard_openai_api_key', sanitize_text_field( $settings['openai_api_key'] ) );
			}
			unset( $settings['openai_api_key'] );
		}

		// Save GSC OAuth credentials separately (not through standard settings array).
		if ( isset( $settings['gsc_client_id'] ) ) {			update_option( 'turbo_guard_gsc_client_id', sanitize_text_field( $settings['gsc_client_id'] ) );
			unset( $settings['gsc_client_id'] );
		}
		if ( isset( $settings['gsc_client_secret'] ) ) {
			if ( ! empty( $settings['gsc_client_secret'] ) ) {
				update_option( 'turbo_guard_gsc_client_secret', sanitize_text_field( $settings['gsc_client_secret'] ) );
			}
			unset( $settings['gsc_client_secret'] );
		}

		// Save hardening options directly.
		$hardening_keys = array(
			'security_headers', 'hide_wp_version', 'disable_xmlrpc',
			'protect_rest_api', 'prevent_user_enum', 'disable_file_edit',
			'remove_readme_links', 'block_php_uploads',
		);
		foreach ( $hardening_keys as $key ) {
			if ( array_key_exists( $key, $settings ) ) {
				$value = ( 'yes' === $settings[ $key ] ) ? 'yes' : 'no';
				update_option( 'turbo_guard_' . $key, $value );
				// Apply/remove uploads .htaccess immediately.
				if ( 'block_php_uploads' === $key ) {
					if ( 'yes' === $value ) {
						Turbo_Guard_Hardening::write_uploads_htaccess();
					} else {
						Turbo_Guard_Hardening::remove_uploads_htaccess();
					}
				}
				unset( $settings[ $key ] );
			}
		}

		// Save geo-fence options.
		$geo_toggle_keys = array( 'trusted_ip_enabled', 'country_lock_enabled', 'upload_country_lock' );
		foreach ( $geo_toggle_keys as $key ) {
			if ( array_key_exists( $key, $settings ) ) {
				update_option( 'turbo_guard_' . $key, ( 'yes' === $settings[ $key ] ) ? 'yes' : 'no' );
				unset( $settings[ $key ] );
			}
		}
		if ( isset( $_POST['settings']['trusted_ips'] ) ) {
			update_option( 'turbo_guard_trusted_ips', sanitize_textarea_field( wp_unslash( $_POST['settings']['trusted_ips'] ) ) );
		}
		if ( isset( $_POST['settings']['allowed_countries'] ) && is_array( $_POST['settings']['allowed_countries'] ) ) {
			$codes = array_map( 'sanitize_text_field', wp_unslash( $_POST['settings']['allowed_countries'] ) );
			update_option( 'turbo_guard_allowed_countries', implode( ',', $codes ) );
		} elseif ( array_key_exists( 'allowed_countries', $settings ) ) {
			update_option( 'turbo_guard_allowed_countries', '' );
		}

		Turbo_Guard_Settings::update( $settings );

		wp_send_json_success( array( 'message' => __( 'Settings saved successfully.', 'turbo-guard' ) ) );
	}

	/**
	 * AJAX: Get dashboard stats (for live updates).
	 *
	 * @since 1.0.0
	 */
	public function ajax_get_dashboard_stats() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$stats = Turbo_Guard_Settings::get_dashboard_stats();

		wp_send_json_success( $stats );
	}

	// =========================================================
	// GSC AJAX HANDLERS
	// =========================================================

	/**
	 * AJAX: Fetch indexed URLs from Google Search Console.
	 *
	 * @since 1.1.0
	 */
	public function ajax_gsc_get_urls() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$gsc = new Turbo_Guard_GSC();

		if ( ! $gsc->is_connected() ) {
			wp_send_json_error( array( 'message' => __( 'Google Search Console is not connected.', 'turbo-guard' ) ) );
		}

		$site_url = home_url( '/' );
		$urls     = $gsc->get_indexed_urls( $site_url );

		if ( is_wp_error( $urls ) ) {
			wp_send_json_error( array( 'message' => $urls->get_error_message() ) );
		}

		wp_send_json_success(
			array(
				'urls'  => $urls,
				'count' => count( $urls ),
			)
		);
	}

	/**
	 * AJAX: Submit bulk URL removal requests to Google.
	 *
	 * @since 1.1.0
	 */
	public function ajax_gsc_remove_urls() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$urls = isset( $_POST['urls'] ) ? array_map( 'esc_url_raw', wp_unslash( (array) $_POST['urls'] ) ) : array();

		if ( empty( $urls ) ) {
			wp_send_json_error( array( 'message' => __( 'No URLs provided.', 'turbo-guard' ) ) );
		}

		$gsc       = new Turbo_Guard_GSC();
		$site_url  = home_url( '/' );
		$submitted = 0;
		$failed    = 0;

		foreach ( $urls as $url ) {
			$url = esc_url_raw( $url );
			if ( ! $url ) {
				++$failed;
				continue;
			}

			$result = $gsc->request_url_removal( $site_url, $url );

			if ( $result && ! is_wp_error( $result ) ) {
				++$submitted;
			} else {
				++$failed;
			}

			// Small delay to avoid rate limiting.
			usleep( 100000 ); // 0.1 second.
		}

		// Log the event.
		Turbo_Guard_Scanner::log_event(
			'gsc_removal_requested',
			'info',
			sprintf(
				/* translators: 1: submitted count, 2: failed count */
				__( 'GSC removal requested: %1$d submitted, %2$d failed.', 'turbo-guard' ),
				$submitted,
				$failed
			)
		);

		wp_send_json_success(
			array(
				'submitted' => $submitted,
				'failed'    => $failed,
				'message'   => sprintf(
				/* translators: 1: submitted count */
					__( 'Removal requested for %d URLs. Google will process within 24-72 hours.', 'turbo-guard' ),
					$submitted
				),
			)
		);
	}

	/**
	 * AJAX: Resubmit sitemap to Google Search Console.
	 *
	 * @since 1.1.0
	 */
	public function ajax_gsc_submit_sitemap() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$gsc         = new Turbo_Guard_GSC();
		$site_url    = home_url( '/' );
		$sitemap_url = home_url( '/sitemap.xml' );

		// Try common sitemap locations.
		$sitemaps = array(
			home_url( '/sitemap.xml' ),
			home_url( '/sitemap_index.xml' ),
			home_url( '/wp-sitemap.xml' ), // WordPress built-in sitemap.
		);

		$submitted = false;
		foreach ( $sitemaps as $sitemap ) {
			$response = wp_remote_head( $sitemap );
			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$result = $gsc->submit_sitemap( $site_url, $sitemap );
				if ( $result ) {
					$submitted   = true;
					$sitemap_url = $sitemap;
					break;
				}
			}
		}

		if ( $submitted ) {
			wp_send_json_success(
				array(
					'message' => sprintf(
					/* translators: %s: sitemap URL */
						__( 'Sitemap submitted: %s', 'turbo-guard' ),
						$sitemap_url
					),
					'sitemap' => $sitemap_url,
				)
			);
		} else {
			wp_send_json_error( array( 'message' => __( 'Could not find or submit sitemap. Please submit manually from Google Search Console.', 'turbo-guard' ) ) );
		}
	}

	/**
	 * AJAX: Disconnect Google Search Console.
	 *
	 * @since 1.1.0
	 */
	public function ajax_gsc_disconnect() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		Turbo_Guard_GSC::disconnect();

		wp_send_json_success( array( 'message' => __( 'Disconnected from Google Search Console.', 'turbo-guard' ) ) );
	}

	// =========================================================
	// FIREWALL IP MANAGEMENT AJAX HANDLERS
	// =========================================================

	/**
	 * AJAX: Block an IP address.
	 *
	 * @since 1.0.0
	 */
	public function ajax_block_ip() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$ip = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'turbo-guard' ) ) );
		}

		$result = Turbo_Guard_Firewall::block_ip( $ip, __( 'Manually blocked by admin', 'turbo-guard' ) );

		if ( $result ) {
			wp_send_json_success(
				array(
					/* translators: %s: IP address */
					'message' => sprintf( __( 'IP %s blocked.', 'turbo-guard' ), $ip ),
				)
			);
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to block IP.', 'turbo-guard' ) ) );
		}
	}

	/**
	 * AJAX: Unblock an IP address.
	 *
	 * @since 1.0.0
	 */
	public function ajax_unblock_ip() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$ip = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'turbo-guard' ) ) );
		}

		$result = Turbo_Guard_Firewall::unblock_ip( $ip );

		if ( $result ) {
			wp_send_json_success(
				array(
					/* translators: %s: IP address */
					'message' => sprintf( __( 'IP %s unblocked.', 'turbo-guard' ), $ip ),
				)
			);
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to unblock IP.', 'turbo-guard' ) ) );
		}
	}

	/**
	 * AJAX: Run SEO spam scan.
	 *
	 * @since 1.2.0
	 */
	public function ajax_run_seo_spam_scan() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$results = Turbo_Guard_SEO_Spam_Detector::run_scan();

		wp_send_json_success( array(
			'total'   => $results['total'],
			// translators: %d: number of spam indicators found
			'message' => sprintf( __( 'Scan complete. %d spam indicator(s) found.', 'turbo-guard' ), $results['total'] ),
		) );
	}

	/**
	 * AJAX: Delete a spam post.
	 *
	 * @since 1.2.0
	 */
	public function ajax_delete_spam_post() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$post_id = isset( $_POST['post_id'] ) ? absint( $_POST['post_id'] ) : 0;
		if ( ! $post_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid post ID.', 'turbo-guard' ) ) );
		}

		$result = Turbo_Guard_SEO_Spam_Detector::delete_spam_post( $post_id );
		if ( $result ) {
			wp_send_json_success( array(
				// translators: %d: post ID that was deleted
				'message' => sprintf( __( 'Post %d deleted.', 'turbo-guard' ), $post_id ),
			) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to delete post.', 'turbo-guard' ) ) );
		}
	}

	/**
	 * AJAX: Mark a scanned file as safe (add to ignore list).
	 *
	 * Mirrors the Wordfence "ignore" workflow. Stores the absolute file path in
	 * a WordPress option so it is:
	 *  1. Skipped during ALL future scans.
	 *  2. Hidden from previous scan results immediately (get_scan_results filters it out).
	 *
	 * @since 1.2.1
	 */
	public function ajax_ignore_file() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$result_id = isset( $_POST['result_id'] ) ? absint( $_POST['result_id'] ) : 0;
		if ( ! $result_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid result ID.', 'turbo-guard' ) ) );
		}

		global $wpdb;

		// Fetch the file path from the scan result.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom security table / plugin stats, no WP core cache available.
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT file_path FROM {$wpdb->prefix}turbo_guard_scan_results WHERE id = %d LIMIT 1",
			$result_id
		) );

		if ( ! $row ) {
			wp_send_json_error( array( 'message' => __( 'Scan result not found.', 'turbo-guard' ) ) );
		}

		// Add to ignore list and mark result as ignored in DB.
		Turbo_Guard_Scanner::ignore_file( $row->file_path );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom security table write, no WP core cache available.
		$wpdb->update(
			$wpdb->prefix . 'turbo_guard_scan_results',
			array( 'status' => 'ignored' ),
			array( 'id' => $result_id ),
			array( '%s' ),
			array( '%d' )
		);

		wp_send_json_success( array(
			'message'   => __( 'File marked as safe and will be excluded from future scans.', 'turbo-guard' ),
			'result_id' => $result_id,
		) );
	}

	/**
	 * AJAX: Remove a file from the ignore list (re-enable scanning).
	 *
	 * @since 1.2.1
	 */
	public function ajax_unignore_file() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
		if ( ! $file_path ) {
			wp_send_json_error( array( 'message' => __( 'No file path provided.', 'turbo-guard' ) ) );
		}

		Turbo_Guard_Scanner::unignore_file( $file_path );

		wp_send_json_success( array( 'message' => __( 'File removed from ignore list.', 'turbo-guard' ) ) );
	}

	/**
	 * Print ajaxUrl + base nonce for the remote notice dismiss JS.
	 * The per-notice nonce is embedded directly in each notice's dismiss button,
	 * so this just ensures turboGuardAdmin is available on every TG page.
	 *
	 * @since 1.3.0
	 */
	public function print_notices_nonce_data() {
		$screen = get_current_screen();
		if ( ! $screen || strpos( $screen->id, 'turbo-guard' ) === false ) {
			return;
		}
		// turboGuardAdmin is already localised in enqueue_admin_assets().
		// Nothing extra needed — per-notice nonces are inline on each button.
	}
}

// NOTE: New AJAX handlers are appended below (added in v1.1.0 refactor).
// The class closing brace above ends the original class block.
// The following global functions register additional AJAX hooks on plugins_loaded.

/**
 * Register v1.1.0 AJAX handlers for vulnerability scanner and live traffic.
 * These are registered as standalone wp_ajax actions to avoid reopening the class.
 *
 * @since 1.1.0
 */
function turbo_guard_register_v110_ajax() {
	add_action( 'wp_ajax_turbo_guard_run_vuln_scan', 'turbo_guard_ajax_run_vuln_scan' );
	add_action( 'wp_ajax_turbo_guard_get_traffic',   'turbo_guard_ajax_get_traffic' );
}
add_action( 'plugins_loaded', 'turbo_guard_register_v110_ajax' );

/**
 * AJAX: Run vulnerability scan.
 *
 * @since 1.1.0
 */
function turbo_guard_ajax_run_vuln_scan() {
	check_ajax_referer( 'turbo_guard_admin', 'nonce' );

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
	}

	@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.PHP.DiscouragedFunctions.Discouraged

	$results = Turbo_Guard_Vuln_Scanner::run_scan();

	wp_send_json_success( array(
		'total'   => $results['total'],
		'plugins' => count( $results['plugins'] ),
		'themes'  => count( $results['themes'] ),
		'message' => sprintf(
			/* translators: %d: vulnerability count */
			__( 'Scan complete. %d vulnerabilities found.', 'turbo-guard' ),
			$results['total']
		),
	) );
}

/**
 * AJAX: Get live traffic rows.
 *
 * @since 1.1.0
 */
function turbo_guard_ajax_get_traffic() {
	check_ajax_referer( 'turbo_guard_admin', 'nonce' );

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
	}

	$filter = isset( $_POST['filter'] ) ? sanitize_key( $_POST['filter'] ) : 'all';
	$limit  = isset( $_POST['limit'] )  ? absint( $_POST['limit'] )        : 100;

	$rows  = Turbo_Guard_Live_Traffic::get_traffic( $limit, $filter );
	$stats = Turbo_Guard_Live_Traffic::get_stats();

	wp_send_json_success( array(
		'rows'  => $rows,
		'stats' => $stats,
	) );
}
