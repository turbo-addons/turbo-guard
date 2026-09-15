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

		// Vulnerability scanner AJAX (standalone function defined at bottom of this file).
		add_action( 'wp_ajax_turbo_guard_run_vuln_scan', 'turbo_guard_ajax_run_vuln_scan' );

		// Integrity + file watcher AJAX.
		add_action( 'wp_ajax_turbo_guard_run_integrity_check', array( $this, 'ajax_run_integrity_check' ) );
		add_action( 'wp_ajax_turbo_guard_rebuild_baseline', array( $this, 'ajax_rebuild_baseline' ) );
		add_action( 'wp_ajax_turbo_guard_run_file_watcher', array( $this, 'ajax_run_file_watcher' ) );

		// SEO Spam Detector AJAX.
		add_action( 'wp_ajax_turbo_guard_run_seo_spam_scan', array( $this, 'ajax_run_seo_spam_scan' ) );
		add_action( 'wp_ajax_turbo_guard_delete_spam_post',  array( $this, 'ajax_delete_spam_post' ) );
		add_action( 'wp_ajax_turbo_guard_ignore_seo_spam',   array( $this, 'ajax_ignore_seo_spam' ) );

		// Scanner: ignore / unignore file.
		add_action( 'wp_ajax_turbo_guard_ignore_file',   array( $this, 'ajax_ignore_file' ) );
		add_action( 'wp_ajax_turbo_guard_unignore_file', array( $this, 'ajax_unignore_file' ) );

		// Scanner: mark a finding as fixed.
		add_action( 'wp_ajax_turbo_guard_mark_fixed', array( $this, 'ajax_mark_fixed' ) );

		// Scanner: view a threat's file content (Pro only).
		add_action( 'wp_ajax_turbo_guard_view_file', array( $this, 'ajax_view_file' ) );

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
		// Show "Turbo Guard Pro" in the sidebar when the Pro add-on is licensed.
		$turbo_guard_menu_title = turbo_guard_is_pro()
			? __( 'Turbo Guard Pro', 'turbo-guard' )
			: __( 'Turbo Guard', 'turbo-guard' );

		add_menu_page(
			__( 'Turbo Guard', 'turbo-guard' ),
			$turbo_guard_menu_title,
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
			__( 'File Integrity', 'turbo-guard' ),
			__( 'File Integrity', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-integrity',
			array( $this, 'render_integrity_page' )
		);

		add_submenu_page(
			'turbo-guard',
			__( 'SEO Spam Detector', 'turbo-guard' ),
			__( 'SEO Spam', 'turbo-guard' ),
			'manage_options',
			'turbo-guard-seo-spam',
			array( $this, 'render_seo_spam_page' )
		);

		// Locked Pro features (hidden when the Pro add-on is active — it adds the real ones).
		if ( ! turbo_guard_is_pro() ) {
			add_submenu_page(
				'turbo-guard',
				__( 'Live Traffic (Pro)', 'turbo-guard' ),
				__( 'Live Traffic', 'turbo-guard' ),
				'manage_options',
				'turbo-guard-pro-live-traffic',
				array( $this, 'render_pro_upsell_page' )
			);

			add_submenu_page(
				'turbo-guard',
				__( 'AI Advisor (Pro)', 'turbo-guard' ),
				__( 'AI Advisor', 'turbo-guard' ),
				'manage_options',
				'turbo-guard-pro-ai-advisor',
				array( $this, 'render_pro_upsell_page' )
			);
		}
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

		// Pass data to JS.
		wp_localize_script(
			'turbo-guard-admin',
			'turboGuardAdmin',
			array(
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				'nonce'      => wp_create_nonce( 'turbo_guard_admin' ),
				'isPro'      => turbo_guard_is_pro(),
				'proUrl'     => turbo_guard_pro_url(),
				'strings' => array(
					'scanning'       => __( 'Scanning...', 'turbo-guard' ),
					'scanComplete'   => __( 'Scan Complete!', 'turbo-guard' ),
					'confirmDelete'  => __( 'Are you sure you want to delete these files? A backup will be created automatically.', 'turbo-guard' ),
					'deleteSuccess'  => __( 'Files deleted successfully!', 'turbo-guard' ),
					'deleteFailed'   => __( 'Failed to delete some files.', 'turbo-guard' ),
					'selectFiles'    => __( 'Please select at least one file.', 'turbo-guard' ),
					'savingSettings' => __( 'Saving...', 'turbo-guard' ),
					'settingsSaved'  => __( 'Settings saved successfully!', 'turbo-guard' ),

					// SEO Spam Detector.
					'seoSpamFound'              => __( 'spam indicator(s) found.', 'turbo-guard' ),
					'noSeoSpamFound'            => __( 'No SEO spam found.', 'turbo-guard' ),
					'seoScanFailed'             => __( 'Scan failed.', 'turbo-guard' ),
					'deleting'                  => __( 'Deleting...', 'turbo-guard' ),
					'deleteFree'                => __( 'Delete', 'turbo-guard' ),
					'cancel'                    => __( 'Cancel', 'turbo-guard' ),
					'seoDeleteTitle'            => __( 'Remove this spam post?', 'turbo-guard' ),
					'seoDeleteBody'             => __( 'Choose how you want to remove this spam post.', 'turbo-guard' ),
					'seoTrashOption'            => __( 'Move to Trash (recoverable)', 'turbo-guard' ),
					'seoPermanentOption'        => __( 'Delete Permanently', 'turbo-guard' ),
					'seoPermanentUpgrade'       => __( 'Permanent delete is a Pro feature. Upgrade to Turbo Guard Pro, or move the post to Trash instead.', 'turbo-guard' ),
					'confirmDeleteAllSpamPosts' => __( 'Move all selected spam posts to Trash? This can be undone from the Trash.', 'turbo-guard' ),
					'confirmIgnoreSeoSpam'      => __( 'Mark this item as safe and exclude it from future scans?', 'turbo-guard' ),

					// File Integrity.
					'checking'               => __( 'Checking...', 'turbo-guard' ),
					'runCheckNow'            => __( 'Run Check Now', 'turbo-guard' ),
					'runNow'                 => __( 'Run Now', 'turbo-guard' ),
					'building'               => __( 'Building...', 'turbo-guard' ),
					'rebuildBaseline'        => __( 'Rebuild Baseline', 'turbo-guard' ),
					'confirmRebuildBaseline' => __( 'Rebuild baseline? This marks all current files as trusted. Only do this on a clean site.', 'turbo-guard' ),

					// Scanner file view (Pro upsell).
					'viewFile'      => __( 'View', 'turbo-guard' ),
					'viewProTitle'  => __( 'Turbo Guard Pro', 'turbo-guard' ),
					'viewProMessage'=> __( 'Viewing file contents is a Pro feature. Upgrade to inspect every threat in detail and clean unlimited files.', 'turbo-guard' ),
					'upgradeNow'    => __( 'Upgrade Now', 'turbo-guard' ),
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
		$turbo_guard_stats = Turbo_Guard_Settings::get_dashboard_stats();
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/dashboard.php';
	}

	/**
	 * Render scanner page.
	 *
	 * @since 1.0.0
	 */
	public function render_scanner_page() {
		$turbo_guard_latest_scan = Turbo_Guard_Scanner::get_latest_scan();
		$turbo_guard_results     = array();

		if ( $turbo_guard_latest_scan ) {
			$turbo_guard_results = Turbo_Guard_Scanner::get_scan_results( $turbo_guard_latest_scan->id );
		}

		$turbo_guard_is_pro       = turbo_guard_is_pro();
		$turbo_guard_free_remain  = turbo_guard_free_cleanup_remaining();
		$turbo_guard_scan_summary = $this->get_scan_summary( $turbo_guard_latest_scan );

		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/scanner.php';
	}

	/**
	 * Build the Wordfence-style scan summary (what was checked, by category).
	 *
	 * @since 1.3.0
	 * @param object|null $scan Latest completed scan row.
	 * @return array Category => count.
	 */
	private function get_scan_summary( $scan ) {
		$posts = wp_count_posts();
		$users = count_users();

		return array(
			'files'   => $scan ? absint( $scan->scanned_files ) : 0,
			'plugins' => function_exists( 'get_plugins' ) ? count( get_plugins() ) : 0,
			'themes'  => count( wp_get_themes() ),
			'posts'   => absint( $posts->publish ) + absint( $posts->draft ) + absint( $posts->pending ) + absint( $posts->private ),
			'users'   => absint( $users['total_users'] ),
		);
	}

	/**
	 * Render firewall page.
	 *
	 * @since 1.0.0
	 */
	public function render_firewall_page() {
		global $wpdb;

		// Cache for 60 seconds — firewall logs are time-sensitive but OK to be slightly stale.
		$cache_key     = 'turbo_guard_firewall_page_data';
		$turbo_guard_cache_data = wp_cache_get( $cache_key, 'turbo_guard' );

		if ( false === $turbo_guard_cache_data ) {
			$recent_blocks = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"SELECT * FROM {$wpdb->prefix}turbo_guard_firewall_log ORDER BY id DESC LIMIT 50"
			);
			$blocked_ips = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"SELECT * FROM {$wpdb->prefix}turbo_guard_ip_blocklist ORDER BY id DESC"
			);
			$turbo_guard_cache_data = array( 'blocks' => $recent_blocks, 'ips' => $blocked_ips );
			wp_cache_set( $cache_key, $turbo_guard_cache_data, 'turbo_guard', 60 );
		}

		$turbo_guard_recent_blocks = $turbo_guard_cache_data['blocks'];
		$turbo_guard_blocked_ips   = $turbo_guard_cache_data['ips'];

		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/firewall.php';
	}

	/**
	 * Render settings page.
	 *
	 * @since 1.0.0
	 */
	public function render_settings_page() {
		$turbo_guard_settings = Turbo_Guard_Settings::get_all();
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/settings.php';
	}
	/**
	 * Render GSC cleanup page.
	 *
	 * @since 1.1.0
	 */
	public function render_gsc_page() {
		$turbo_guard_gsc = new Turbo_Guard_GSC();
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/gsc-cleanup.php';
	}

	/**
	 * Render vulnerabilities page.
	 *
	 * @since 1.1.0
	 */
	public function render_vulnerabilities_page() {
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/vulnerabilities.php';
	}

	/**
	 * Render SEO Spam Detector page.
	 *
	 * @since 1.2.0
	 */
	public function render_seo_spam_page() {
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/seo-spam.php';
	}

	/**
	 * Render File Integrity page.
	 *
	 * @since 1.2.0
	 */
	public function render_integrity_page() {
		$turbo_guard_integrity_results = Turbo_Guard_Integrity::get_last_results();
		$turbo_guard_baseline_built_at = get_option( 'turbo_guard_baseline_built_at', '' );
		$turbo_guard_watcher_last_run  = get_option( 'turbo_guard_watcher_last_run', '' );
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/integrity.php';
	}

	/**
	 * Render the Pro upsell page for locked features.
	 *
	 * @since 2.0.0
	 */
	public function render_pro_upsell_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only page slug for display.
		$turbo_guard_pro_feature = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		include TURBO_GUARD_PLUGIN_DIR . 'admin/views/pro-upsell.php';
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

		// Notify the Pro add-on when a scan completes (for AI analysis etc.).
		if ( ! empty( $result['done'] ) ) {
			do_action( 'turbo_guard_scan_completed', $scan_id );
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

		if ( ! turbo_guard_is_pro() ) {
			$remaining = turbo_guard_free_cleanup_remaining();

			if ( $remaining <= 0 ) {
				wp_send_json_error(
					array(
						'message' => sprintf(
							/* translators: %s: pro URL */
							__( 'You have reached the free cleanup limit. <a href="%s">Upgrade to Turbo Guard Pro</a> for unlimited cleanup.', 'turbo-guard' ),
							esc_url( turbo_guard_pro_url() )
						),
					)
				);
			}

			if ( count( $result_ids ) > $remaining ) {
				wp_send_json_error(
					array(
						'message' => sprintf(
							/* translators: 1: remaining count, 2: pro URL */
							__( 'The free version can only clean %1$d more file(s). <a href="%2$s">Upgrade to Turbo Guard Pro</a> for unlimited cleanup.', 'turbo-guard' ),
							$remaining,
							esc_url( turbo_guard_pro_url() )
						),
					)
				);
			}
		}

		$result = Turbo_Guard_Cleaner::delete_files( $result_ids );

		// Record successful cleanup against the free-tier quota.
		if ( ! turbo_guard_is_pro() && ! empty( $result['deleted'] ) ) {
			turbo_guard_increment_free_cleanup( (int) $result['deleted'] );
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

		if ( ! turbo_guard_is_pro() ) {
			$remaining = turbo_guard_free_cleanup_remaining();

			if ( $remaining <= 0 ) {
				wp_send_json_error(
					array(
						'message' => sprintf(
							/* translators: %s: pro URL */
							__( 'You have reached the free cleanup limit. <a href="%s">Upgrade to Turbo Guard Pro</a> for unlimited cleanup.', 'turbo-guard' ),
							esc_url( turbo_guard_pro_url() )
						),
					)
				);
			}

			if ( count( $result_ids ) > $remaining ) {
				wp_send_json_error(
					array(
						'message' => sprintf(
							/* translators: 1: remaining count, 2: pro URL */
							__( 'The free version can only clean %1$d more file(s). <a href="%2$s">Upgrade to Turbo Guard Pro</a> for unlimited cleanup.', 'turbo-guard' ),
							$remaining,
							esc_url( turbo_guard_pro_url() )
						),
					)
				);
			}
		}

		$results = Turbo_Guard_Cleaner::quarantine_files( $result_ids );

		// Record successful cleanup against the free-tier quota.
		if ( ! turbo_guard_is_pro() && ! empty( $results ) && is_array( $results ) ) {
			$quarantined = 0;
			foreach ( $results as $qr ) {
				if ( is_array( $qr ) && ! empty( $qr['success'] ) ) {
					++$quarantined;
				}
			}
			if ( $quarantined > 0 ) {
				turbo_guard_increment_free_cleanup( $quarantined );
			}
		}

		wp_send_json_success( array( 'results' => $results ) );
	}

	/**
	 * AJAX: View a threat's file content.
	 *
	 * Reads the flagged file and returns a sanitized snippet for display.
	 * Pro users can view any file; free users can view files within their
	 * cleanup quota (the same files they are allowed to delete).
	 *
	 * @since 1.1.1
	 * @since 1.4.0 Free users can view files within their cleanup quota.
	 */
	public function ajax_view_file() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$result_id = isset( $_POST['result_id'] ) ? absint( $_POST['result_id'] ) : 0;

		if ( ! $result_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid file.', 'turbo-guard' ) ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, scan_id, file_path, threat_name, threat_details, severity FROM {$wpdb->prefix}turbo_guard_scan_results WHERE id = %d",
				$result_id
			)
		);

		if ( ! $row ) {
			wp_send_json_error( array( 'message' => __( 'File not found.', 'turbo-guard' ) ) );
		}

		// Pro users can view any flagged file. Free users can view files within
		// their cleanup quota — the same files they are allowed to delete.
		if ( ! turbo_guard_is_pro() && ! $this->is_free_viewable_result( $row ) ) {
			wp_send_json_error( array( 'message' => __( 'Viewing file contents is a Turbo Guard Pro feature.', 'turbo-guard' ) ) );
		}

		// Only filesystem files can be viewed — not database entries.
		if ( 0 === strpos( $row->file_path, 'database://' ) ) {
			wp_send_json_error( array( 'message' => __( 'This is a database entry and cannot be viewed as a file.', 'turbo-guard' ) ) );
		}

		$file_path = $row->file_path;
		if ( ! is_readable( $file_path ) || ! is_file( $file_path ) ) {
			wp_send_json_error( array( 'message' => __( 'The file is no longer available on disk.', 'turbo-guard' ) ) );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$content = @file_get_contents( $file_path, false, null, 0, 8192 );
		if ( false === $content ) {
			wp_send_json_error( array( 'message' => __( 'Could not read the file.', 'turbo-guard' ) ) );
		}

		wp_send_json_success(
			array(
				'file_path'      => str_replace( ABSPATH, '', $file_path ),
				'threat_name'    => $row->threat_name,
				'threat_details' => $row->threat_details,
				'severity'       => $row->severity,
				'content'        => $content,
				'truncated'      => strlen( $content ) >= 8192,
			)
		);
	}

	/**
	 * Whether a free user may view a given scan result's file content.
	 *
	 * Mirrors the scanner view's cleanup ordering: filesystem files are counted
	 * in display order (critical → high → medium → info, then id) and a free
	 * user may view the first N (their remaining cleanup quota).
	 *
	 * @since 1.4.0
	 * @param object $row Scan result row.
	 * @return bool
	 */
	private function is_free_viewable_result( $row ) {
		$remaining = turbo_guard_free_cleanup_remaining();
		if ( $remaining <= 0 ) {
			return false;
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$ordered_ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT id FROM {$wpdb->prefix}turbo_guard_scan_results
				 WHERE scan_id = %d AND status = 'pending' AND file_path NOT LIKE %s
				 ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'info') ASC, id ASC",
				absint( $row->scan_id ),
				'database://%'
			)
		);

		$position = array_search( (int) $row->id, array_map( 'intval', $ordered_ids ), true );

		return ( false !== $position && $position < $remaining );
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

		// Save WPScan API key separately.
		if ( array_key_exists( 'wpscan_api_key', $settings ) ) {
			update_option( 'turbo_guard_wpscan_api_key', sanitize_text_field( $settings['wpscan_api_key'] ) );
			unset( $settings['wpscan_api_key'] );
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

		// Allow the Pro add-on to save its own settings (geo-fence, AI).
		do_action( 'turbo_guard_settings_save', $settings );

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
			$message = $urls->get_error_message();
			if ( 'gsc_permission_denied' === $urls->get_error_code() ) {
				$message = __( 'Your Google account does not have access to this Search Console property. Open search.google.com with the SAME Google account, make sure the site is added as a property, and that you are a verified owner (or have been added as a user).', 'turbo-guard' );
			} elseif ( 'gsc_not_found' === $urls->get_error_code() ) {
				$message = __( 'No Search Console property was found for this site. Go to search.google.com, add your site as a property, and verify ownership.', 'turbo-guard' );
			}
			wp_send_json_error( array( 'message' => $message ) );
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

		$gsc        = new Turbo_Guard_GSC();
		$site_url   = home_url( '/' );
		$submitted  = 0;
		$failed     = 0;
		$last_error = '';

		foreach ( $urls as $url ) {
			$url = esc_url_raw( $url );
			if ( ! $url ) {
				++$failed;
				continue;
			}

			$result = $gsc->request_url_removal( $site_url, $url );

			if ( is_wp_error( $result ) ) {
				++$failed;
				if ( '' === $last_error ) {
					$last_error = $result->get_error_message();
				}
			} else {
				++$submitted;
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
				'submitted'  => $submitted,
				'failed'     => $failed,
				'last_error' => $last_error,
				'message'    => sprintf(
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
	 * AJAX: Delete or trash a spam post.
	 *
	 * @since 1.2.0
	 * @since 1.4.0 Trash is default; permanent delete is Pro-only; verifies
	 *              the post is in the current scan results; free quota = 10%.
	 */
	public function ajax_delete_spam_post() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$post_id = isset( $_POST['post_id'] ) ? absint( $_POST['post_id'] ) : 0;
		$mode    = isset( $_POST['mode'] ) ? sanitize_key( $_POST['mode'] ) : 'trash';
		if ( ! in_array( $mode, array( 'trash', 'delete' ), true ) ) {
			$mode = 'trash';
		}

		if ( ! $post_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid post ID.', 'turbo-guard' ) ) );
		}

		// Only allow removing posts the SEO spam scan actually flagged.
		$results    = Turbo_Guard_SEO_Spam_Detector::get_cached_results();
		$spam_posts = ( is_array( $results ) && ! empty( $results['spam_posts'] ) ) ? $results['spam_posts'] : array();
		$ids        = array_column( $spam_posts, 'id' );
		$index      = array_search( $post_id, array_map( 'intval', $ids ), true );

		if ( false === $index ) {
			wp_send_json_error( array( 'message' => __( 'This post is not in the current SEO spam scan results. Re-run the scan first.', 'turbo-guard' ) ) );
		}

		$is_pro = turbo_guard_is_pro();

		// Permanent delete is a Pro feature.
		if ( 'delete' === $mode && ! $is_pro ) {
			wp_send_json_error(
				array(
					'message' => sprintf(
						/* translators: %s: pro URL */
						__( 'Permanent delete is a Pro feature. <a href="%s">Upgrade to Turbo Guard Pro</a>, or move the post to Trash instead.', 'turbo-guard' ),
						esc_url( turbo_guard_pro_url() )
					),
				)
			);
		}

		// Free users can only clean the first ceil(10%) of spam posts.
		if ( ! $is_pro ) {
			$deletable = Turbo_Guard_SEO_Spam_Detector::free_deletable_count( count( $spam_posts ) );
			if ( $index >= $deletable ) {
				wp_send_json_error(
					array(
						'message' => sprintf(
							/* translators: 1: deletable count, 2: pro URL */
							__( 'The free version can only move the first %1$d spam posts to Trash. <a href="%2$s">Upgrade to Turbo Guard Pro</a> to remove all spam.', 'turbo-guard' ),
							$deletable,
							esc_url( turbo_guard_pro_url() )
						),
					)
				);
			}
		}

		$result = Turbo_Guard_SEO_Spam_Detector::delete_spam_post( $post_id, $mode );
		if ( $result ) {
			wp_send_json_success(
				array(
					// translators: %d: post ID that was removed
					'message' => sprintf( __( 'Post %d removed.', 'turbo-guard' ), $post_id ),
				)
			);
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to remove post.', 'turbo-guard' ) ) );
		}
	}

	/**
	 * AJAX: Mark an SEO spam item as safe (add to ignore list).
	 *
	 * @since 1.4.0
	 */
	public function ajax_ignore_seo_spam() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$bucket = isset( $_POST['bucket'] ) ? sanitize_key( $_POST['bucket'] ) : '';
		$key    = isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '';

		if ( 'posts' === $bucket ) {
			$key = absint( $key );
		}

		if ( ! in_array( $bucket, array( 'posts', 'options', 'files' ), true ) || '' === (string) $key ) {
			wp_send_json_error( array( 'message' => __( 'Invalid item.', 'turbo-guard' ) ) );
		}

		$result = Turbo_Guard_SEO_Spam_Detector::ignore_item( $bucket, $key );

		if ( $result ) {
			wp_send_json_success( array( 'message' => __( 'Item marked as safe and excluded from future scans.', 'turbo-guard' ) ) );
		}

		wp_send_json_error( array( 'message' => __( 'Failed to ignore item.', 'turbo-guard' ) ) );
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT file_path FROM {$wpdb->prefix}turbo_guard_scan_results WHERE id = %d LIMIT 1",
			$result_id
		) );

		if ( ! $row ) {
			wp_send_json_error( array( 'message' => __( 'Scan result not found.', 'turbo-guard' ) ) );
		}

		// Add to ignore list and mark result as ignored in DB.
		Turbo_Guard_Scanner::ignore_file( $row->file_path );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
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
	 * AJAX: Mark a scan finding as fixed (resolved).
	 *
	 * Sets the result status to "fixed" so it is hidden from active results
	 * (get_scan_results only returns pending rows). Mirrors Wordfence's
	 * "Mark as Fixed" workflow.
	 *
	 * @since 1.3.0
	 */
	public function ajax_mark_fixed() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'turbo-guard' ) ) );
		}

		$result_id = isset( $_POST['result_id'] ) ? absint( $_POST['result_id'] ) : 0;
		if ( ! $result_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid result ID.', 'turbo-guard' ) ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$updated = $wpdb->update(
			$wpdb->prefix . 'turbo_guard_scan_results',
			array( 'status' => 'fixed' ),
			array( 'id' => $result_id ),
			array( '%s' ),
			array( '%d' )
		);

		if ( false === $updated ) {
			wp_send_json_error( array( 'message' => __( 'Failed to update the result.', 'turbo-guard' ) ) );
		}

		wp_send_json_success( array(
			'message'   => __( 'Finding marked as fixed.', 'turbo-guard' ),
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
// The following global functions define the standalone AJAX callbacks registered in the constructor.

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

	@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged

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

