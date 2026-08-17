<?php
/**
 * Main Turbo Guard Class.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Main plugin class - Singleton pattern.
 *
 * @since 1.0.0
 */
class Turbo_Guard {

	/**
	 * Single instance of the class.
	 *
	 * @var Turbo_Guard|null
	 */
	private static $instance = null;

	/**
	 * Get class instance.
	 *
	 * @since 1.0.0
	 * @return Turbo_Guard
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
		$this->load_dependencies();
		$this->init_hooks();
	}

	/**
	 * Load required dependencies.
	 *
	 * @since 1.0.0
	 */
	private function load_dependencies() {
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-scanner.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-cleaner.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-firewall.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-login-security.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-settings.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-gsc.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-hardening.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-2fa.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-vuln-scanner.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-live-traffic.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-ai-advisor.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-geo-fence.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-integrity.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-bot-protection.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-seo-spam-detector.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-notices.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-activity.php';

		// Admin classes.
		if ( is_admin() ) {
			require_once TURBO_GUARD_PLUGIN_DIR . 'admin/class-turbo-guard-admin.php';
		}
	}

	/**
	 * Initialize WordPress hooks.
	 *
	 * @since 1.0.0
	 */
	private function init_hooks() {
		// Load text domain for translations.
		add_action( 'init', array( $this, 'load_textdomain' ) );

		// Initialize components.
		add_action( 'init', array( $this, 'init_components' ) );

		// Add plugin action links.
		add_filter( 'plugin_action_links_' . TURBO_GUARD_PLUGIN_BASENAME, array( $this, 'add_action_links' ) );
	}

	/**
	 * Load plugin text domain for translations.
	 *
	 * Note: Since WordPress 4.6, load_plugin_textdomain() is no longer needed
	 * for plugins hosted on WordPress.org. WordPress auto-loads translations.
	 * This method is intentionally empty — kept for backward compatibility hook.
	 *
	 * @since 1.0.0
	 */
	public function load_textdomain() {
		// WordPress.org auto-loads translations since WP 4.6.
		// No action needed here.
	}

	/**
	 * Initialize plugin components.
	 *
	 * @since 1.0.0
	 */
	public function init_components() {
		// Initialize firewall (must run early).
		Turbo_Guard_Firewall::get_instance();

		// Initialize login security + 2FA.
		Turbo_Guard_Login_Security::get_instance();
		Turbo_Guard_2FA::get_instance();

		// Initialize site hardening.
		Turbo_Guard_Hardening::get_instance();

		// Initialize live traffic (registers shutdown hook).
		Turbo_Guard_Live_Traffic::get_instance();

		// Initialize geo-fence (runs before admin check so it protects wp-admin).
		Turbo_Guard_Geo_Fence::get_instance();

		// Initialize file integrity checker + file watcher.
		Turbo_Guard_Integrity::get_instance();

		// Initialize bot protection.
		Turbo_Guard_Bot_Protection::get_instance();

		// Initialize admin interface.
		if ( is_admin() ) {
			Turbo_Guard_Admin::get_instance();
			// Remote notification system (fetch + render dismissible banners).
			Turbo_Guard_Notices::get_instance();
			// Activity tracker singleton — hooks into admin page renders.
			Turbo_Guard_Activity::get_instance();
		}

		// Hook scheduled vulnerability scan.
		add_action( 'turbo_guard_scheduled_scan', array( $this, 'run_scheduled_scan' ) );

		// Hook AI analysis (triggered after each scan completes).
		add_action( 'turbo_guard_ai_analyse', array( $this, 'run_ai_analysis' ) );
	}

	/**
	 * Run AI analysis for a completed scan.
	 *
	 * @since 1.2.0
	 * @param int $scan_id Completed scan ID.
	 */
	public function run_ai_analysis( $scan_id ) {
		$use_openai = ! empty( get_option( 'turbo_guard_openai_api_key', '' ) );
		Turbo_Guard_AI_Advisor::analyse_scan( absint( $scan_id ), $use_openai );
	}

	/**
	 * Run the scheduled malware + vulnerability scan.
	 *
	 * The malware scan is local and always runs. The vulnerability scan
	 * contacts the WPScan API with installed plugin/theme versions, so it
	 * only runs when the site owner explicitly opted in via the
	 * `enable_scheduled_vuln_scan` setting (default OFF).
	 *
	 * @since 1.1.0
	 */
	public function run_scheduled_scan() {
		$scanner = new Turbo_Guard_Scanner();
		$scan_id = $scanner->start_scan();
		$scanner->scan_chunk( $scan_id, 0, 500 ); // Large chunk for background cron.

		// Vulnerability scan is opt-in: only contact WPScan API when enabled.
		if ( 'yes' === get_option( 'turbo_guard_enable_scheduled_vuln_scan', 'no' ) ) {
			Turbo_Guard_Vuln_Scanner::run_scan();
		}
	}

	/**
	 * Add plugin action links on plugins page.
	 *
	 * @since 1.0.0
	 * @param array $links Existing plugin action links.
	 * @return array Modified plugin action links.
	 */
	public function add_action_links( $links ) {
		$settings_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'admin.php?page=turbo-guard' ) ),
			esc_html__( 'Dashboard', 'turbo-guard' )
		);

		array_unshift( $links, $settings_link );

		return $links;
	}
}
