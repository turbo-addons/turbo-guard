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
		$this->init_security_components();
		$this->init_hooks();
	}

	/**
	 * Load required dependencies.
	 *
	 * @since 1.0.0
	 */
	private function load_dependencies() {
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-scanner.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-known-files.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-cleaner.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-firewall.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-login-security.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-settings.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-gsc.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-hardening.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-2fa.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-vuln-scanner.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-integrity.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-bot-protection.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-seo-spam-detector.php';
		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-notices.php';
		// Admin classes.
		if ( is_admin() ) {
			require_once TURBO_GUARD_PLUGIN_DIR . 'admin/class-turbo-guard-admin.php';
		}
	}

	/**
	 * Initialize the real-time security components as early as possible.
	 *
	 * The firewall, bot protection and site hardening register their own hooks on
	 * the `init` action at priority 1–2 (so they run before WordPress processes
	 * the request). For those early hooks to actually fire, the components MUST be
	 * instantiated BEFORE `init` starts — i.e. here, on `plugins_loaded` (the main
	 * class is bootstrapped from `turbo_guard_init`). Instantiating them inside
	 * `init_components()` (which itself runs on `init` at priority 10) would
	 * register their priority-1/2 hooks too late, and they would never run.
	 *
	 * @since 1.1.4
	 */
	private function init_security_components() {
		Turbo_Guard_Firewall::get_instance();
		Turbo_Guard_Bot_Protection::get_instance();
		Turbo_Guard_Hardening::get_instance();
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

		// Run DB schema/option upgrades for existing installs (idempotent).
		add_action( 'admin_init', array( $this, 'maybe_run_upgrades' ) );

		// Clear the known-good file cache whenever plugins/themes change so the
		// repository index stays fresh (prevents stale false positives/negatives).
		add_action( 'upgrader_process_complete', array( 'Turbo_Guard_Known_Files', 'clear_cache' ), 10, 0 );
		add_action( 'activated_plugin', array( 'Turbo_Guard_Known_Files', 'clear_cache' ) );
		add_action( 'deactivated_plugin', array( 'Turbo_Guard_Known_Files', 'clear_cache' ) );
		add_action( 'switch_theme', array( 'Turbo_Guard_Known_Files', 'clear_cache' ) );
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
	 * Run schema/option upgrades for existing installs.
	 *
	 * Loads the installer lazily and calls its idempotent migration routine so
	 * pre-existing installs pick up new tables (e.g. the rate-limit log) and
	 * default options without a deactivate/reactivate cycle.
	 *
	 * @since 1.1.4
	 */
	public function maybe_run_upgrades() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-installer.php';
		Turbo_Guard_Installer::maybe_upgrade();
	}

	/**
	 * Initialize plugin components.
	 *
	 * @since 1.0.0
	 */
	public function init_components() {
		// Initialize login security + 2FA.
		Turbo_Guard_Login_Security::get_instance();
		Turbo_Guard_2FA::get_instance();

		// Initialize file integrity checker + file watcher.
		Turbo_Guard_Integrity::get_instance();

		// Initialize admin interface.
		if ( is_admin() ) {
			Turbo_Guard_Admin::get_instance();
			// Local admin notice banners (no remote requests).
			Turbo_Guard_Notices::get_instance();
			// GSC must be instantiated early so its admin_init OAuth callback
			// hook is registered before the callback request is handled.
			new Turbo_Guard_GSC();
		}

		// Hook scheduled vulnerability scan.
		add_action( 'turbo_guard_scheduled_scan', array( $this, 'run_scheduled_scan' ) );

		// Allow the Pro add-on to initialize its features (live traffic, geo-fence, AI).
		do_action( 'turbo_guard_init_pro' );
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

		// Vulnerability scan is opt-in (Pro): only contact WPScan API when enabled.
		if ( 'yes' === get_option( 'turbo_guard_enable_scheduled_vuln_scan', 'no' ) && turbo_guard_is_pro() ) {
			Turbo_Guard_Vuln_Scanner::run_scan();
		}

		// SEO spam scan is local and opt-in via settings (email alerts are Pro).
		if ( 'yes' === get_option( 'turbo_guard_enable_scheduled_seo_spam_scan', 'no' ) ) {
			Turbo_Guard_SEO_Spam_Detector::run_scan();
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
