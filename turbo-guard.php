<?php
/**
 * Plugin Name: Turbo Guard – Security & Malware Scanner
 * Plugin URI: https://wp-turbo.com/turbo-guard/
 * Description: Advanced WordPress security with AI-powered malware scanning, WordPress core file manifest verification, bulk cleanup, firewall, 2FA, vulnerability scanner, file integrity checker, live traffic monitor, bot protection, geo-fence & SEO spam removal. 100% free.
 * Version: 1.1.1
 * Author: Turbo Addons
 * Author URI: https://wp-turbo.com
 * License: GPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: turbo-guard
 * Domain Path: /languages
 * Requires at least: 5.6
 * Requires PHP: 7.4
 *
 * @package TurboGuard
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Define plugin constants.
define( 'TURBO_GUARD_VERSION', '1.1.1' );
define( 'TURBO_GUARD_PLUGIN_FILE', __FILE__ );
define( 'TURBO_GUARD_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'TURBO_GUARD_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'TURBO_GUARD_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

// Free-tier cleanup quota: max files a free user can delete/quarantine per action.
define( 'TURBO_GUARD_FREE_CLEANUP_LIMIT', 3 );

/**
 * Get the free-tier cleanup limit.
 *
 * @since 2.0.0
 * @return int Max files free users can delete/quarantine per action.
 */
function turbo_guard_free_cleanup_limit() {
	return (int) apply_filters( 'turbo_guard_free_cleanup_limit', TURBO_GUARD_FREE_CLEANUP_LIMIT );
}

/**
 * URL for the Pro upgrade page.
 *
 * The free plugin is NOT registered on Freemius — it just links out to the
 * Pro sales page on wp-turbo.com.
 *
 * @since 2.0.0
 * @return string
 */
function turbo_guard_pro_url() {
	return apply_filters( 'turbo_guard_pro_url', 'https://wp-turbo.com/turbo-guard/' );
}

/**
 * Whether the Turbo Guard Pro add-on is active and licensed.
 *
 * The Pro add-on sets the `turbo_guard_is_pro` filter to true. Free returns false.
 *
 * @since 2.0.0
 * @return bool
 */
function turbo_guard_is_pro() {
	return (bool) apply_filters( 'turbo_guard_is_pro', false );
}

// Require main plugin class — wrapped so a syntax/load error doesn't crash the site.
try {
	require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard.php';
} catch ( Throwable $e ) {
	$turbo_guard_upload_dir = wp_upload_dir();
	$turbo_guard_log_dir    = $turbo_guard_upload_dir['basedir'] . '/turbo-guard';
	if ( ! is_dir( $turbo_guard_log_dir ) ) {
		wp_mkdir_p( $turbo_guard_log_dir );
	}
	$turbo_guard_log  = $turbo_guard_log_dir . '/error.log';
	$turbo_guard_line = '[' . gmdate( 'Y-m-d H:i:s' ) . '] LOAD ERROR: ' . $e->getMessage()
	        . ' in ' . $e->getFile() . ' on line ' . $e->getLine() . "\n";
	file_put_contents( $turbo_guard_log, $turbo_guard_line, FILE_APPEND | LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
	return; // Stop here — don't register hooks if core class failed to load.
}

/**
 * Initialize the plugin.
 * Wrapped in try/catch so any fatal error logs to turbo-guard-error.log
 * and never crashes the site.
 *
 * @since 1.0.0
 */
function turbo_guard_init() {
	try {
		Turbo_Guard::get_instance();
	} catch ( Throwable $e ) {
		$upload_dir = wp_upload_dir();
		$log_dir    = $upload_dir['basedir'] . '/turbo-guard';
		if ( ! is_dir( $log_dir ) ) {
			wp_mkdir_p( $log_dir );
		}
		$log  = $log_dir . '/error.log';
		$line = '[' . gmdate( 'Y-m-d H:i:s' ) . '] INIT ERROR: ' . $e->getMessage()
		        . ' in ' . $e->getFile() . ' on line ' . $e->getLine() . "\n";
		file_put_contents( $log, $line, FILE_APPEND | LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
	}
}
add_action( 'plugins_loaded', 'turbo_guard_init' );

/**
 * Activation hook.
 *
 * @since 1.0.0
 */
function turbo_guard_activate() {
	require_once TURBO_GUARD_PLUGIN_DIR . 'includes/class-turbo-guard-installer.php';
	Turbo_Guard_Installer::activate();
}
register_activation_hook( __FILE__, 'turbo_guard_activate' );

/**
 * Deactivation hook.
 *
 * @since 1.0.0
 */
function turbo_guard_deactivate() {
	// Clear scheduled scans.
	wp_clear_scheduled_hook( 'turbo_guard_scheduled_scan' );
}
register_deactivation_hook( __FILE__, 'turbo_guard_deactivate' );
