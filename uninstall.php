<?php
/**
 * Uninstall script for Turbo Guard.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if not called from WordPress.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Only remove data if user opts in.
$remove_data = get_option( 'turbo_guard_remove_data_on_uninstall', false );

if ( $remove_data ) {
	// Drop custom tables.
	$tables = array(
		$wpdb->prefix . 'turbo_guard_scans',
		$wpdb->prefix . 'turbo_guard_scan_results',
		$wpdb->prefix . 'turbo_guard_firewall_log',
		$wpdb->prefix . 'turbo_guard_ip_blocklist',
		$wpdb->prefix . 'turbo_guard_events',
		$wpdb->prefix . 'turbo_guard_login_attempts',
	);

	foreach ( $tables as $table ) {
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	// Delete all plugin options.
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'turbo_guard_%'" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

	// Delete all transients.
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_turbo_guard_%'" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_turbo_guard_%'" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
}
