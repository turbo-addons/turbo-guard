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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Schema cleanup on uninstall; $table is built from $wpdb->prefix plus fixed table names, no user input.
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
	}

	// Delete all plugin options.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Uninstall cleanup; literal LIKE pattern scoped to the turbo_guard_ prefix.
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'turbo_guard_%'" );

	// Delete all transients.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Uninstall cleanup; literal LIKE pattern scoped to the turbo_guard_ prefix.
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_turbo_guard_%'" );
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Uninstall cleanup; literal LIKE pattern scoped to the turbo_guard_ prefix.
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_turbo_guard_%'" );
}
