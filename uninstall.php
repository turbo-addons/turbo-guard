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
$turbo_guard_remove_data = get_option( 'turbo_guard_remove_data_on_uninstall', false );

if ( $turbo_guard_remove_data ) {
	// Drop custom tables.
	$turbo_guard_tables = array(
		$wpdb->prefix . 'turbo_guard_scans',
		$wpdb->prefix . 'turbo_guard_scan_results',
		$wpdb->prefix . 'turbo_guard_firewall_log',
		$wpdb->prefix . 'turbo_guard_ip_blocklist',
		$wpdb->prefix . 'turbo_guard_events',
		$wpdb->prefix . 'turbo_guard_login_attempts',
		$wpdb->prefix . 'turbo_guard_rate_limit_log',
	);

	foreach ( $turbo_guard_tables as $turbo_guard_table ) {
		$wpdb->query( "DROP TABLE IF EXISTS {$turbo_guard_table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
	}

	// Delete all plugin options.
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'turbo_guard_%'" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	// Delete all transients.
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_turbo_guard_%'" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_turbo_guard_%'" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	// Delete plugin user meta (2FA secrets / recovery codes, dismissed notices).
	$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'turbo_guard_%'" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

	// Remove the quarantine folder and the error-log folder from uploads.
	$turbo_guard_uploads = wp_upload_dir();
	if ( ! empty( $turbo_guard_uploads['basedir'] ) ) {
		$turbo_guard_dirs = array( 'turbo-guard-quarantine', 'turbo-guard' );

		foreach ( $turbo_guard_dirs as $turbo_guard_dir_name ) {
			$turbo_guard_dir = trailingslashit( $turbo_guard_uploads['basedir'] ) . $turbo_guard_dir_name;

			if ( ! is_dir( $turbo_guard_dir ) ) {
				continue;
			}

			$turbo_guard_entries = @scandir( $turbo_guard_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( is_array( $turbo_guard_entries ) ) {
				foreach ( $turbo_guard_entries as $turbo_guard_entry ) {
					if ( '.' === $turbo_guard_entry || '..' === $turbo_guard_entry ) {
						continue;
					}
					$turbo_guard_path = $turbo_guard_dir . '/' . $turbo_guard_entry;
					if ( is_file( $turbo_guard_path ) ) {
						@unlink( $turbo_guard_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink
					}
				}
			}

			@rmdir( $turbo_guard_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
	}
}
