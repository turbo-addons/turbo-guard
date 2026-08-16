<?php
/**
 * Malware Cleaner Class.
 *
 * Handles quarantine, deletion, and backup of malicious files.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles malware cleanup operations.
 *
 * @since 1.0.0
 */
class Turbo_Guard_Cleaner {

	/**
	 * Quarantine a list of files by ID.
	 *
	 * Moves files to a safe quarantine folder instead of deleting.
	 *
	 * @since 1.0.0
	 * @param array $result_ids Array of scan result IDs.
	 * @return array Results array with success/fail per file.
	 */
	public static function quarantine_files( array $result_ids ) {
		global $wpdb;

		$results        = array();
		$upload_dir     = wp_upload_dir();
		$quarantine_dir = $upload_dir['basedir'] . '/turbo-guard-quarantine';

		if ( ! file_exists( $quarantine_dir ) ) {
			wp_mkdir_p( $quarantine_dir );
		}

		foreach ( $result_ids as $result_id ) {
			$result_id = absint( $result_id );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; row lookup by ID, plugin-specific data.
			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}turbo_guard_scan_results WHERE id = %d",
					$result_id
				)
			);

			if ( ! $row || ! file_exists( $row->file_path ) ) {
				$results[] = array(
					'id'      => $result_id,
					'success' => false,
					'message' => __( 'File not found.', 'turbo-guard' ),
				);
				continue;
			}

			// Create unique quarantine filename.
			$quarantine_name = time() . '_' . $result_id . '_' . basename( $row->file_path );
			$quarantine_path = $quarantine_dir . '/' . $quarantine_name;

			// Move file to quarantine.
			$moved = rename( $row->file_path, $quarantine_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename

			if ( $moved ) {
				// Mark as quarantined in DB.
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; status update by ID, plugin-specific data.
				$wpdb->update(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array(
						'status'         => 'quarantined',
						'threat_details' => sprintf(
							/* translators: %s: quarantine file path */
							__( 'Quarantined to: %s', 'turbo-guard' ),
							$quarantine_path
						),
					),
					array( 'id' => $result_id ),
					array( '%s', '%s' ),
					array( '%d' )
				);

				Turbo_Guard_Scanner::log_event(
					'file_quarantined',
					'warning',
					sprintf(
						/* translators: %s: file path */
						__( 'File quarantined: %s', 'turbo-guard' ),
						$row->file_path
					)
				);

				$results[] = array(
					'id'      => $result_id,
					'success' => true,
					'message' => __( 'File quarantined successfully.', 'turbo-guard' ),
				);
			} else {
				$results[] = array(
					'id'      => $result_id,
					'success' => false,
					'message' => __( 'Failed to quarantine file.', 'turbo-guard' ),
				);
			}
		}

		return $results;
	}

	/**
	 * Permanently delete a list of files by scan result ID.
	 *
	 * Always creates a backup ZIP before deleting.
	 *
	 * @since 1.0.0
	 * @param array $result_ids Array of scan result IDs.
	 * @return array Results including backup path and per-file status.
	 */
	public static function delete_files( array $result_ids ) {
		global $wpdb;

		$results = array();
		$deleted = 0;
		$failed  = 0;

		// Collect file paths for backup.
		$file_paths = array();
		foreach ( $result_ids as $result_id ) {
			$result_id = absint( $result_id );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; row lookup by ID, plugin-specific data.
			$row       = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}turbo_guard_scan_results WHERE id = %d",
					$result_id
				)
			);
			if ( $row && file_exists( $row->file_path ) ) {
				$file_paths[ $result_id ] = $row->file_path;
			}
		}

		// Create ZIP backup before deletion.
		$backup_path = self::create_backup( $file_paths );

		// Delete files.
		foreach ( $result_ids as $result_id ) {
			$result_id = absint( $result_id );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; row lookup by ID, plugin-specific data.
			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}turbo_guard_scan_results WHERE id = %d",
					$result_id
				)
			);

			if ( ! $row ) {
				$results[] = array(
					'id'      => $result_id,
					'success' => false,
					'message' => __( 'Record not found.', 'turbo-guard' ),
				);
				++$failed;
				continue;
			}

			if ( ! file_exists( $row->file_path ) ) {
				// File already gone - mark as deleted.
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; status update by ID, plugin-specific data.
				$wpdb->update(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array( 'status' => 'deleted' ),
					array( 'id' => $result_id ),
					array( '%s' ),
					array( '%d' )
				);
				$results[] = array(
					'id'      => $result_id,
					'success' => true,
					'message' => __( 'File already removed.', 'turbo-guard' ),
				);
				++$deleted;
				continue;
			}

			// Attempt deletion.
			$success = wp_delete_file( $row->file_path );

			if ( $success || ! file_exists( $row->file_path ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; status update by ID, plugin-specific data.
				$wpdb->update(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array( 'status' => 'deleted' ),
					array( 'id' => $result_id ),
					array( '%s' ),
					array( '%d' )
				);

				Turbo_Guard_Scanner::log_event(
					'file_deleted',
					'warning',
					sprintf(
						/* translators: %s: file path */
						__( 'Malware file deleted: %s', 'turbo-guard' ),
						$row->file_path
					)
				);

				$results[] = array(
					'id'      => $result_id,
					'success' => true,
					'message' => __( 'File deleted.', 'turbo-guard' ),
					'file'    => basename( $row->file_path ),
				);
				++$deleted;
			} else {
				$results[] = array(
					'id'      => $result_id,
					'success' => false,
					'message' => __( 'Permission denied. Cannot delete file.', 'turbo-guard' ),
					'file'    => basename( $row->file_path ),
				);
				++$failed;
			}
		}

		return array(
			'deleted'      => $deleted,
			'failed'       => $failed,
			'backup'       => $backup_path,
			'file_results' => $results,
		);
	}

	/**
	 * Create a ZIP backup of given files.
	 *
	 * @since 1.0.0
	 * @param array $file_paths Map of ID => full path.
	 * @return string|false Backup ZIP path or false on failure.
	 */
	private static function create_backup( array $file_paths ) {
		if ( empty( $file_paths ) || ! class_exists( 'ZipArchive' ) ) {
			return false;
		}

		$upload_dir  = wp_upload_dir();
		$backup_dir  = $upload_dir['basedir'] . '/turbo-guard-quarantine';
		$backup_name = 'backup_' . gmdate( 'Ymd_His' ) . '.zip';
		$backup_path = $backup_dir . '/' . $backup_name;

		if ( ! file_exists( $backup_dir ) ) {
			wp_mkdir_p( $backup_dir );
		}

		$zip = new ZipArchive();
		if ( true !== $zip->open( $backup_path, ZipArchive::CREATE ) ) {
			return false;
		}

		foreach ( $file_paths as $file_path ) {
			if ( file_exists( $file_path ) ) {
				$zip->addFile( $file_path, ltrim( str_replace( ABSPATH, '', $file_path ), '/' ) ); // Display-only relative path inside the backup ZIP.
			}
		}

		$zip->close();

		return file_exists( $backup_path ) ? $backup_path : false;
	}

	/**
	 * Get quarantine directory contents.
	 *
	 * @since 1.0.0
	 * @return array List of quarantined file info.
	 */
	public static function get_quarantine_files() {
		$upload_dir     = wp_upload_dir();
		$quarantine_dir = $upload_dir['basedir'] . '/turbo-guard-quarantine';
		$files          = array();

		if ( ! is_dir( $quarantine_dir ) ) {
			return $files;
		}

		$dir_files = glob( $quarantine_dir . '/*.php' );
		if ( ! $dir_files ) {
			return $files;
		}

		foreach ( $dir_files as $file ) {
			$files[] = array(
				'name'     => basename( $file ),
				'path'     => $file,
				'size'     => size_format( filesize( $file ) ),
				'modified' => gmdate( 'Y-m-d H:i', filemtime( $file ) ),
			);
		}

		return $files;
	}
}
