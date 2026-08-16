<?php
/**
 * File Integrity Page Template.
 *
 * @package TurboGuard
 * @since   1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Prefixed variables to satisfy WordPress.NamingConventions.PrefixAllGlobals.
$tg_ir              = $integrity_results;
$tg_baseline        = get_option( 'turbo_guard_file_baseline', array() );
$tg_baseline_count  = count( $tg_baseline );
$tg_watcher_last    = isset( $watcher_last_run ) ? $watcher_last_run : '';
$tg_baseline_at     = isset( $baseline_built_at ) ? $baseline_built_at : '';
?>

<div class="wrap turbo-guard-integrity">

	<div class="turbo-guard-page-header">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-lock"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'File Integrity & Change Detection', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Core file verification against WordPress.org checksums + real-time file watcher', 'turbo-guard' ); ?></p>
			</div>
		</div>
	</div>

	<div id="turbo-guard-integrity-notice" class="turbo-guard-notice" style="display:none;"></div>

	<!-- Status Cards -->
	<div class="turbo-guard-stats-grid" style="grid-template-columns:repeat(3,1fr);">

		<!-- Core Integrity -->
		<div class="turbo-guard-card turbo-guard-stat-card">
			<h3><?php esc_html_e( 'Core File Integrity', 'turbo-guard' ); ?></h3>
			<?php if ( $tg_ir ) : ?>
				<div class="turbo-guard-stat-value <?php echo ( $tg_ir['modified'] + $tg_ir['missing'] ) > 0 ? 'tg-red' : 'tg-green'; ?>">
					<?php echo absint( $tg_ir['modified'] + $tg_ir['missing'] ); ?>
				</div>
				<p class="turbo-guard-stat-label">
					<?php
					if ( ( $tg_ir['modified'] + $tg_ir['missing'] ) > 0 ) {
						printf(
							/* translators: 1: number of modified files, 2: number of missing files */
							esc_html__( '%1$d modified, %2$d missing', 'turbo-guard' ),
							absint( $tg_ir['modified'] ),
							absint( $tg_ir['missing'] )
						);
					} else {
						esc_html_e( 'All core files verified', 'turbo-guard' );
					}
					?>
				</p>
				<p style="font-size:11px;color:#9ca3af;margin:4px 0 8px;">
					<?php
					printf(
						/* translators: 1: WordPress version, 2: number of files checked, 3: date/time of check */
						esc_html__( 'WP %1$s — %2$d files checked — %3$s', 'turbo-guard' ),
						esc_html( $tg_ir['wp_version'] ),
						absint( $tg_ir['checked'] ),
						esc_html( $tg_ir['checked_at'] )
					);
					?>
				</p>
			<?php else : ?>
				<div class="turbo-guard-stat-value" style="font-size:20px;">—</div>
				<p class="turbo-guard-stat-label"><?php esc_html_e( 'Not run yet', 'turbo-guard' ); ?></p>
			<?php endif; ?>
			<button id="tg-run-integrity" class="button button-primary button-small">
				<?php esc_html_e( 'Checking...', 'turbo-guard' ); ?>
			</button>
		</div>

		<!-- File Watcher -->
		<div class="turbo-guard-card turbo-guard-stat-card">
			<h3><?php esc_html_e( 'File Watcher', 'turbo-guard' ); ?></h3>
			<div class="turbo-guard-stat-value tg-green">
				<span class="dashicons dashicons-visibility" style="font-size:32px;width:32px;height:32px;"></span>
			</div>
			<p class="turbo-guard-stat-label"><?php esc_html_e( 'Runs every 12 hours via WP-Cron', 'turbo-guard' ); ?></p>
			<?php if ( $tg_watcher_last ) : ?>
				<p style="font-size:11px;color:#9ca3af;margin:4px 0 8px;">
					<?php
					printf(
						/* translators: %s: date/time of last watcher run */
						esc_html__( 'Last run: %s', 'turbo-guard' ),
						esc_html( $tg_watcher_last )
					);
					?>
				</p>
			<?php endif; ?>
			<button id="tg-run-watcher" class="button button-secondary button-small">
				<?php esc_html_e( 'Run Now', 'turbo-guard' ); ?>
			</button>
		</div>

		<!-- Baseline -->
		<div class="turbo-guard-card turbo-guard-stat-card">
			<h3><?php esc_html_e( 'File Baseline', 'turbo-guard' ); ?></h3>
			<div class="turbo-guard-stat-value" style="font-size:20px;">
				<?php echo esc_html( number_format( $tg_baseline_count ) ); ?>
			</div>
			<p class="turbo-guard-stat-label"><?php esc_html_e( 'Files tracked', 'turbo-guard' ); ?></p>
			<?php if ( $tg_baseline_at ) : ?>
				<p style="font-size:11px;color:#9ca3af;margin:4px 0 8px;">
					<?php
					printf(
						/* translators: %s: date/time the baseline was built */
						esc_html__( 'Built: %s', 'turbo-guard' ),
						esc_html( $tg_baseline_at )
					);
					?>
				</p>
			<?php endif; ?>
			<button id="tg-rebuild-baseline" class="button button-secondary button-small">
				<?php esc_html_e( 'Rebuild Baseline', 'turbo-guard' ); ?>
			</button>
		</div>

	</div>

	<?php if ( $tg_ir && ! empty( $tg_ir['results'] ) ) : ?>
	<div class="turbo-guard-card">
		<h2 style="color:#dc2626;">
			<span class="dashicons dashicons-warning" style="color:#dc2626;vertical-align:middle;margin-right:6px;"></span>
			<?php
			printf(
				/* translators: %d: number of core file issues found */
				esc_html__( '%d Core File Issue(s) Found', 'turbo-guard' ),
				count( $tg_ir['results'] )
			);
			?>
		</h2>
		<p style="color:#6b7280;font-size:13px;margin-bottom:16px;">
			<?php esc_html_e( 'These WordPress core files do not match the official WordPress.org checksums. This is a strong indicator of a hack.', 'turbo-guard' ); ?>
		</p>
		<table class="widefat">
			<thead>
				<tr>
					<th><?php esc_html_e( 'File', 'turbo-guard' ); ?></th>
					<th style="width:100px;"><?php esc_html_e( 'Status', 'turbo-guard' ); ?></th>
					<th><?php esc_html_e( 'Detail', 'turbo-guard' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $tg_ir['results'] as $tg_ir_row ) : ?>
				<tr>
					<td><code><?php echo esc_html( $tg_ir_row['path'] ); ?></code></td>
					<td>
						<span class="turbo-guard-badge turbo-guard-badge-critical">
							<?php echo esc_html( ucfirst( $tg_ir_row['status'] ) ); ?>
						</span>
					</td>
					<td style="font-size:12px;color:#6b7280;"><?php echo esc_html( $tg_ir_row['detail'] ); ?></td>
				</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<?php elseif ( $tg_ir ) : ?>
	<div class="turbo-guard-card">
		<div style="text-align:center;padding:30px;color:#16a34a;">
			<span class="dashicons dashicons-yes-alt" style="font-size:48px;width:48px;height:48px;display:block;margin:0 auto 12px;"></span>
			<strong style="font-size:16px;"><?php esc_html_e( 'All core files are intact!', 'turbo-guard' ); ?></strong>
			<p style="color:#6b7280;margin-top:8px;">
				<?php
				printf(
					/* translators: %d: number of WordPress core files verified */
					esc_html__( '%d WordPress core files verified against WordPress.org checksums.', 'turbo-guard' ),
					absint( $tg_ir['checked'] )
				);
				?>
			</p>
		</div>
	</div>
	<?php endif; ?>

	<!-- How It Works -->
	<div class="turbo-guard-card">
		<h2><?php esc_html_e( 'How It Works', 'turbo-guard' ); ?></h2>
		<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
			<div>
				<h3 style="font-size:13px;color:#1f2937;">🔐 <?php esc_html_e( 'Core File Integrity Check', 'turbo-guard' ); ?></h3>
				<p style="font-size:13px;color:#6b7280;line-height:1.6;">
					<?php esc_html_e( 'Downloads the official MD5 checksums for your WordPress version from WordPress.org and compares every core file. Any file that has been modified or deleted is flagged — this catches hackers who inject code into wp-login.php, wp-settings.php, or other core files.', 'turbo-guard' ); ?>
				</p>
			</div>
			<div>
				<h3 style="font-size:13px;color:#1f2937;">👁️ <?php esc_html_e( 'File Watcher (Change Detection)', 'turbo-guard' ); ?></h3>
				<p style="font-size:13px;color:#6b7280;line-height:1.6;">
					<?php esc_html_e( 'Takes a snapshot (baseline) of all PHP/JS files in your themes, plugins, and uploads. Every 12 hours it compares the current files against the baseline using MD5 hashes. New files, modified files, and deleted plugin/theme files are all detected and logged.', 'turbo-guard' ); ?>
				</p>
			</div>
		</div>
	</div>

</div>

<?php
// Integrity check / watcher / baseline rebuild handling lives in
// admin/js/turbo-guard-admin-v3.js (enqueued via admin_enqueue_scripts).
// User-facing strings are localised via wp_localize_script (turboGuardAdmin.strings).
?>
