<?php
/**
 * Scanner Page Template.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Local variables — prefixed to satisfy PHPCS global-variable sniff in included view files.
$turbo_guard_counts = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0 );
foreach ( $turbo_guard_results as $turbo_guard_r ) {
	if ( isset( $turbo_guard_counts[ $turbo_guard_r->severity ] ) ) {
		++$turbo_guard_counts[ $turbo_guard_r->severity ];
	}
}

$turbo_guard_total_threats  = count( $turbo_guard_results );
$turbo_guard_critical_count = $turbo_guard_counts['critical'];
$turbo_guard_site_is_hacked = $turbo_guard_critical_count > 0;
?>

<div class="wrap turbo-guard-scanner">

	<!-- Page Header Banner -->
	<div class="turbo-guard-page-header">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-search"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'Malware Scanner', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Scan for backdoors, web shells, SEO spam &amp; injected code', 'turbo-guard' ); ?></p>
			</div>
		</div>
		<?php if ( $turbo_guard_latest_scan ) : ?>
			<span class="turbo-guard-header-badge">
				<?php
				printf(
					/* translators: %s: human-readable time difference */
					esc_html__( 'Last scan: %s ago', 'turbo-guard' ),
					esc_html( human_time_diff( strtotime( $turbo_guard_latest_scan->completed_at ), current_time( 'timestamp' ) ) )
				);
				?>
			</span>
		<?php endif; ?>
	</div>

	<?php if ( $turbo_guard_site_is_hacked ) : ?>
	<!-- SITE HACKED alert -->
	<div style="background:#dc2626;border-radius:8px;padding:20px 24px;margin-bottom:18px;display:flex;align-items:flex-start;gap:16px;">
		<span class="dashicons dashicons-warning" style="font-size:36px;width:36px;height:36px;color:#fff;flex-shrink:0;margin-top:2px;"></span>
		<div style="flex:1;">
			<strong style="display:block;color:#fff;font-size:18px;margin-bottom:6px;">
				<?php esc_html_e( 'Your Site Has Been Hacked!', 'turbo-guard' ); ?>
			</strong>
			<p style="color:rgba(255,255,255,.9);font-size:13px;margin:0 0 14px;line-height:1.6;">
				<?php
				printf(
					/* translators: 1: number of critical malware files, 2: total number of threats */
					esc_html__( 'Turbo Guard found %1$d critical malware file(s) out of %2$d total threats. Select all critical files below and click "Delete Selected" — a backup is created automatically. This is 100%% free.', 'turbo-guard' ),
					absint( $turbo_guard_critical_count ),
					absint( $turbo_guard_total_threats )
				);
				?>
			</p>
			<div style="display:flex;gap:10px;flex-wrap:wrap;">
				<button id="turbo-guard-quick-delete-critical" class="button" type="button"
					style="background:#fff;border-color:#fff;color:#dc2626;font-weight:700;height:36px;line-height:34px;padding:0 18px;">
					<span class="dashicons dashicons-trash" style="font-size:14px;width:14px;height:14px;vertical-align:middle;margin-right:4px;"></span>
					<?php
					printf(
						/* translators: %d: number of critical files */
						esc_html__( 'Delete All %d Critical Files Now (Free)', 'turbo-guard' ),
						absint( $turbo_guard_critical_count )
					);
					?>
				</button>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-ai-report' ) ); ?>"
					style="background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.4);color:#fff;height:36px;line-height:34px;padding:0 16px;border-radius:4px;text-decoration:none;font-size:13px;display:inline-flex;align-items:center;">
					<?php esc_html_e( 'See AI Analysis &amp; Fix Guide', 'turbo-guard' ); ?>
				</a>
			</div>
		</div>
		<div style="text-align:center;background:rgba(255,255,255,.15);border-radius:8px;padding:12px 16px;flex-shrink:0;min-width:100px;">
			<div style="font-size:40px;font-weight:800;color:#fff;line-height:1;"><?php echo absint( $turbo_guard_critical_count ); ?></div>
			<div style="font-size:11px;color:rgba(255,255,255,.8);text-transform:uppercase;letter-spacing:.5px;"><?php esc_html_e( 'Critical', 'turbo-guard' ); ?></div>
		</div>
	</div>
	<?php elseif ( $turbo_guard_total_threats > 0 ) : ?>
	<div style="background:#fffbeb;border:1px solid #f59e0b;border-left:4px solid #f59e0b;border-radius:8px;padding:14px 18px;margin-bottom:16px;display:flex;align-items:center;gap:12px;">
		<span class="dashicons dashicons-warning" style="font-size:24px;width:24px;height:24px;color:#d97706;flex-shrink:0;"></span>
		<div>
			<strong style="color:#92400e;">
				<?php
				printf(
					/* translators: %d: number of suspicious files found */
					esc_html__( '%d suspicious file(s) found — review and clean below.', 'turbo-guard' ),
					absint( $turbo_guard_total_threats )
				);
				?>
			</strong>
			<p style="margin:2px 0 0;font-size:12px;color:#78350f;"><?php esc_html_e( 'Select files and click "Delete Selected". Backup is created automatically. This is 100% free.', 'turbo-guard' ); ?></p>
		</div>
	</div>
	<?php elseif ( $turbo_guard_latest_scan ) : ?>
	<div style="background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:14px 18px;margin-bottom:16px;display:flex;align-items:center;gap:12px;">
		<span class="dashicons dashicons-yes-alt" style="font-size:24px;width:24px;height:24px;color:#16a34a;flex-shrink:0;"></span>
		<strong style="color:#14532d;"><?php esc_html_e( 'Your site is clean — no malware found!', 'turbo-guard' ); ?></strong>
	</div>
	<?php endif; ?>

	<!-- Scan Control Card -->
	<div class="turbo-guard-card">
		<div class="turbo-guard-scan-hero">
			<div class="turbo-guard-scan-intro">
				<h2><?php esc_html_e( 'Full Site Scan', 'turbo-guard' ); ?></h2>
				<p><?php esc_html_e( 'Scans all PHP and JavaScript files for malware, backdoors, SEO spam and suspicious code. WordPress core is checked against the official file manifest to detect injected files. Database scanning included. 100% free.', 'turbo-guard' ); ?></p>
			</div>
			<button id="turbo-guard-start-scan" class="button button-primary button-large">
				<span class="dashicons dashicons-search"></span>
				<?php esc_html_e( 'Start Full Scan', 'turbo-guard' ); ?>
			</button>
		</div>
		<div id="turbo-guard-scan-progress" class="turbo-guard-progress-wrap" style="display:none;">
			<div class="turbo-guard-progress-header">
				<strong id="turbo-guard-progress-label"><?php esc_html_e( 'Initialising scan...', 'turbo-guard' ); ?></strong>
				<span id="turbo-guard-progress-count" style="font-size:12px;color:#9ca3af;">0 / 0 files</span>
			</div>
			<div class="turbo-guard-progress-bar">
				<div id="turbo-guard-progress-fill" style="width:0%;"></div>
			</div>
			<p id="turbo-guard-progress-threats" class="turbo-guard-threats-live"></p>
		</div>
	</div>

	<!-- Results Card -->
	<div class="turbo-guard-card">
		<div class="turbo-guard-results-header">
			<h2>
				<?php esc_html_e( 'Scan Results', 'turbo-guard' ); ?>
				<?php if ( $turbo_guard_latest_scan ) : ?>
					<small class="turbo-guard-scan-time">
						&mdash;
						<?php
						printf(
							/* translators: %d: number of files scanned */
							esc_html__( '%d files checked', 'turbo-guard' ),
							absint( $turbo_guard_latest_scan->scanned_files )
						);
						?>
					</small>
				<?php endif; ?>
			</h2>
			<?php if ( $turbo_guard_total_threats > 0 ) : ?>
				<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
					<?php foreach ( array( 'critical', 'high', 'medium', 'info' ) as $turbo_guard_sev ) : ?>
						<?php if ( $turbo_guard_counts[ $turbo_guard_sev ] > 0 ) : ?>
							<span class="turbo-guard-badge turbo-guard-badge-<?php echo esc_attr( $turbo_guard_sev ); ?>">
								<?php echo absint( $turbo_guard_counts[ $turbo_guard_sev ] ); ?> <?php echo esc_html( ucfirst( $turbo_guard_sev ) ); ?>
							</span>
						<?php endif; ?>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>
		</div>

		<div id="turbo-guard-action-result" class="turbo-guard-notice" style="display:none;"></div>

		<?php if ( $turbo_guard_total_threats > 0 ) : ?>
			<div class="turbo-guard-bulk-toolbar">
				<label>
					<input type="checkbox" id="turbo-guard-select-all" />
					<?php esc_html_e( 'Select All', 'turbo-guard' ); ?>
				</label>
				<button id="turbo-guard-select-critical" class="button" type="button">
					<span class="dashicons dashicons-flag" style="font-size:14px;width:14px;height:14px;vertical-align:middle;margin-right:3px;color:#dc2626;"></span>
					<?php esc_html_e( 'Critical Only', 'turbo-guard' ); ?>
				</button>
				<span style="width:1px;height:20px;background:#e5e7eb;margin:0 2px;display:inline-block;"></span>
				<button id="turbo-guard-quarantine-selected" class="button" type="button" disabled>
					<span class="dashicons dashicons-archive" style="font-size:14px;width:14px;height:14px;vertical-align:middle;margin-right:3px;"></span>
					<?php esc_html_e( 'Quarantine', 'turbo-guard' ); ?>
				</button>
				<button id="turbo-guard-delete-selected" class="button" type="button" disabled
					style="background:#dc2626;border-color:#b91c1c;color:#fff;">
					<span class="dashicons dashicons-trash" style="font-size:14px;width:14px;height:14px;vertical-align:middle;margin-right:3px;"></span>
					<?php esc_html_e( 'Delete Selected', 'turbo-guard' ); ?>
				</button>
				<span id="turbo-guard-selection-count" class="turbo-guard-count-badge" style="margin-left:4px;">
					0 <?php esc_html_e( 'selected', 'turbo-guard' ); ?>
				</span>
				<span style="margin-left:auto;font-size:12px;color:#9ca3af;">
					<?php
					printf(
						/* translators: %d: total number of threats */
						esc_html__( '%d threat(s) total', 'turbo-guard' ),
						absint( $turbo_guard_total_threats )
					);
					?>
				</span>
			</div>

			<div id="turbo-guard-results-list">
				<table class="turbo-guard-results-table">
					<thead>
						<tr>
							<th class="turbo-guard-col-check"><span class="screen-reader-text"><?php esc_html_e( 'Select', 'turbo-guard' ); ?></span></th>
							<th><?php esc_html_e( 'File Path', 'turbo-guard' ); ?></th>
							<th style="min-width:200px;"><?php esc_html_e( 'Threat Detected', 'turbo-guard' ); ?></th>
							<th style="width:100px;"><?php esc_html_e( 'Severity', 'turbo-guard' ); ?></th>
							<th style="width:70px;"><?php esc_html_e( 'Size', 'turbo-guard' ); ?></th>
							<th style="width:170px;"><?php esc_html_e( 'Actions', 'turbo-guard' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $turbo_guard_results as $turbo_guard_result ) : ?>
							<?php
							$turbo_guard_is_db   = ( strpos( $turbo_guard_result->file_path, 'database://' ) === 0 );
							$turbo_guard_relpath = $turbo_guard_is_db
								? $turbo_guard_result->file_path
								: str_replace( ABSPATH, '', $turbo_guard_result->file_path );
							$turbo_guard_detail  = $turbo_guard_result->threat_details;
							?>
							<tr class="turbo-guard-result-row turbo-guard-severity-<?php echo esc_attr( $turbo_guard_result->severity ); ?>"
								data-id="<?php echo absint( $turbo_guard_result->id ); ?>">
								<td>
									<?php if ( ! $turbo_guard_is_db ) : ?>
										<input type="checkbox" class="turbo-guard-file-check"
											value="<?php echo absint( $turbo_guard_result->id ); ?>"
											data-severity="<?php echo esc_attr( $turbo_guard_result->severity ); ?>" />
									<?php else : ?>
										<span title="<?php esc_attr_e( 'Database entry — use phpMyAdmin to fix', 'turbo-guard' ); ?>" style="color:#9ca3af;font-size:11px;">DB</span>
									<?php endif; ?>
								</td>
								<td class="turbo-guard-file-path">
									<code title="<?php echo esc_attr( $turbo_guard_result->file_path ); ?>"
										<?php if ( $turbo_guard_is_db ) echo 'style="color:#7c3aed;"'; ?>>
										<?php echo esc_html( $turbo_guard_relpath ); ?>
									</code>
								</td>
								<td>
									<strong style="font-size:12px;color:#1f2937;"><?php echo esc_html( $turbo_guard_result->threat_name ); ?></strong>
									<?php if ( $turbo_guard_detail ) : ?>
										<br><small style="color:#9ca3af;font-size:11px;line-height:1.4;display:block;margin-top:2px;">
											<?php echo esc_html( strlen( $turbo_guard_detail ) > 80 ? substr( $turbo_guard_detail, 0, 80 ) . '...' : $turbo_guard_detail ); ?>
										</small>
									<?php endif; ?>
								</td>
								<td>
									<span class="turbo-guard-badge turbo-guard-badge-<?php echo esc_attr( $turbo_guard_result->severity ); ?>">
										<?php echo esc_html( ucfirst( $turbo_guard_result->severity ) ); ?>
									</span>
								</td>
								<td style="font-size:12px;color:#9ca3af;">
									<?php echo ( ! $turbo_guard_is_db && $turbo_guard_result->file_size ) ? esc_html( size_format( $turbo_guard_result->file_size ) ) : '&mdash;'; ?>
								</td>
								<td class="turbo-guard-row-actions">
									<?php if ( ! $turbo_guard_is_db ) : ?>
										<button class="button turbo-guard-quarantine-single" type="button"
											data-id="<?php echo absint( $turbo_guard_result->id ); ?>"
											title="<?php esc_attr_e( 'Move to quarantine folder', 'turbo-guard' ); ?>">
											<?php esc_html_e( 'Quarantine', 'turbo-guard' ); ?>
										</button>
										<button class="button turbo-guard-delete-single" type="button"
											data-id="<?php echo absint( $turbo_guard_result->id ); ?>"
											title="<?php esc_attr_e( 'Permanently delete — backup created automatically', 'turbo-guard' ); ?>"
											style="color:#dc2626;border-color:#fca5a5;">
											<?php esc_html_e( 'Delete (Free)', 'turbo-guard' ); ?>
										</button>
										<button class="button turbo-guard-ignore-single" type="button"
											data-id="<?php echo absint( $turbo_guard_result->id ); ?>"
											title="<?php esc_attr_e( 'Mark as safe — exclude from all future scans (like Wordfence Ignore)', 'turbo-guard' ); ?>"
											style="color:#6b7280;border-color:#d1d5db;">
											<span class="dashicons dashicons-hidden" style="font-size:13px;width:13px;height:13px;vertical-align:middle;margin-right:3px;"></span>
											<?php esc_html_e( 'Ignore', 'turbo-guard' ); ?>
										</button>
									<?php elseif ( strpos( $turbo_guard_result->file_path, 'database://wp_posts#' ) === 0 ) : ?>
										<?php
										// Extract post ID from path like: database://wp_posts#42 (post: Title)
										preg_match( '/wp_posts#(\d+)/', $turbo_guard_result->file_path, $turbo_guard_post_match );
										$turbo_guard_post_id = ! empty( $turbo_guard_post_match[1] ) ? absint( $turbo_guard_post_match[1] ) : 0;
										?>
										<?php if ( $turbo_guard_post_id ) : ?>
											<a href="<?php echo esc_url( get_edit_post_link( $turbo_guard_post_id ) ); ?>"
												class="button" target="_blank" style="font-size:11px;"
												title="<?php esc_attr_e( 'View and edit this post in WordPress', 'turbo-guard' ); ?>">
												<?php esc_html_e( 'View Post', 'turbo-guard' ); ?>
											</a>
											<button class="button turbo-guard-delete-post" type="button"
												data-post-id="<?php echo absint( $turbo_guard_post_id ); ?>"
												data-result-id="<?php echo absint( $turbo_guard_result->id ); ?>"
												style="color:#dc2626;border-color:#fca5a5;font-size:11px;"
												title="<?php esc_attr_e( 'Permanently delete this spam post from the database', 'turbo-guard' ); ?>">
												<?php esc_html_e( 'Delete Post', 'turbo-guard' ); ?>
											</button>
										<?php else : ?>
											<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-ai-report' ) ); ?>"
												class="button" style="font-size:11px;">
												<?php esc_html_e( 'Fix Guide', 'turbo-guard' ); ?>
											</a>
										<?php endif; ?>
									<?php else : ?>
										<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-ai-report' ) ); ?>"
											class="button" style="font-size:11px;">
											<?php esc_html_e( 'Fix Guide', 'turbo-guard' ); ?>
										</a>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p class="turbo-guard-results-summary">
				<?php
				printf(
					/* translators: %d: total number of threats */
					esc_html__( 'Showing %d threat(s). ZIP backup is created automatically before any deletion. All features are 100%% free.', 'turbo-guard' ),
					absint( $turbo_guard_total_threats )
				);
				?>
			</p>

		<?php elseif ( $turbo_guard_latest_scan ) : ?>
			<div class="turbo-guard-no-threats">
				<span class="dashicons dashicons-yes-alt"></span>
				<p><?php esc_html_e( 'No malware found — your site is clean!', 'turbo-guard' ); ?></p>
				<p style="font-size:12px;margin-top:6px;color:#9ca3af;">
					<?php
					printf(
						/* translators: %d: number of files scanned */
						esc_html__( '%d files were checked.', 'turbo-guard' ),
						absint( $turbo_guard_latest_scan->scanned_files )
					);
					?>
				</p>
			</div>
		<?php else : ?>
			<div class="turbo-guard-no-scan">
				<span class="dashicons dashicons-search"></span>
				<p><?php esc_html_e( 'No scans run yet. Click "Start Full Scan" above.', 'turbo-guard' ); ?></p>
			</div>
		<?php endif; ?>
	</div>

</div>

<?php
// "Delete All Critical Files Now" shortcut handling lives in
// admin/js/turbo-guard-admin-v3.js (enqueued via admin_enqueue_scripts).
?>
