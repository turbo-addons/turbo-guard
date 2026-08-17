<?php
/**
 * SEO Spam Detector Page Template.
 *
 * @package TurboGuard
 * @since   1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Clear stale cache so latest detection logic is used.
delete_transient( 'turbo_guard_seo_spam_results' );

// Prefixed variables: satisfies WordPress.NamingConventions.PrefixAllGlobals.
$turbo_guard_seo_results = Turbo_Guard_SEO_Spam_Detector::get_cached_results();
$turbo_guard_seo_total   = $turbo_guard_seo_results ? (int) $turbo_guard_seo_results['total'] : 0;
$turbo_guard_domain      = wp_parse_url( home_url(), PHP_URL_HOST );
?>

<div class="wrap turbo-guard-seo-spam">

	<div class="turbo-guard-page-header" style="background:linear-gradient(135deg,#7c2d12 0%,#c2410c 60%,#ea580c 100%);">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-admin-site-alt3"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'SEO Spam Detector', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Find Japanese/Chinese spam pages on your site — no Google setup required', 'turbo-guard' ); ?></p>
			</div>
		</div>
		<?php if ( $turbo_guard_seo_results ) : ?>
			<span class="turbo-guard-header-badge">
				<?php
				printf(
					/* translators: %s: human-readable time since last scan */
					esc_html__( 'Last scan: %s ago', 'turbo-guard' ),
					esc_html( human_time_diff( strtotime( $turbo_guard_seo_results['scanned_at'] ), current_time( 'timestamp' ) ) )
				);
				?>
			</span>
		<?php endif; ?>
	</div>

	<!-- How it works -->
	<div class="turbo-guard-card" style="border-left:4px solid #ea580c;">
		<h2 style="color:#c2410c;"><?php esc_html_e( 'How This Works (No Google Login Needed!)', 'turbo-guard' ); ?></h2>
		<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
			<div>
				<p style="font-size:13px;color:#374151;line-height:1.6;margin:0 0 8px;">
					<?php esc_html_e( 'When hackers inject Japanese/Chinese SEO spam they leave traces on your server BEFORE Google indexes them. Turbo Guard scans for these traces locally:', 'turbo-guard' ); ?>
				</p>
				<ul style="font-size:13px;color:#374151;margin:0 0 0 18px;line-height:1.8;">
					<li><?php esc_html_e( 'Posts/pages with Japanese or Chinese titles in your database', 'turbo-guard' ); ?></li>
					<li><?php esc_html_e( 'PHP files in uploads folder containing CJK text', 'turbo-guard' ); ?></li>
					<li><?php esc_html_e( '.htaccess redirect rules pointing to spam domains', 'turbo-guard' ); ?></li>
					<li><?php esc_html_e( 'Contaminated WordPress options (siteurl, blogname)', 'turbo-guard' ); ?></li>
				</ul>
			</div>
			<div style="background:#fff7ed;border-radius:8px;padding:14px 16px;">
				<strong style="font-size:13px;color:#92400e;display:block;margin-bottom:8px;">
					<?php esc_html_e( 'Already indexed in Google?', 'turbo-guard' ); ?>
				</strong>
				<p style="font-size:12px;color:#78350f;margin:0 0 10px;line-height:1.5;">
					<?php esc_html_e( 'If spam pages are already in Google, connect Google Search Console in GSC Cleanup to remove them. First — clean the source files here.', 'turbo-guard' ); ?>
				</p>
				<a href="<?php echo esc_url( 'https://www.google.com/search?q=site:' . rawurlencode( $turbo_guard_domain ) ); ?>"
					target="_blank" rel="noopener noreferrer" class="button button-small" style="margin-right:6px;">
					<?php
					printf(
						/* translators: %s: domain name */
						esc_html__( 'Check site:%s on Google', 'turbo-guard' ),
						esc_html( $turbo_guard_domain )
					);
					?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-gsc' ) ); ?>" class="button button-small">
					<?php esc_html_e( 'GSC Cleanup', 'turbo-guard' ); ?>
				</a>
			</div>
		</div>
	</div>

	<!-- Scan Control -->
	<div class="turbo-guard-card">
		<div class="turbo-guard-scan-hero">
			<div class="turbo-guard-scan-intro">
				<h2><?php esc_html_e( 'Scan for SEO Spam', 'turbo-guard' ); ?></h2>
				<p><?php esc_html_e( 'Scans your database, uploads folder, and .htaccess for Japanese/Chinese spam content. Instant — no external connection needed.', 'turbo-guard' ); ?></p>
			</div>
			<button id="turbo-guard-run-seo-scan" class="button button-primary button-large">
				<span class="dashicons dashicons-search"></span>
				<?php esc_html_e( 'Scan for SEO Spam', 'turbo-guard' ); ?>
			</button>
		</div>
		<div id="turbo-guard-seo-scanning" style="display:none;margin-top:14px;padding-top:14px;border-top:1px solid #f3f4f6;">
			<span class="spinner is-active" style="float:none;vertical-align:middle;margin-right:6px;"></span>
			<strong><?php esc_html_e( 'Scanning database, uploads, and .htaccess...', 'turbo-guard' ); ?></strong>
		</div>
		<div id="turbo-guard-seo-notice" class="turbo-guard-notice" style="display:none;margin-top:12px;"></div>
	</div>

	<?php if ( $turbo_guard_seo_results ) : ?>

		<!-- Summary stats -->
		<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;">
			<?php
			$turbo_guard_seo_cards = array(
				array( 'label' => __( 'Total Found', 'turbo-guard' ),      'value' => $turbo_guard_seo_total,                                        'sub' => __( 'spam indicators', 'turbo-guard' ) ),
				array( 'label' => __( 'Spam Posts', 'turbo-guard' ),       'value' => count( $turbo_guard_seo_results['spam_posts'] ),               'sub' => __( 'in database', 'turbo-guard' ) ),
				array( 'label' => __( 'Spam Files', 'turbo-guard' ),       'value' => count( $turbo_guard_seo_results['spam_files'] ),               'sub' => __( 'on disk', 'turbo-guard' ) ),
				array( 'label' => __( '.htaccess Hacks', 'turbo-guard' ),  'value' => count( $turbo_guard_seo_results['htaccess_hacks'] ),           'sub' => __( 'redirect rules', 'turbo-guard' ) ),
			);
			foreach ( $turbo_guard_seo_cards as $turbo_guard_seo_card ) :
				$turbo_guard_seo_card_val = (int) $turbo_guard_seo_card['value'];
			?>
			<div class="turbo-guard-card" style="padding:16px;text-align:center;border-top:3px solid <?php echo $turbo_guard_seo_card_val > 0 ? '#dc2626' : '#16a34a'; ?>;">
				<h3><?php echo esc_html( $turbo_guard_seo_card['label'] ); ?></h3>
				<div class="turbo-guard-stat-value <?php echo $turbo_guard_seo_card_val > 0 ? 'tg-red' : 'tg-green'; ?>" style="font-size:36px;"><?php echo absint( $turbo_guard_seo_card_val ); ?></div>
				<p class="turbo-guard-stat-label"><?php echo esc_html( $turbo_guard_seo_card['sub'] ); ?></p>
			</div>
			<?php endforeach; ?>
		</div>

		<?php if ( 0 === $turbo_guard_seo_total ) : ?>
			<div class="turbo-guard-card">
				<div style="text-align:center;padding:40px 20px;">
					<span class="dashicons dashicons-yes-alt" style="font-size:52px;width:52px;height:52px;color:#16a34a;display:block;margin:0 auto 12px;"></span>
					<strong style="font-size:16px;color:#14532d;"><?php esc_html_e( 'No SEO spam found on this site!', 'turbo-guard' ); ?></strong>
					<p style="color:#6b7280;margin-top:8px;font-size:13px;">
						<?php
						printf(
							/* translators: %s: Google site search URL */
							esc_html__( 'Tip: Also check Google manually: %s', 'turbo-guard' ),
							'<a href="' . esc_url( $turbo_guard_seo_results['google_link'] ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( $turbo_guard_seo_results['google_link'] ) . '</a>'
						);
						?>
					</p>
				</div>
			</div>
		<?php endif; ?>

		<!-- Spam Posts -->
		<?php if ( ! empty( $turbo_guard_seo_results['spam_posts'] ) ) : ?>
		<div class="turbo-guard-card">
			<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:10px;">
				<h2 style="margin:0;color:#dc2626;">
					<span class="dashicons dashicons-warning" style="vertical-align:middle;margin-right:6px;"></span>
					<?php
					printf(
						/* translators: %d: number of spam posts found */
						esc_html__( '%d Spam Posts/Pages Found in Database', 'turbo-guard' ),
						count( $turbo_guard_seo_results['spam_posts'] )
					);
					?>
				</h2>
				<button id="turbo-guard-delete-all-spam-posts" class="button"
					style="background:#dc2626;border-color:#b91c1c;color:#fff;"
					data-ids="<?php echo esc_attr( implode( ',', array_column( $turbo_guard_seo_results['spam_posts'], 'id' ) ) ); ?>">
					<span class="dashicons dashicons-trash" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span>
					<?php
					printf(
						/* translators: %d: number of spam posts to delete */
						esc_html__( 'Delete All %d Spam Posts (Free)', 'turbo-guard' ),
						count( $turbo_guard_seo_results['spam_posts'] )
					);
					?>
				</button>
			</div>
			<p style="font-size:13px;color:#6b7280;margin-bottom:14px;">
				<?php esc_html_e( 'These posts contain Japanese or Chinese spam content. Delete them here, then use GSC Cleanup to remove them from Google index.', 'turbo-guard' ); ?>
			</p>
			<table class="widefat turbo-guard-results-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Title', 'turbo-guard' ); ?></th>
						<th style="width:80px;"><?php esc_html_e( 'Type', 'turbo-guard' ); ?></th>
						<th style="width:80px;"><?php esc_html_e( 'Status', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'turbo-guard' ); ?></th>
						<th style="width:160px;"><?php esc_html_e( 'Actions', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $turbo_guard_seo_results['spam_posts'] as $turbo_guard_spam_post ) : ?>
					<tr>
						<td>
							<strong style="font-size:13px;"><?php echo esc_html( $turbo_guard_spam_post['title'] ? $turbo_guard_spam_post['title'] : __( '(no title)', 'turbo-guard' ) ); ?></strong>
							<?php if ( $turbo_guard_spam_post['url'] ) : ?>
								<br><a href="<?php echo esc_url( $turbo_guard_spam_post['url'] ); ?>" target="_blank" rel="noopener noreferrer" style="font-size:11px;color:#9ca3af;">
									<?php echo esc_html( $turbo_guard_spam_post['url'] ); ?>
								</a>
							<?php endif; ?>
						</td>
						<td style="font-size:12px;"><?php echo esc_html( $turbo_guard_spam_post['type'] ); ?></td>
						<td>
							<span class="turbo-guard-badge <?php echo 'publish' === $turbo_guard_spam_post['status'] ? 'turbo-guard-badge-critical' : 'turbo-guard-badge-medium'; ?>">
								<?php echo esc_html( $turbo_guard_spam_post['status'] ); ?>
							</span>
						</td>
						<td style="font-size:12px;color:#6b7280;"><?php echo esc_html( implode( ', ', $turbo_guard_spam_post['reasons'] ) ); ?></td>
						<td>
							<button class="button button-small turbo-guard-delete-spam-post"
								style="color:#dc2626;border-color:#fca5a5;"
								data-id="<?php echo absint( $turbo_guard_spam_post['id'] ); ?>"
								data-nonce="<?php echo esc_attr( wp_create_nonce( 'turbo_guard_admin' ) ); ?>">
								<?php esc_html_e( 'Delete (Free)', 'turbo-guard' ); ?>
							</button>
							<?php if ( $turbo_guard_spam_post['edit_url'] ) : ?>
							<a href="<?php echo esc_url( $turbo_guard_spam_post['edit_url'] ); ?>" class="button button-small" style="margin-left:4px;">
								<?php esc_html_e( 'Edit', 'turbo-guard' ); ?>
							</a>
							<?php endif; ?>
						</td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php endif; ?>

		<!-- .htaccess Hacks -->
		<?php if ( ! empty( $turbo_guard_seo_results['htaccess_hacks'] ) ) : ?>
		<div class="turbo-guard-card" style="border-left:4px solid #dc2626;">
			<h2 style="color:#dc2626;">
				<?php
				printf(
					/* translators: %d: number of suspicious htaccess rules */
					esc_html__( '%d Suspicious .htaccess Rules', 'turbo-guard' ),
					count( $turbo_guard_seo_results['htaccess_hacks'] )
				);
				?>
			</h2>
			<p style="font-size:13px;color:#6b7280;margin-bottom:14px;">
				<?php esc_html_e( 'These .htaccess rules look suspicious. Review carefully and remove any you did not add.', 'turbo-guard' ); ?>
			</p>
			<table class="widefat">
				<thead>
					<tr>
						<th style="width:80px;"><?php esc_html_e( 'Line', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Rule', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $turbo_guard_seo_results['htaccess_hacks'] as $turbo_guard_htaccess_hack ) : ?>
					<tr style="background:#fff5f5;">
						<td style="font-family:monospace;font-size:12px;"><?php echo absint( $turbo_guard_htaccess_hack['line'] ); ?></td>
						<td><code style="font-size:11px;word-break:break-all;"><?php echo esc_html( $turbo_guard_htaccess_hack['rule'] ); ?></code></td>
						<td style="font-size:12px;color:#dc2626;"><?php echo esc_html( $turbo_guard_htaccess_hack['reason'] ); ?></td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php endif; ?>

		<!-- Spam Files -->
		<?php if ( ! empty( $turbo_guard_seo_results['spam_files'] ) ) : ?>
		<div class="turbo-guard-card">
			<h2 style="color:#dc2626;">
				<?php
				printf(
					/* translators: %d: number of spam files found on disk */
					esc_html__( '%d Spam Files Found on Disk', 'turbo-guard' ),
					count( $turbo_guard_seo_results['spam_files'] )
				);
				?>
			</h2>
			<p style="font-size:13px;color:#6b7280;margin-bottom:14px;">
				<?php esc_html_e( 'Go to Turbo Guard Scanner to select and delete these files in bulk. A backup ZIP is created automatically.', 'turbo-guard' ); ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-scanner' ) ); ?>" class="button button-small" style="margin-left:8px;">
					<?php esc_html_e( 'Go to Scanner to Delete', 'turbo-guard' ); ?>
				</a>
			</p>
			<table class="widefat">
				<thead>
					<tr>
						<th><?php esc_html_e( 'File Path', 'turbo-guard' ); ?></th>
						<th style="width:70px;"><?php esc_html_e( 'Size', 'turbo-guard' ); ?></th>
						<th style="width:130px;"><?php esc_html_e( 'Modified', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Why Suspicious', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $turbo_guard_seo_results['spam_files'] as $turbo_guard_spam_file ) : ?>
					<tr style="background:#fff5f5;">
						<td><code style="font-size:11px;"><?php echo esc_html( $turbo_guard_spam_file['path'] ); ?></code></td>
						<td style="font-size:12px;color:#9ca3af;"><?php echo esc_html( $turbo_guard_spam_file['size'] ); ?></td>
						<td style="font-size:12px;color:#9ca3af;"><?php echo esc_html( $turbo_guard_spam_file['modified'] ); ?></td>
						<td style="font-size:12px;color:#dc2626;"><?php echo esc_html( implode( ', ', $turbo_guard_spam_file['reasons'] ) ); ?></td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php endif; ?>

		<!-- Google check -->
		<div class="turbo-guard-card">
			<h2><?php esc_html_e( 'Check What Google Has Indexed', 'turbo-guard' ); ?></h2>
			<p style="font-size:13px;color:#6b7280;line-height:1.6;">
				<?php esc_html_e( 'After cleaning files and spam posts, check if Google has already indexed any spam pages. Look for any pages with Japanese, Chinese, or spam product titles.', 'turbo-guard' ); ?>
			</p>
			<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
				<a href="<?php echo esc_url( $turbo_guard_seo_results['google_link'] ); ?>" target="_blank" rel="noopener noreferrer" class="button button-primary">
					<?php
					printf(
						/* translators: %s: domain name */
						esc_html__( 'View site:%s on Google', 'turbo-guard' ),
						esc_html( $turbo_guard_domain )
					);
					?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-gsc' ) ); ?>" class="button">
					<?php esc_html_e( 'Connect GSC to Remove from Google', 'turbo-guard' ); ?>
				</a>
			</div>
		</div>

	<?php else : ?>
		<div class="turbo-guard-card">
			<div style="text-align:center;padding:40px 20px;color:#6b7280;">
				<span class="dashicons dashicons-search" style="font-size:52px;width:52px;height:52px;display:block;margin:0 auto 12px;color:#d1d5db;"></span>
				<strong style="font-size:15px;"><?php esc_html_e( 'No scan run yet.', 'turbo-guard' ); ?></strong>
				<p style="margin-top:6px;"><?php esc_html_e( 'Click "Scan for SEO Spam" above to check your site instantly.', 'turbo-guard' ); ?></p>
			</div>
		</div>
	<?php endif; ?>

</div>

<?php
// SEO spam scan + delete handling is in admin/js/turbo-guard-admin-v3.js
// (enqueued via admin_enqueue_scripts). Scan/delete buttons carry data-*
// attributes consumed by that script; user-facing strings are localised via
// wp_localize_script (turboGuardAdmin.strings).
?>
