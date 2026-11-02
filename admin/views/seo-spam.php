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

// Prefixed variables: satisfies WordPress.NamingConventions.PrefixAllGlobals.
$turbo_guard_seo_results = Turbo_Guard_SEO_Spam_Detector::get_cached_results();
if ( $turbo_guard_seo_results ) {
	// Normalise against older cached results that predate the core-file scan.
	$turbo_guard_seo_results = wp_parse_args(
		$turbo_guard_seo_results,
		array(
			'spam_core_files' => array(),
		)
	);
}
$turbo_guard_seo_total   = $turbo_guard_seo_results ? (int) $turbo_guard_seo_results['total'] : 0;
$turbo_guard_domain      = wp_parse_url( home_url(), PHP_URL_HOST );
$turbo_guard_is_pro      = turbo_guard_is_pro();
	$turbo_guard_free_limit  = 0;
	if ( $turbo_guard_seo_results ) {
		$turbo_guard_free_limit = Turbo_Guard_SEO_Spam_Detector::free_deletable_count(
			empty( $turbo_guard_seo_results['spam_posts'] ) ? 0 : count( $turbo_guard_seo_results['spam_posts'] )
		);
	}
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
					<li><?php esc_html_e( 'Spam PHP files in uploads, plugins, themes and mu-plugins', 'turbo-guard' ); ?></li>
					<li><?php esc_html_e( 'Doorway-generator backdoors injected into WordPress core files', 'turbo-guard' ); ?></li>
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
				<p><?php esc_html_e( 'Scans your database, files, WordPress core, and .htaccess for Japanese/Chinese spam content. Instant — no external connection needed.', 'turbo-guard' ); ?></p>
			</div>
			<button id="turbo-guard-run-seo-scan" class="button button-primary button-large">
				<span class="dashicons dashicons-search"></span>
				<?php esc_html_e( 'Scan for SEO Spam', 'turbo-guard' ); ?>
			</button>
		</div>
		<div id="turbo-guard-seo-scanning" style="display:none;margin-top:14px;padding-top:14px;border-top:1px solid #f3f4f6;">
			<span class="spinner is-active" style="float:none;vertical-align:middle;margin-right:6px;"></span>
			<strong><?php esc_html_e( 'Scanning database, files, core, and .htaccess...', 'turbo-guard' ); ?></strong>
		</div>
		<div id="turbo-guard-seo-notice" class="turbo-guard-notice" style="display:none;margin-top:12px;"></div>
	</div>

	<?php if ( $turbo_guard_seo_results ) : ?>

		<!-- Summary stats -->
		<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px;">
			<?php
			$turbo_guard_seo_cards = array(
				array( 'label' => __( 'Total Found', 'turbo-guard' ),      'value' => $turbo_guard_seo_total,                                                      'sub' => __( 'spam indicators', 'turbo-guard' ) ),
				array( 'label' => __( 'Spam Posts', 'turbo-guard' ),       'value' => count( $turbo_guard_seo_results['spam_posts'] ),                          'sub' => __( 'in database', 'turbo-guard' ) ),
				array( 'label' => __( 'Spam Files', 'turbo-guard' ),       'value' => count( $turbo_guard_seo_results['spam_files'] ),                          'sub' => __( 'on disk', 'turbo-guard' ) ),
				array( 'label' => __( 'Core Files', 'turbo-guard' ),       'value' => count( $turbo_guard_seo_results['spam_core_files'] ),                    'sub' => __( 'in wp-admin/includes', 'turbo-guard' ) ),
				array( 'label' => __( 'Options', 'turbo-guard' ),           'value' => count( $turbo_guard_seo_results['spam_options'] ),                        'sub' => __( 'contaminated', 'turbo-guard' ) ),
				array( 'label' => __( '.htaccess Hacks', 'turbo-guard' ),  'value' => count( $turbo_guard_seo_results['htaccess_hacks'] ),                      'sub' => __( 'redirect rules', 'turbo-guard' ) ),
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
						<?php esc_html_e( 'No spam posts, files, options or backdoors were found on the server.', 'turbo-guard' ); ?>
					</p>
					<p style="color:#92400e;margin-top:6px;font-size:12px;">
						<?php esc_html_e( 'Note: cloaked doorway spam can be indexed in Google with no trace left on your server (it is fetched from a remote server only when Googlebot visits). If Google shows Japanese/Chinese results for your domain, connect Google Search Console in GSC Cleanup to find the exact URLs.', 'turbo-guard' ); ?>
					</p>
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
		<?php
		$turbo_guard_all_spam_ids  = array_column( $turbo_guard_seo_results['spam_posts'], 'id' );
		$turbo_guard_spam_total    = count( $turbo_guard_all_spam_ids );
		$turbo_guard_deletable_ids = $turbo_guard_is_pro ? $turbo_guard_all_spam_ids : array_slice( $turbo_guard_all_spam_ids, 0, $turbo_guard_free_limit );
		?>
		<div class="turbo-guard-card">
			<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:10px;">
				<h2 style="margin:0;color:#dc2626;">
					<span class="dashicons dashicons-warning" style="vertical-align:middle;margin-right:6px;"></span>
					<?php
					printf(
						/* translators: %d: number of spam posts found */
						esc_html__( '%d Spam Posts/Pages Found in Database', 'turbo-guard' ),
						absint( $turbo_guard_spam_total )
					);
					?>
				</h2>
				<button id="turbo-guard-delete-all-spam-posts" class="button"
					style="background:#dc2626;border-color:#b91c1c;color:#fff;"
					data-ids="<?php echo esc_attr( implode( ',', $turbo_guard_deletable_ids ) ); ?>">
					<span class="dashicons dashicons-trash" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span>
					<?php
					if ( $turbo_guard_is_pro ) {
						/* translators: %d: number of spam posts to remove */
						printf( esc_html__( 'Remove All %d Spam Posts', 'turbo-guard' ), absint( $turbo_guard_spam_total ) );
					} elseif ( $turbo_guard_spam_total > $turbo_guard_free_limit ) {
						/* translators: %d: free cleanup limit */
						printf( esc_html__( 'Move First %d to Trash (Free)', 'turbo-guard' ), absint( $turbo_guard_free_limit ) );
					} else {
						/* translators: %d: number of spam posts to remove */
						printf( esc_html__( 'Move All %d to Trash (Free)', 'turbo-guard' ), absint( $turbo_guard_spam_total ) );
					}
					?>
				</button>
			</div>
			<p style="font-size:13px;color:#6b7280;margin-bottom:14px;">
				<?php esc_html_e( 'These posts contain Japanese or Chinese spam content. Move them to Trash here (recoverable), then use GSC Cleanup to remove them from Google index.', 'turbo-guard' ); ?>
				<?php if ( ! $turbo_guard_is_pro && $turbo_guard_spam_total > $turbo_guard_free_limit ) : ?>
					<?php
					printf(
						wp_kses(
							/* translators: %1$d: free cleanup limit, %2$s: pro URL, %3$d: total spam posts */
							__( 'The free version can move up to %1$d spam posts to Trash. <a href="%2$s" target="_blank" rel="noopener noreferrer">Upgrade to Turbo Guard Pro</a> to remove all %3$d.', 'turbo-guard' ),
							array( 'a' => array( 'href' => array(), 'target' => array(), 'rel' => array() ) )
						),
						absint( $turbo_guard_free_limit ),
						esc_url( turbo_guard_pro_url() ),
						absint( $turbo_guard_spam_total )
					);
					?>
				<?php endif; ?>
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
					<?php foreach ( $turbo_guard_seo_results['spam_posts'] as $turbo_guard_post_index => $turbo_guard_spam_post ) : ?>
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
							<?php if ( $turbo_guard_is_pro || $turbo_guard_post_index < $turbo_guard_free_limit ) : ?>
							<button class="button button-small turbo-guard-delete-spam-post"
								style="color:#dc2626;border-color:#fca5a5;"
								data-id="<?php echo absint( $turbo_guard_spam_post['id'] ); ?>"
								data-nonce="<?php echo esc_attr( wp_create_nonce( 'turbo_guard_admin' ) ); ?>">
								<?php esc_html_e( 'Remove', 'turbo-guard' ); ?>
							</button>
							<?php else : ?>
							<button class="button button-small" disabled
								style="opacity:.55;cursor:not-allowed;"
								title="<?php esc_attr_e( 'Upgrade to Turbo Guard Pro to remove all spam posts', 'turbo-guard' ); ?>">
								<span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span>
								<?php esc_html_e( 'Delete', 'turbo-guard' ); ?>
							</button>
							<a href="<?php echo esc_url( turbo_guard_pro_url() ); ?>" target="_blank" rel="noopener noreferrer" class="button button-small button-primary" style="margin-left:4px;">
								<?php esc_html_e( 'Upgrade', 'turbo-guard' ); ?>
							</a>
							<?php endif; ?>
							<?php if ( $turbo_guard_spam_post['edit_url'] ) : ?>
							<a href="<?php echo esc_url( $turbo_guard_spam_post['edit_url'] ); ?>" class="button button-small" style="margin-left:4px;">
								<?php esc_html_e( 'Edit', 'turbo-guard' ); ?>
							</a>
							<?php endif; ?>
							<button class="button button-small turbo-guard-ignore-seo-spam" type="button"
								style="margin-left:4px;"
								data-bucket="posts"
								data-key="<?php echo absint( $turbo_guard_spam_post['id'] ); ?>">
								<?php esc_html_e( 'Ignore', 'turbo-guard' ); ?>
							</button>
						</td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php endif; ?>

		<!-- Contaminated Options -->
		<?php if ( ! empty( $turbo_guard_seo_results['spam_options'] ) ) : ?>
		<div class="turbo-guard-card" style="border-left:4px solid #dc2626;">
			<h2 style="color:#dc2626;">
				<span class="dashicons dashicons-admin-settings" style="vertical-align:middle;margin-right:6px;"></span>
				<?php
				printf(
					/* translators: %d: number of contaminated options */
					esc_html__( '%d Contaminated WordPress Option(s)', 'turbo-guard' ),
					count( $turbo_guard_seo_results['spam_options'] )
				);
				?>
			</h2>
			<p style="font-size:13px;color:#6b7280;margin-bottom:14px;">
				<?php esc_html_e( 'These WordPress settings contain spam text. Review and correct them under Settings, or contact your host if you are unsure.', 'turbo-guard' ); ?>
			</p>
			<table class="widefat">
				<thead>
					<tr>
						<th style="width:180px;"><?php esc_html_e( 'Setting', 'turbo-guard' ); ?></th>
						<th style="width:110px;"><?php esc_html_e( 'Option', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Current Value', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $turbo_guard_seo_results['spam_options'] as $turbo_guard_spam_option ) : ?>
					<tr style="background:#fff5f5;">
						<td><strong style="font-size:13px;"><?php echo esc_html( $turbo_guard_spam_option['label'] ); ?></strong></td>
						<td style="font-family:monospace;font-size:12px;"><?php echo esc_html( $turbo_guard_spam_option['option'] ); ?></td>
						<td><code style="font-size:11px;word-break:break-all;"><?php echo esc_html( $turbo_guard_spam_option['value'] ); ?></code></td>
						<td style="font-size:12px;color:#dc2626;"><?php echo esc_html( implode( ', ', $turbo_guard_spam_option['reasons'] ) ); ?></td>
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

		<!-- Infected Core Files -->
		<?php if ( ! empty( $turbo_guard_seo_results['spam_core_files'] ) ) : ?>
		<?php
		$turbo_guard_core_total  = count( $turbo_guard_seo_results['spam_core_files'] );
		$turbo_guard_core_free   = $turbo_guard_is_pro
			? $turbo_guard_core_total
			: min( $turbo_guard_core_total, Turbo_Guard_SEO_Spam_Detector::free_core_deletions_remaining() );
		$turbo_guard_core_paths  = array_column( $turbo_guard_seo_results['spam_core_files'], 'path' );
		$turbo_guard_core_delete = $turbo_guard_is_pro
			? $turbo_guard_core_paths
			: array_slice( $turbo_guard_core_paths, 0, $turbo_guard_core_free );
		?>
		<div class="turbo-guard-card" style="border-left:4px solid #7f1d1d;">
			<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:10px;">
				<h2 style="margin:0;color:#7f1d1d;">
					<span class="dashicons dashicons-warning" style="vertical-align:middle;margin-right:6px;"></span>
					<?php
					printf(
						/* translators: %d: number of infected core files */
						esc_html__( '%d Infected WordPress Core File(s)', 'turbo-guard' ),
						absint( $turbo_guard_core_total )
					);
					?>
				</h2>
				<?php if ( ! empty( $turbo_guard_core_delete ) ) : ?>
				<button id="turbo-guard-delete-all-core-files" class="button"
					style="background:#dc2626;border-color:#b91c1c;color:#fff;"
					data-paths="<?php echo esc_attr( wp_json_encode( $turbo_guard_core_delete ) ); ?>">
					<span class="dashicons dashicons-trash" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span>
					<?php
					if ( $turbo_guard_is_pro ) {
						/* translators: %d: number of infected core files */
						printf( esc_html__( 'Remove All %d Infected Files', 'turbo-guard' ), absint( $turbo_guard_core_total ) );
					} elseif ( $turbo_guard_core_total > $turbo_guard_core_free ) {
						/* translators: %d: free cleanup limit */
						printf( esc_html__( 'Remove First %d (Free)', 'turbo-guard' ), absint( $turbo_guard_core_free ) );
					} else {
						/* translators: %d: number of infected core files */
						printf( esc_html__( 'Remove All %d (Free)', 'turbo-guard' ), absint( $turbo_guard_core_total ) );
					}
					?>
				</button>
				<?php endif; ?>
			</div>
			<p style="font-size:13px;color:#6b7280;margin-bottom:14px;">
				<?php esc_html_e( 'A backdoor was injected into a WordPress core file. Restoring the file from a clean WordPress copy is safest — but you can also delete it here (a backup ZIP is created automatically) or ignore it if it is a false positive.', 'turbo-guard' ); ?>
				<?php if ( ! $turbo_guard_is_pro && $turbo_guard_core_total > $turbo_guard_core_free ) : ?>
					<?php
					printf(
						wp_kses(
							/* translators: 1: free cleanup limit, 2: pro URL, 3: total infected core files */
							__( 'The free version can delete up to %1$d infected core file(s). <a href="%2$s" target="_blank" rel="noopener noreferrer">Upgrade to Turbo Guard Pro</a> to remove all %3$d.', 'turbo-guard' ),
							array( 'a' => array( 'href' => array(), 'target' => array(), 'rel' => array() ) )
						),
						absint( Turbo_Guard_SEO_Spam_Detector::free_core_deletions_remaining() ),
						esc_url( turbo_guard_pro_url() ),
						absint( $turbo_guard_core_total )
					);
					?>
				<?php endif; ?>
			</p>
			<table class="widefat">
				<thead>
					<tr>
						<th><?php esc_html_e( 'File Path', 'turbo-guard' ); ?></th>
						<th style="width:70px;"><?php esc_html_e( 'Size', 'turbo-guard' ); ?></th>
						<th style="width:130px;"><?php esc_html_e( 'Modified', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Why Suspicious', 'turbo-guard' ); ?></th>
						<th style="width:260px;"><?php esc_html_e( 'Actions', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $turbo_guard_seo_results['spam_core_files'] as $turbo_guard_spam_core_file ) : ?>
					<tr style="background:#fef2f2;">
						<td><code style="font-size:11px;"><?php echo esc_html( $turbo_guard_spam_core_file['path'] ); ?></code></td>
						<td style="font-size:12px;color:#9ca3af;"><?php echo esc_html( $turbo_guard_spam_core_file['size'] ); ?></td>
						<td style="font-size:12px;color:#9ca3af;"><?php echo esc_html( $turbo_guard_spam_core_file['modified'] ); ?></td>
						<td style="font-size:12px;color:#dc2626;"><?php echo esc_html( implode( ', ', $turbo_guard_spam_core_file['reasons'] ) ); ?></td>
						<td>
							<button class="button button-small turbo-guard-view-core-file" type="button"
								data-path="<?php echo esc_attr( $turbo_guard_spam_core_file['path'] ); ?>">
								<?php esc_html_e( 'View', 'turbo-guard' ); ?>
							</button>
							<?php if ( $turbo_guard_is_pro || in_array( $turbo_guard_spam_core_file['path'], $turbo_guard_core_delete, true ) ) : ?>
							<button class="button button-small turbo-guard-delete-core-file" type="button"
								style="margin-left:4px;color:#dc2626;border-color:#fca5a5;"
								data-path="<?php echo esc_attr( $turbo_guard_spam_core_file['path'] ); ?>">
								<?php esc_html_e( 'Delete', 'turbo-guard' ); ?>
							</button>
							<?php else : ?>
							<button class="button button-small" disabled
								style="margin-left:4px;opacity:.55;cursor:not-allowed;"
								title="<?php esc_attr_e( 'Upgrade to Turbo Guard Pro to delete all infected core files', 'turbo-guard' ); ?>">
								<span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span>
								<?php esc_html_e( 'Delete', 'turbo-guard' ); ?>
							</button>
							<a href="<?php echo esc_url( turbo_guard_pro_url() ); ?>" target="_blank" rel="noopener noreferrer" class="button button-small button-primary" style="margin-left:4px;">
								<?php esc_html_e( 'Upgrade', 'turbo-guard' ); ?>
							</a>
							<?php endif; ?>
							<button class="button button-small turbo-guard-ignore-seo-spam" type="button"
								style="margin-left:4px;"
								data-bucket="core_files"
								data-key="<?php echo esc_attr( $turbo_guard_spam_core_file['path'] ); ?>">
								<?php esc_html_e( 'Ignore', 'turbo-guard' ); ?>
							</button>
							<button class="button button-small turbo-guard-fix-core-file" type="button"
								style="margin-left:4px;color:#047857;border-color:#6ee7b7;"
								data-path="<?php echo esc_attr( $turbo_guard_spam_core_file['path'] ); ?>">
								<?php esc_html_e( 'Fix', 'turbo-guard' ); ?>
							</button>
						</td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>

		<!-- Core file viewer -->
		<div id="turbo-guard-core-view-modal" style="display:none;position:fixed;inset:0;z-index:100000;background:rgba(0,0,0,.55);padding:40px 20px;">
			<div style="max-width:900px;margin:0 auto;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.35);">
				<div style="display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:#111827;color:#fff;">
					<strong id="turbo-guard-core-view-title" style="font-family:monospace;font-size:12px;word-break:break-all;"></strong>
					<button type="button" class="turbo-guard-core-view-close" style="background:none;border:0;color:#fff;cursor:pointer;font-size:20px;line-height:1;">&times;</button>
				</div>
				<pre id="turbo-guard-core-view-code" style="margin:0;padding:16px;max-height:60vh;overflow:auto;background:#0b1220;color:#d1fae5;font-size:12px;line-height:1.5;"></pre>
			</div>
		</div>
		<?php endif; ?>

		<!-- Spam Files -->
		<?php if ( ! empty( $turbo_guard_seo_results['spam_files'] ) ) : ?>
		<?php
		$turbo_guard_spam_file_total    = count( $turbo_guard_seo_results['spam_files'] );
		$turbo_guard_all_spam_paths     = array_column( $turbo_guard_seo_results['spam_files'], 'path' );
		$turbo_guard_seo_file_free      = $turbo_guard_is_pro
			? $turbo_guard_spam_file_total
			: min( $turbo_guard_spam_file_total, Turbo_Guard_SEO_Spam_Detector::free_file_deletions_remaining() );
		$turbo_guard_deletable_paths    = $turbo_guard_is_pro
			? $turbo_guard_all_spam_paths
			: array_slice( $turbo_guard_all_spam_paths, 0, $turbo_guard_seo_file_free );
		?>
		<div class="turbo-guard-card">
			<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:10px;">
				<h2 style="margin:0;color:#dc2626;">
					<?php
					printf(
						/* translators: %d: number of spam files found on disk */
						esc_html__( '%d Spam Files Found on Disk', 'turbo-guard' ),
						absint( $turbo_guard_spam_file_total )
					);
					?>
				</h2>
				<?php if ( ! empty( $turbo_guard_deletable_paths ) ) : ?>
				<button id="turbo-guard-delete-all-spam-files" class="button"
					style="background:#dc2626;border-color:#b91c1c;color:#fff;"
					data-paths="<?php echo esc_attr( wp_json_encode( $turbo_guard_deletable_paths ) ); ?>">
					<span class="dashicons dashicons-trash" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span>
					<?php
					if ( $turbo_guard_is_pro ) {
						/* translators: %d: number of spam files to remove */
						printf( esc_html__( 'Remove All %d Spam Files', 'turbo-guard' ), absint( $turbo_guard_spam_file_total ) );
					} elseif ( $turbo_guard_spam_file_total > $turbo_guard_seo_file_free ) {
						/* translators: %d: free cleanup limit */
						printf( esc_html__( 'Remove First %d (Free)', 'turbo-guard' ), absint( $turbo_guard_seo_file_free ) );
					} else {
						/* translators: %d: number of spam files to remove */
						printf( esc_html__( 'Remove All %d (Free)', 'turbo-guard' ), absint( $turbo_guard_spam_file_total ) );
					}
					?>
				</button>
				<?php endif; ?>
			</div>
			<p style="font-size:13px;color:#6b7280;margin-bottom:14px;">
				<?php esc_html_e( 'These files contain spam brand keywords, Japanese/Chinese text, or injected code. Delete them here — a backup ZIP is created automatically before deletion.', 'turbo-guard' ); ?>
				<?php if ( ! $turbo_guard_is_pro && $turbo_guard_spam_file_total > $turbo_guard_seo_file_free ) : ?>
					<?php
					printf(
						wp_kses(
							/* translators: 1: free cleanup limit, 2: pro URL, 3: total spam files */
							__( 'The free version can delete up to %1$d spam file(s). <a href="%2$s" target="_blank" rel="noopener noreferrer">Upgrade to Turbo Guard Pro</a> to remove all %3$d.', 'turbo-guard' ),
							array( 'a' => array( 'href' => array(), 'target' => array(), 'rel' => array() ) )
						),
						absint( Turbo_Guard_SEO_Spam_Detector::free_file_deletions_remaining() ),
						esc_url( turbo_guard_pro_url() ),
						absint( $turbo_guard_spam_file_total )
					);
					?>
				<?php endif; ?>
			</p>
			<table class="widefat">
				<thead>
					<tr>
						<th><?php esc_html_e( 'File Path', 'turbo-guard' ); ?></th>
						<th style="width:70px;"><?php esc_html_e( 'Size', 'turbo-guard' ); ?></th>
						<th style="width:130px;"><?php esc_html_e( 'Modified', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Why Suspicious', 'turbo-guard' ); ?></th>
						<th style="width:160px;"><?php esc_html_e( 'Actions', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $turbo_guard_seo_results['spam_files'] as $turbo_guard_spam_file_index => $turbo_guard_spam_file ) : ?>
					<tr style="background:#fff5f5;">
						<td><code style="font-size:11px;"><?php echo esc_html( $turbo_guard_spam_file['path'] ); ?></code></td>
						<td style="font-size:12px;color:#9ca3af;"><?php echo esc_html( $turbo_guard_spam_file['size'] ); ?></td>
						<td style="font-size:12px;color:#9ca3af;"><?php echo esc_html( $turbo_guard_spam_file['modified'] ); ?></td>
						<td style="font-size:12px;color:#dc2626;"><?php echo esc_html( implode( ', ', $turbo_guard_spam_file['reasons'] ) ); ?></td>
						<td>
							<?php if ( $turbo_guard_is_pro || $turbo_guard_spam_file_index < $turbo_guard_seo_file_free ) : ?>
							<button class="button button-small turbo-guard-delete-spam-file" type="button"
								style="color:#dc2626;border-color:#fca5a5;"
								data-path="<?php echo esc_attr( $turbo_guard_spam_file['path'] ); ?>">
								<?php esc_html_e( 'Delete', 'turbo-guard' ); ?>
							</button>
							<?php else : ?>
							<button class="button button-small" disabled
								style="opacity:.55;cursor:not-allowed;"
								title="<?php esc_attr_e( 'Upgrade to Turbo Guard Pro to delete all spam files', 'turbo-guard' ); ?>">
								<span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span>
								<?php esc_html_e( 'Delete', 'turbo-guard' ); ?>
							</button>
							<a href="<?php echo esc_url( turbo_guard_pro_url() ); ?>" target="_blank" rel="noopener noreferrer" class="button button-small button-primary" style="margin-left:4px;">
								<?php esc_html_e( 'Upgrade', 'turbo-guard' ); ?>
							</a>
							<?php endif; ?>
							<button class="button button-small turbo-guard-ignore-seo-spam" type="button"
								style="margin-left:4px;"
								data-bucket="files"
								data-key="<?php echo esc_attr( $turbo_guard_spam_file['path'] ); ?>">
								<?php esc_html_e( 'Ignore', 'turbo-guard' ); ?>
							</button>
						</td>
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
