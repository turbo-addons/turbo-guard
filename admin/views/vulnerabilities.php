<?php
/**
 * Vulnerabilities Page Template.
 *
 * @package TurboGuard
 * @since 1.1.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$results = Turbo_Guard_Vuln_Scanner::get_cached_results();
?>

<div class="wrap turbo-guard-vulnerabilities">

	<!-- Page Header -->
	<div class="turbo-guard-page-header">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-warning"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'Vulnerability Scanner', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Check plugins, themes &amp; WordPress core for known CVEs', 'turbo-guard' ); ?></p>
			</div>
		</div>
		<?php if ( $results ) : ?>
			<span class="turbo-guard-header-badge">
				<?php
				printf(
					/* translators: %s: time ago */
					esc_html__( 'Last scan: %s ago', 'turbo-guard' ),
					esc_html( human_time_diff( strtotime( $results['scanned_at'] ), current_time( 'timestamp' ) ) )
				);
				?>
			</span>
		<?php endif; ?>
	</div>

	<!-- Scan control -->
	<div class="turbo-guard-card">
		<div class="turbo-guard-scan-hero">
			<div class="turbo-guard-scan-intro">
				<h2><?php esc_html_e( 'Vulnerability Check', 'turbo-guard' ); ?></h2>
				<p>
					<?php esc_html_e( 'Checks all installed plugins and themes against the WPScan vulnerability database. Add a free WPScan API key in Settings for more detailed results.', 'turbo-guard' ); ?>
				</p>
			</div>
			<button id="turbo-guard-run-vuln-scan" class="button button-primary button-large">
				<span class="dashicons dashicons-search"></span>
				<?php esc_html_e( 'Run Vulnerability Scan', 'turbo-guard' ); ?>
			</button>
		</div>
		<div id="turbo-guard-vuln-scanning" style="display:none;margin-top:14px;padding-top:14px;border-top:1px solid #f3f4f6;">
			<span class="spinner is-active" style="float:none;vertical-align:middle;margin-right:6px;"></span>
			<strong><?php esc_html_e( 'Scanning installed plugins and themes…', 'turbo-guard' ); ?></strong>
		</div>
		<div id="turbo-guard-vuln-notice" class="turbo-guard-notice" style="display:none;"></div>
	</div>

	<?php if ( $results ) : ?>

		<!-- Summary cards -->
		<div class="turbo-guard-stats-grid" style="grid-template-columns:repeat(3,1fr);">
			<div class="turbo-guard-card turbo-guard-stat-card <?php echo $results['total'] > 0 ? 'tg-threat' : ''; ?>" style="padding:18px 20px;">
				<h3><?php esc_html_e( 'Total Vulnerabilities', 'turbo-guard' ); ?></h3>
				<div class="turbo-guard-stat-value <?php echo $results['total'] > 0 ? 'tg-red' : 'tg-green'; ?>">
					<?php echo esc_html( $results['total'] ); ?>
				</div>
				<p class="turbo-guard-stat-label"><?php esc_html_e( 'Across plugins, themes &amp; core', 'turbo-guard' ); ?></p>
			</div>
			<div class="turbo-guard-card" style="padding:18px 20px;">
				<h3><?php esc_html_e( 'Vulnerable Plugins', 'turbo-guard' ); ?></h3>
				<div class="turbo-guard-stat-value <?php echo count( $results['plugins'] ) > 0 ? 'tg-red' : ''; ?>">
					<?php echo esc_html( count( $results['plugins'] ) ); ?>
				</div>
				<p class="turbo-guard-stat-label"><?php esc_html_e( 'Plugins with known CVEs', 'turbo-guard' ); ?></p>
			</div>
			<div class="turbo-guard-card" style="padding:18px 20px;">
				<h3><?php esc_html_e( 'Vulnerable Themes', 'turbo-guard' ); ?></h3>
				<div class="turbo-guard-stat-value <?php echo count( $results['themes'] ) > 0 ? 'tg-red' : ''; ?>">
					<?php echo esc_html( count( $results['themes'] ) ); ?>
				</div>
				<p class="turbo-guard-stat-label"><?php esc_html_e( 'Themes with known CVEs', 'turbo-guard' ); ?></p>
			</div>
		</div>

		<?php if ( ! empty( $results['wordpress'] ) ) : ?>
			<!-- WordPress core vulnerabilities -->
			<div class="turbo-guard-card" style="border-left:4px solid #dc2626;">
				<h2 style="color:#dc2626;">
					<span class="dashicons dashicons-warning" style="vertical-align:middle;margin-right:4px;"></span>
					<?php esc_html_e( 'WordPress Core Vulnerabilities', 'turbo-guard' ); ?>
				</h2>
				<p class="description"><?php esc_html_e( 'Update WordPress immediately to resolve these issues.', 'turbo-guard' ); ?></p>
				<?php turbo_guard_render_vuln_table( $results['wordpress'] ); ?>
			</div>
		<?php endif; ?>

		<?php if ( ! empty( $results['plugins'] ) ) : ?>
			<div class="turbo-guard-card">
				<h2><?php esc_html_e( 'Plugin Vulnerabilities', 'turbo-guard' ); ?></h2>
				<?php foreach ( $results['plugins'] as $plugin ) : ?>
					<div class="turbo-guard-vuln-item">
						<div class="turbo-guard-vuln-plugin-header">
							<strong><?php echo esc_html( $plugin['name'] ); ?></strong>
							<span class="description">v<?php echo esc_html( $plugin['version'] ); ?></span>
							<span class="turbo-guard-badge turbo-guard-badge-critical" style="margin-left:8px;">
								<?php
								printf(
									/* translators: %d: count */
									esc_html( _n( '%d issue', '%d issues', $plugin['count'], 'turbo-guard' ) ),
									esc_html( $plugin['count'] )
								);
								?>
							</span>
						</div>
						<?php turbo_guard_render_vuln_table( $plugin['vulnerabilities'] ); ?>
					</div>
				<?php endforeach; ?>
			</div>
		<?php endif; ?>

		<?php if ( ! empty( $results['themes'] ) ) : ?>
			<div class="turbo-guard-card">
				<h2><?php esc_html_e( 'Theme Vulnerabilities', 'turbo-guard' ); ?></h2>
				<?php foreach ( $results['themes'] as $theme ) : ?>
					<div class="turbo-guard-vuln-item">
						<div class="turbo-guard-vuln-plugin-header">
							<strong><?php echo esc_html( $theme['name'] ); ?></strong>
							<span class="description">v<?php echo esc_html( $theme['version'] ); ?></span>
							<span class="turbo-guard-badge turbo-guard-badge-high" style="margin-left:8px;">
								<?php
								printf(
									/* translators: %d: count */
									esc_html( _n( '%d issue', '%d issues', $theme['count'], 'turbo-guard' ) ),
									esc_html( $theme['count'] )
								);
								?>
							</span>
						</div>
						<?php turbo_guard_render_vuln_table( $theme['vulnerabilities'] ); ?>
					</div>
				<?php endforeach; ?>
			</div>
		<?php endif; ?>

		<?php if ( 0 === $results['total'] ) : ?>
			<div class="turbo-guard-card">
				<div class="turbo-guard-no-threats">
					<span class="dashicons dashicons-yes-alt"></span>
					<p><?php esc_html_e( 'No known vulnerabilities found — all plugins and themes are clean!', 'turbo-guard' ); ?></p>
				</div>
			</div>
		<?php endif; ?>

	<?php else : ?>

		<div class="turbo-guard-card">
			<div class="turbo-guard-no-scan">
				<span class="dashicons dashicons-shield"></span>
				<p><?php esc_html_e( 'No vulnerability scan has been run yet. Click "Run Vulnerability Scan" to start.', 'turbo-guard' ); ?></p>
			</div>
		</div>

	<?php endif; ?>

</div><!-- /.wrap -->

<?php
/**
 * Render a vulnerability table.
 *
 * @param array $vulns List of normalised vulnerability arrays.
 */
function turbo_guard_render_vuln_table( $vulns ) {
	if ( empty( $vulns ) ) {
		return;
	}
	?>
	<table class="widefat turbo-guard-results-table" style="margin-top:10px;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Vulnerability', 'turbo-guard' ); ?></th>
				<th style="width:90px;"><?php esc_html_e( 'Type', 'turbo-guard' ); ?></th>
				<th style="width:90px;"><?php esc_html_e( 'Severity', 'turbo-guard' ); ?></th>
				<th style="width:110px;"><?php esc_html_e( 'Fixed In', 'turbo-guard' ); ?></th>
				<th style="width:60px;"><?php esc_html_e( 'CVE', 'turbo-guard' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $vulns as $v ) : ?>
				<tr>
					<td>
						<strong style="font-size:12px;"><?php echo esc_html( $v['title'] ); ?></strong>
						<?php if ( $v['url'] ) : ?>
							<br><a href="<?php echo esc_url( $v['url'] ); ?>" target="_blank" rel="noopener noreferrer" style="font-size:11px;">
								<?php esc_html_e( 'Details →', 'turbo-guard' ); ?>
							</a>
						<?php endif; ?>
					</td>
					<td style="font-size:11px;"><?php echo esc_html( $v['type'] ); ?></td>
					<td>
						<span class="turbo-guard-badge turbo-guard-badge-<?php echo esc_attr( $v['severity'] ); ?>">
							<?php echo esc_html( ucfirst( $v['severity'] ) ); ?>
						</span>
					</td>
					<td style="font-size:12px;">
						<?php echo $v['fixed_in'] ? esc_html( $v['fixed_in'] ) : '<span style="color:#dc2626;">No fix</span>'; ?>
					</td>
					<td style="font-size:11px;">
						<?php
						if ( ! empty( $v['cve'] ) ) {
							foreach ( $v['cve'] as $cve ) {
								printf(
									'<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-%s" target="_blank" rel="noopener noreferrer">CVE-%s</a> ',
									esc_attr( $cve ),
									esc_html( $cve )
								);
							}
						} else {
							echo '—';
						}
						?>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
	<?php
}
// Use function directly in template for simplicity.
add_action( 'turbo_guard_render_vuln_table', 'turbo_guard_render_vuln_table' );
