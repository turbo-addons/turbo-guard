<?php
/**
 * AI Security Report Page Template.
 *
 * @package TurboGuard
 * @since 1.2.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$turbo_guard_latest_scan = Turbo_Guard_Scanner::get_latest_scan();
$turbo_guard_report      = $turbo_guard_latest_scan ? Turbo_Guard_AI_Advisor::get_cached_report( $turbo_guard_latest_scan->id ) : null;
$turbo_guard_trend       = Turbo_Guard_AI_Advisor::get_security_trend();
$turbo_guard_openai_key  = get_option( 'turbo_guard_openai_api_key', '' );

// If no cached report, generate one from latest scan.
if ( ! $turbo_guard_report && $turbo_guard_latest_scan ) {
	$turbo_guard_report = Turbo_Guard_AI_Advisor::analyse_scan( $turbo_guard_latest_scan->id, false );
}
?>

<div class="wrap turbo-guard-ai-report">

	<!-- Page Header -->
	<div class="turbo-guard-page-header" style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 50%,#2563eb 100%);">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon" style="background:rgba(255,255,255,.2);">
				<span class="dashicons dashicons-superhero-alt"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'AI Security Advisor', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Intelligent analysis of your security posture with plain-English guidance', 'turbo-guard' ); ?></p>
			</div>
		</div>
		<span class="turbo-guard-header-badge"><?php esc_html_e( 'Powered by Turbo Guard AI', 'turbo-guard' ); ?></span>
	</div>

	<?php if ( ! $turbo_guard_latest_scan ) : ?>
		<div class="turbo-guard-card">
			<div class="turbo-guard-no-scan">
				<span class="dashicons dashicons-superhero-alt"></span>
				<p><?php esc_html_e( 'Run your first scan to get AI security analysis.', 'turbo-guard' ); ?></p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-scanner' ) ); ?>" class="button button-primary" style="margin-top:12px;">
					<?php esc_html_e( 'Start Scan Now →', 'turbo-guard' ); ?>
				</a>
			</div>
		</div>
	<?php else : ?>

		<?php if ( $turbo_guard_report ) : ?>

			<!-- Status Banner -->
			<?php
			$turbo_guard_status_colors = array(
				'clean'    => array( 'bg' => '#f0fdf4', 'border' => '#16a34a', 'text' => '#15803d', 'icon' => 'dashicons-yes-alt' ),
				'warning'  => array( 'bg' => '#fffbeb', 'border' => '#d97706', 'text' => '#92400e', 'icon' => 'dashicons-warning' ),
				'high'     => array( 'bg' => '#fff7ed', 'border' => '#ea580c', 'text' => '#c2410c', 'icon' => 'dashicons-warning' ),
				'critical' => array( 'bg' => '#fef2f2', 'border' => '#dc2626', 'text' => '#b91c1c', 'icon' => 'dashicons-dismiss' ),
			);
			$turbo_guard_sc = $turbo_guard_status_colors[ $turbo_guard_report['overall_status'] ] ?? $turbo_guard_status_colors['warning'];
			?>
			<div style="background:<?php echo esc_attr( $turbo_guard_sc['bg'] ); ?>;border-left:5px solid <?php echo esc_attr( $turbo_guard_sc['border'] ); ?>;padding:16px 20px;border-radius:6px;margin-bottom:16px;display:flex;align-items:flex-start;gap:14px;">
				<span class="dashicons <?php echo esc_attr( $turbo_guard_sc['icon'] ); ?>" style="font-size:28px;width:28px;height:28px;color:<?php echo esc_attr( $turbo_guard_sc['border'] ); ?>;flex-shrink:0;margin-top:2px;"></span>
				<div>
					<strong style="font-size:15px;color:<?php echo esc_attr( $turbo_guard_sc['text'] ); ?>;display:block;margin-bottom:4px;">
						<?php
						$turbo_guard_labels = array(
							'clean'    => __( 'Your site is clean and well-protected.', 'turbo-guard' ),
							'warning'  => __( 'Security issues detected — action recommended.', 'turbo-guard' ),
							'high'     => __( 'High-severity threats found — address within 24 hours.', 'turbo-guard' ),
							'critical' => __( 'CRITICAL: Your site is actively compromised — act immediately.', 'turbo-guard' ),
						);
						echo esc_html( $turbo_guard_labels[ $turbo_guard_report['overall_status'] ] ?? $turbo_guard_labels['warning'] );
						?>
					</strong>
					<p style="margin:0;color:<?php echo esc_attr( $turbo_guard_sc['text'] ); ?>;font-size:13px;opacity:.85;">
						<?php echo esc_html( $turbo_guard_report['summary'] ); ?>
					</p>
				</div>
			</div>

			<!-- OpenAI Enhanced Narrative -->
			<?php if ( ! empty( $turbo_guard_report['ai_narrative'] ) ) : ?>
				<div class="turbo-guard-card" style="border-left:4px solid #7c3aed;">
					<h2 style="color:#7c3aed;">
						<span class="dashicons dashicons-superhero-alt" style="vertical-align:middle;margin-right:6px;"></span>
						<?php esc_html_e( 'AI Security Analysis (GPT-Enhanced)', 'turbo-guard' ); ?>
					</h2>
					<div style="font-size:13px;line-height:1.7;color:#374151;white-space:pre-wrap;">
						<?php echo esc_html( $turbo_guard_report['ai_narrative'] ); ?>
					</div>
				</div>
			<?php elseif ( ! $turbo_guard_openai_key ) : ?>
				<div class="turbo-guard-card" style="border:1px dashed #7c3aed;background:#faf5ff;">
					<div style="display:flex;align-items:center;gap:16px;">
						<span class="dashicons dashicons-superhero-alt" style="font-size:36px;width:36px;height:36px;color:#7c3aed;flex-shrink:0;"></span>
						<div>
							<strong style="display:block;font-size:14px;color:#5b21b6;"><?php esc_html_e( 'Upgrade to AI-Enhanced Analysis', 'turbo-guard' ); ?></strong>
							<p style="margin:4px 0 8px;font-size:13px;color:#6d28d9;">
								<?php esc_html_e( 'Connect your OpenAI API key to get GPT-powered narrative analysis explaining exactly what happened, how the attacker got in, and detailed remediation guidance tailored to your specific threats.', 'turbo-guard' ); ?>
							</p>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-settings#ai' ) ); ?>" class="button" style="background:#7c3aed;border-color:#6d28d9;color:#fff;">
								<?php esc_html_e( 'Add OpenAI API Key →', 'turbo-guard' ); ?>
							</a>
							<a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener noreferrer" class="button" style="margin-left:8px;">
								<?php esc_html_e( 'Get Free OpenAI Key', 'turbo-guard' ); ?>
							</a>
						</div>
					</div>
				</div>
			<?php endif; ?>

			<!-- Attack Campaigns Identified -->
			<?php if ( ! empty( $turbo_guard_report['campaigns'] ) && 'clean' !== $turbo_guard_report['overall_status'] ) : ?>
				<div class="turbo-guard-card">
					<h2><?php esc_html_e( 'Attack Analysis', 'turbo-guard' ); ?></h2>
					<?php foreach ( $turbo_guard_report['campaigns'] as $turbo_guard_campaign ) : ?>
						<?php
						$turbo_guard_badge_class = 'turbo-guard-badge-' . ( $turbo_guard_campaign['severity'] ?? 'high' );
						?>
						<div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:12px;">
							<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
								<strong style="font-size:14px;"><?php echo esc_html( $turbo_guard_campaign['name'] ); ?></strong>
								<span class="turbo-guard-badge <?php echo esc_attr( $turbo_guard_badge_class ); ?>">
									<?php echo esc_html( ucfirst( $turbo_guard_campaign['severity'] ) ); ?>
								</span>
							</div>
							<p style="font-size:13px;color:#374151;line-height:1.6;margin:0 0 12px;">
								<?php echo esc_html( $turbo_guard_campaign['explanation'] ); ?>
							</p>

							<?php if ( ! empty( $turbo_guard_campaign['impact'] ) ) : ?>
								<div style="background:#fef2f2;border-radius:6px;padding:10px 14px;margin-bottom:12px;">
									<strong style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#dc2626;"><?php esc_html_e( 'Business Impact', 'turbo-guard' ); ?></strong>
									<ul style="margin:6px 0 0;padding-left:18px;">
										<?php foreach ( $turbo_guard_campaign['impact'] as $turbo_guard_impact ) : ?>
											<li style="font-size:12px;color:#7f1d1d;margin-bottom:2px;"><?php echo esc_html( $turbo_guard_impact ); ?></li>
										<?php endforeach; ?>
									</ul>
								</div>
							<?php endif; ?>

							<div style="background:#f0fdf4;border-radius:6px;padding:10px 14px;">
								<strong style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#16a34a;"><?php esc_html_e( 'Step-by-Step Fix', 'turbo-guard' ); ?></strong>
								<ol style="margin:6px 0 0;padding-left:18px;">
									<?php foreach ( $turbo_guard_campaign['steps'] as $turbo_guard_step ) : ?>
										<li style="font-size:12px;color:#14532d;margin-bottom:4px;line-height:1.5;"><?php echo esc_html( $turbo_guard_step ); ?></li>
									<?php endforeach; ?>
								</ol>
							</div>
						</div>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>

			<!-- Security Trend Chart -->
			<?php if ( count( $turbo_guard_trend ) > 1 ) : ?>
				<div class="turbo-guard-card">
					<h2><?php esc_html_e( 'Security Score Trend (30 Days)', 'turbo-guard' ); ?></h2>
					<canvas id="turbo-guard-trend-chart" height="80"></canvas>
					<?php
					// The trend chart is drawn by admin/js/turbo-guard-admin-v3.js
					// (enqueued via admin_enqueue_scripts); the trend data is passed
					// through wp_localize_script as turboGuardAdmin.trend.
					?>
					<p style="font-size:11px;color:#9ca3af;margin-top:8px;">
						<?php esc_html_e( 'Higher is better. Score drops when threats are found.', 'turbo-guard' ); ?>
					</p>
				</div>
			<?php endif; ?>

			<!-- Quick Actions -->
			<div class="turbo-guard-card">
				<h2><?php esc_html_e( 'Recommended Actions', 'turbo-guard' ); ?></h2>
				<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-scanner' ) ); ?>" class="turbo-guard-action-button">
						<span class="dashicons dashicons-search"></span>
						<div>
							<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Run New Scan', 'turbo-guard' ); ?></strong>
							<span style="font-size:11px;color:#9ca3af;"><?php esc_html_e( 'Scan + database check', 'turbo-guard' ); ?></span>
						</div>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-vulnerabilities' ) ); ?>" class="turbo-guard-action-button">
						<span class="dashicons dashicons-warning"></span>
						<div>
							<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Check Vulnerabilities', 'turbo-guard' ); ?></strong>
							<span style="font-size:11px;color:#9ca3af;"><?php esc_html_e( 'Find exploitable plugins', 'turbo-guard' ); ?></span>
						</div>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-gsc' ) ); ?>" class="turbo-guard-action-button">
						<span class="dashicons dashicons-admin-site"></span>
						<div>
							<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Clean Google Index', 'turbo-guard' ); ?></strong>
							<span style="font-size:11px;color:#9ca3af;"><?php esc_html_e( 'Remove spam URLs', 'turbo-guard' ); ?></span>
						</div>
					</a>
					<a href="<?php echo esc_url( admin_url( 'users.php' ) ); ?>" class="turbo-guard-action-button">
						<span class="dashicons dashicons-admin-users"></span>
						<div>
							<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Audit Admin Users', 'turbo-guard' ); ?></strong>
							<span style="font-size:11px;color:#9ca3af;"><?php esc_html_e( 'Remove suspicious accounts', 'turbo-guard' ); ?></span>
						</div>
					</a>
				</div>
			</div>

		<?php endif; ?>

	<?php endif; ?>

</div><!-- /.wrap -->
