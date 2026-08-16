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

$latest_scan = Turbo_Guard_Scanner::get_latest_scan();
$report      = $latest_scan ? Turbo_Guard_AI_Advisor::get_cached_report( $latest_scan->id ) : null;
$trend       = Turbo_Guard_AI_Advisor::get_security_trend();
$openai_key  = get_option( 'turbo_guard_openai_api_key', '' );

// If no cached report, generate one from latest scan.
if ( ! $report && $latest_scan ) {
	$report = Turbo_Guard_AI_Advisor::analyse_scan( $latest_scan->id, false );
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
				<h1><?php esc_html_e( 'AI Security Advisor', 'turbo-guard-security-malware-scanner' ); ?></h1>
				<p><?php esc_html_e( 'Intelligent analysis of your security posture with plain-English guidance', 'turbo-guard-security-malware-scanner' ); ?></p>
			</div>
		</div>
		<span class="turbo-guard-header-badge"><?php esc_html_e( 'Powered by Turbo Guard AI', 'turbo-guard-security-malware-scanner' ); ?></span>
	</div>

	<?php if ( ! $latest_scan ) : ?>
		<div class="turbo-guard-card">
			<div class="turbo-guard-no-scan">
				<span class="dashicons dashicons-superhero-alt"></span>
				<p><?php esc_html_e( 'Run your first scan to get AI security analysis.', 'turbo-guard-security-malware-scanner' ); ?></p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-scanner' ) ); ?>" class="button button-primary" style="margin-top:12px;">
					<?php esc_html_e( 'Start Scan Now →', 'turbo-guard-security-malware-scanner' ); ?>
				</a>
			</div>
		</div>
	<?php else : ?>

		<?php if ( $report ) : ?>

			<!-- Status Banner -->
			<?php
			$status_colors = array(
				'clean'    => array( 'bg' => '#f0fdf4', 'border' => '#16a34a', 'text' => '#15803d', 'icon' => 'dashicons-yes-alt' ),
				'warning'  => array( 'bg' => '#fffbeb', 'border' => '#d97706', 'text' => '#92400e', 'icon' => 'dashicons-warning' ),
				'high'     => array( 'bg' => '#fff7ed', 'border' => '#ea580c', 'text' => '#c2410c', 'icon' => 'dashicons-warning' ),
				'critical' => array( 'bg' => '#fef2f2', 'border' => '#dc2626', 'text' => '#b91c1c', 'icon' => 'dashicons-dismiss' ),
			);
			$sc = $status_colors[ $report['overall_status'] ] ?? $status_colors['warning'];
			?>
			<div style="background:<?php echo esc_attr( $sc['bg'] ); ?>;border-left:5px solid <?php echo esc_attr( $sc['border'] ); ?>;padding:16px 20px;border-radius:6px;margin-bottom:16px;display:flex;align-items:flex-start;gap:14px;">
				<span class="dashicons <?php echo esc_attr( $sc['icon'] ); ?>" style="font-size:28px;width:28px;height:28px;color:<?php echo esc_attr( $sc['border'] ); ?>;flex-shrink:0;margin-top:2px;"></span>
				<div>
					<strong style="font-size:15px;color:<?php echo esc_attr( $sc['text'] ); ?>;display:block;margin-bottom:4px;">
						<?php
						$labels = array(
							'clean'    => __( 'Your site is clean and well-protected.', 'turbo-guard-security-malware-scanner' ),
							'warning'  => __( 'Security issues detected — action recommended.', 'turbo-guard-security-malware-scanner' ),
							'high'     => __( 'High-severity threats found — address within 24 hours.', 'turbo-guard-security-malware-scanner' ),
							'critical' => __( 'CRITICAL: Your site is actively compromised — act immediately.', 'turbo-guard-security-malware-scanner' ),
						);
						echo esc_html( $labels[ $report['overall_status'] ] ?? $labels['warning'] );
						?>
					</strong>
					<p style="margin:0;color:<?php echo esc_attr( $sc['text'] ); ?>;font-size:13px;opacity:.85;">
						<?php echo esc_html( $report['summary'] ); ?>
					</p>
				</div>
			</div>

			<!-- OpenAI Enhanced Narrative -->
			<?php if ( ! empty( $report['ai_narrative'] ) ) : ?>
				<div class="turbo-guard-card" style="border-left:4px solid #7c3aed;">
					<h2 style="color:#7c3aed;">
						<span class="dashicons dashicons-superhero-alt" style="vertical-align:middle;margin-right:6px;"></span>
						<?php esc_html_e( 'AI Security Analysis (GPT-Enhanced)', 'turbo-guard-security-malware-scanner' ); ?>
					</h2>
					<div style="font-size:13px;line-height:1.7;color:#374151;white-space:pre-wrap;">
						<?php echo esc_html( $report['ai_narrative'] ); ?>
					</div>
				</div>
			<?php elseif ( ! $openai_key ) : ?>
				<div class="turbo-guard-card" style="border:1px dashed #7c3aed;background:#faf5ff;">
					<div style="display:flex;align-items:center;gap:16px;">
						<span class="dashicons dashicons-superhero-alt" style="font-size:36px;width:36px;height:36px;color:#7c3aed;flex-shrink:0;"></span>
						<div>
							<strong style="display:block;font-size:14px;color:#5b21b6;"><?php esc_html_e( 'Upgrade to AI-Enhanced Analysis', 'turbo-guard-security-malware-scanner' ); ?></strong>
							<p style="margin:4px 0 8px;font-size:13px;color:#6d28d9;">
								<?php esc_html_e( 'Connect your OpenAI API key to get GPT-powered narrative analysis explaining exactly what happened, how the attacker got in, and detailed remediation guidance tailored to your specific threats.', 'turbo-guard-security-malware-scanner' ); ?>
							</p>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-settings#ai' ) ); ?>" class="button" style="background:#7c3aed;border-color:#6d28d9;color:#fff;">
								<?php esc_html_e( 'Add OpenAI API Key →', 'turbo-guard-security-malware-scanner' ); ?>
							</a>
							<a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener noreferrer" class="button" style="margin-left:8px;">
								<?php esc_html_e( 'Get Free OpenAI Key', 'turbo-guard-security-malware-scanner' ); ?>
							</a>
						</div>
					</div>
				</div>
			<?php endif; ?>

			<!-- Attack Campaigns Identified -->
			<?php if ( ! empty( $report['campaigns'] ) && 'clean' !== $report['overall_status'] ) : ?>
				<div class="turbo-guard-card">
					<h2><?php esc_html_e( 'Attack Analysis', 'turbo-guard-security-malware-scanner' ); ?></h2>
					<?php foreach ( $report['campaigns'] as $campaign ) : ?>
						<?php
						$badge_class = 'turbo-guard-badge-' . ( $campaign['severity'] ?? 'high' );
						?>
						<div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:12px;">
							<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
								<strong style="font-size:14px;"><?php echo esc_html( $campaign['name'] ); ?></strong>
								<span class="turbo-guard-badge <?php echo esc_attr( $badge_class ); ?>">
									<?php echo esc_html( ucfirst( $campaign['severity'] ) ); ?>
								</span>
							</div>
							<p style="font-size:13px;color:#374151;line-height:1.6;margin:0 0 12px;">
								<?php echo esc_html( $campaign['explanation'] ); ?>
							</p>

							<?php if ( ! empty( $campaign['impact'] ) ) : ?>
								<div style="background:#fef2f2;border-radius:6px;padding:10px 14px;margin-bottom:12px;">
									<strong style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#dc2626;"><?php esc_html_e( 'Business Impact', 'turbo-guard-security-malware-scanner' ); ?></strong>
									<ul style="margin:6px 0 0;padding-left:18px;">
										<?php foreach ( $campaign['impact'] as $impact ) : ?>
											<li style="font-size:12px;color:#7f1d1d;margin-bottom:2px;"><?php echo esc_html( $impact ); ?></li>
										<?php endforeach; ?>
									</ul>
								</div>
							<?php endif; ?>

							<div style="background:#f0fdf4;border-radius:6px;padding:10px 14px;">
								<strong style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#16a34a;"><?php esc_html_e( 'Step-by-Step Fix', 'turbo-guard-security-malware-scanner' ); ?></strong>
								<ol style="margin:6px 0 0;padding-left:18px;">
									<?php foreach ( $campaign['steps'] as $step ) : ?>
										<li style="font-size:12px;color:#14532d;margin-bottom:4px;line-height:1.5;"><?php echo esc_html( $step ); ?></li>
									<?php endforeach; ?>
								</ol>
							</div>
						</div>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>

			<!-- Security Trend Chart -->
			<?php if ( count( $trend ) > 1 ) : ?>
				<div class="turbo-guard-card">
					<h2><?php esc_html_e( 'Security Score Trend (30 Days)', 'turbo-guard-security-malware-scanner' ); ?></h2>
					<canvas id="turbo-guard-trend-chart" height="80"></canvas>
					<script>
					(function() {
						var data = <?php echo wp_json_encode( $trend ); ?>;
						var canvas = document.getElementById('turbo-guard-trend-chart');
						if (!canvas) return;
						var ctx = canvas.getContext('2d');
						var W = canvas.offsetWidth;
						canvas.width = W;
						var H = 80;
						var scores = data.map(function(d) { return d.score; });
						var minS = Math.min.apply(null, scores);
						var maxS = Math.max.apply(null, scores) || 100;
						var step = W / Math.max(data.length - 1, 1);

						ctx.fillStyle = '#f9fafb';
						ctx.fillRect(0, 0, W, H);

						// Draw grid lines.
						ctx.strokeStyle = '#e5e7eb';
						ctx.lineWidth = 1;
						[0, 25, 50, 75, 100].forEach(function(pct) {
							var y = H - (pct / 100) * H;
							ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
						});

						// Draw gradient fill.
						var gradient = ctx.createLinearGradient(0, 0, 0, H);
						gradient.addColorStop(0, 'rgba(37,99,235,.3)');
						gradient.addColorStop(1, 'rgba(37,99,235,.02)');

						ctx.beginPath();
						data.forEach(function(d, i) {
							var x = i * step;
							var y = H - ((d.score - minS) / (maxS - minS + 1)) * (H - 10) - 5;
							i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
						});
						ctx.lineTo((data.length - 1) * step, H);
						ctx.lineTo(0, H);
						ctx.closePath();
						ctx.fillStyle = gradient;
						ctx.fill();

						// Draw line.
						ctx.beginPath();
						ctx.strokeStyle = '#2563eb';
						ctx.lineWidth = 2;
						data.forEach(function(d, i) {
							var x = i * step;
							var y = H - ((d.score - minS) / (maxS - minS + 1)) * (H - 10) - 5;
							i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
						});
						ctx.stroke();
					}());
					</script>
					<p style="font-size:11px;color:#9ca3af;margin-top:8px;">
						<?php esc_html_e( 'Higher is better. Score drops when threats are found.', 'turbo-guard-security-malware-scanner' ); ?>
					</p>
				</div>
			<?php endif; ?>

			<!-- Quick Actions -->
			<div class="turbo-guard-card">
				<h2><?php esc_html_e( 'Recommended Actions', 'turbo-guard-security-malware-scanner' ); ?></h2>
				<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-scanner' ) ); ?>" class="turbo-guard-action-button">
						<span class="dashicons dashicons-search"></span>
						<div>
							<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Run New Scan', 'turbo-guard-security-malware-scanner' ); ?></strong>
							<span style="font-size:11px;color:#9ca3af;"><?php esc_html_e( 'Scan + database check', 'turbo-guard-security-malware-scanner' ); ?></span>
						</div>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-vulnerabilities' ) ); ?>" class="turbo-guard-action-button">
						<span class="dashicons dashicons-warning"></span>
						<div>
							<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Check Vulnerabilities', 'turbo-guard-security-malware-scanner' ); ?></strong>
							<span style="font-size:11px;color:#9ca3af;"><?php esc_html_e( 'Find exploitable plugins', 'turbo-guard-security-malware-scanner' ); ?></span>
						</div>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-gsc' ) ); ?>" class="turbo-guard-action-button">
						<span class="dashicons dashicons-admin-site"></span>
						<div>
							<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Clean Google Index', 'turbo-guard-security-malware-scanner' ); ?></strong>
							<span style="font-size:11px;color:#9ca3af;"><?php esc_html_e( 'Remove spam URLs', 'turbo-guard-security-malware-scanner' ); ?></span>
						</div>
					</a>
					<a href="<?php echo esc_url( admin_url( 'users.php' ) ); ?>" class="turbo-guard-action-button">
						<span class="dashicons dashicons-admin-users"></span>
						<div>
							<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Audit Admin Users', 'turbo-guard-security-malware-scanner' ); ?></strong>
							<span style="font-size:11px;color:#9ca3af;"><?php esc_html_e( 'Remove suspicious accounts', 'turbo-guard-security-malware-scanner' ); ?></span>
						</div>
					</a>
				</div>
			</div>

		<?php endif; ?>

	<?php endif; ?>

</div><!-- /.wrap -->
