<?php
/**
 * Dashboard Page Template.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Determine score color for SVG circle.
$score       = $stats['security_score'];
$circumference = 314; // 2 * pi * 50.
$dash_offset   = $circumference - ( ( $score / 100 ) * $circumference );
$circle_color  = $score >= 90 ? '#16a34a' : ( $score >= 70 ? '#d97706' : '#dc2626' );
?>

<div class="wrap turbo-guard-dashboard">

	<!-- Page Header Banner -->
	<div class="turbo-guard-page-header">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-shield"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'Turbo Guard', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Security Dashboard — All systems overview', 'turbo-guard' ); ?></p>
			</div>
		</div>
		<span class="turbo-guard-header-badge">v<?php echo esc_html( TURBO_GUARD_VERSION ); ?> Free</span>
	</div>

	<?php
	/**
	 * Remote notification banners are rendered here.
	 * Turbo_Guard_Notices::render_notices() is hooked to this action.
	 *
	 * @since 1.3.0
	 */
	do_action( 'turbo_guard_after_header' );
	?>

	<?php
	// TEMPORARY DEBUG — remove after testing.
	if ( current_user_can( 'manage_options' ) && isset( $_GET['tg_debug'] ) ) {
		echo '<div style="background:#fff3cd;border:1px solid #ffc107;padding:10px;margin:10px 0;font-size:12px;">';
		echo '<strong>🔧 NOTICE SYSTEM DEBUG:</strong><br>';

		// Check if class exists.
		echo '✓ Notices class exists: ' . ( class_exists( 'Turbo_Guard_Notices' ) ? 'YES' : 'NO' ) . '<br>';
		echo '✓ Activity class exists: ' . ( class_exists( 'Turbo_Guard_Activity' ) ? 'YES' : 'NO' ) . '<br>';

		// Check transient.
		$cached = get_transient( 'turbo_guard_remote_notices' );
		if ( $cached === false ) {
			echo '✓ Transient: EXPIRED (will fetch fresh on next load)<br>';
		} elseif ( isset( $cached['__empty'] ) ) {
			echo '✓ Transient: Server had no notices (will retry after TTL)<br>';
		} else {
			echo '✓ Transient: HAS ' . count( $cached ) . ' notices cached<br>';
		}

		// Check error transient.
		$error_state = get_transient( 'turbo_guard_notices_fetch_error' );
		echo '✓ Error cooldown: ' . ( $error_state ? 'ACTIVE (' . esc_html( $error_state ) . ') — retrying in ≤60s' : 'NONE' ) . '<br>';

		// Version tracking.
		$stored_ver = get_option( 'turbo_guard_notices_version', '' );
		echo '✓ Stored version: ' . esc_html( $stored_ver ) . ' | Current: ' . TURBO_GUARD_VERSION . '<br>';

		// Try fetching the actual URL directly.
		$test_url = Turbo_Guard_Notices::REMOTE_URL;
		echo '✓ Fetching: ' . esc_html( $test_url ) . '<br>';
		$response = wp_remote_get( $test_url, array( 'timeout' => 8 ) );
		if ( is_wp_error( $response ) ) {
			echo '❌ Fetch error: ' . esc_html( $response->get_error_message() ) . '<br>';
		} else {
			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );
			echo '✓ HTTP status: ' . wp_remote_retrieve_response_code( $response ) . '<br>';
			echo '✓ Notices in remote JSON: ' . ( isset( $data['notices'] ) ? count( $data['notices'] ) : '0 or invalid' ) . '<br>';
		}

		// Activity data.
		$snap = Turbo_Guard_Activity::get_instance()->get_snapshot();
		echo esc_html( '✓ Activity: first_seen=' . date( 'Y-m-d', $snap['first_seen'] ?: time() )
			. ' | last_seen=' . date( 'Y-m-d', $snap['last_seen'] ?: time() )
			. ' | scans=' . $snap['scan_count']
			. ' | score=' . $snap['last_score']
			. ' | days_since_install=' . $snap['days_since_install'] ) . '<br>';

		// Check dismissed.
		$dismissed = get_user_meta( get_current_user_id(), 'turbo_guard_dismissed_notices', true );
		echo '✓ Dismissed: ' . ( is_array( $dismissed ) && ! empty( $dismissed ) ? implode( ', ', $dismissed ) : 'NONE' ) . '<br>';

		// activated_at.
		$activated = get_option( 'turbo_guard_activated_at', 0 );
		echo '✓ activated_at: ' . ( $activated ? date( 'Y-m-d H:i', $activated ) : 'NOT SET' ) . '<br>';

		echo '<br><a href="' . esc_url( admin_url( 'admin-ajax.php?action=turbo_guard_flush_notices&nonce=' . wp_create_nonce( 'turbo_guard_flush_notices' ) ) ) . '" style="color:#d63384;">⟳ Flush Cache Now</a>';
		echo '</div>';
	}
	?>

	<!-- Stats Grid -->
	<div class="turbo-guard-stats-grid">

		<!-- Security Score -->
		<div class="turbo-guard-card turbo-guard-score-card">
			<h2><?php esc_html_e( 'Security Score', 'turbo-guard' ); ?></h2>
			<div class="turbo-guard-score-circle">
				<svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg">
					<circle cx="60" cy="60" r="50" fill="none" stroke="#e5e7eb" stroke-width="10"/>
					<circle cx="60" cy="60" r="50" fill="none"
						stroke="<?php echo esc_attr( $circle_color ); ?>"
						stroke-width="10"
						stroke-linecap="round"
						stroke-dasharray="<?php echo esc_attr( ( $score / 100 ) * $circumference ); ?> <?php echo esc_attr( $circumference ); ?>"
						transform="rotate(-90 60 60)"
						style="transition: stroke-dasharray .6s ease;"
					/>
				</svg>
				<span class="turbo-guard-score-value" style="color:<?php echo esc_attr( $circle_color ); ?>">
					<?php echo esc_html( $score ); ?>
				</span>
			</div>
			<p class="turbo-guard-score-label">
				<?php
				if ( $score >= 90 ) {
					esc_html_e( 'Excellent protection', 'turbo-guard' );
				} elseif ( $score >= 70 ) {
					esc_html_e( 'Good — can improve', 'turbo-guard' );
				} else {
					esc_html_e( 'Action required', 'turbo-guard' );
				}
				?>
			</p>
		</div>

		<!-- Active Threats -->
		<div class="turbo-guard-card turbo-guard-stat-card tg-threat">
			<h3><?php esc_html_e( 'Active Threats', 'turbo-guard' ); ?></h3>
			<div class="turbo-guard-stat-value <?php echo $stats['threats_count'] > 0 ? 'tg-red' : 'tg-green'; ?>">
				<?php echo esc_html( $stats['threats_count'] ); ?>
			</div>
			<p class="turbo-guard-stat-label">
				<?php
				if ( $stats['threats_count'] > 0 ) {
					echo esc_html(
						sprintf(
							/* translators: %d: threat count */
							_n( '%d malware file found', '%d malware files found', $stats['threats_count'], 'turbo-guard' ),
							$stats['threats_count']
						)
					);
				} else {
					esc_html_e( 'No threats detected', 'turbo-guard' );
				}
				?>
			</p>
			<?php if ( $stats['threats_count'] > 0 ) : ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-scanner' ) ); ?>" class="button button-primary button-small">
					<?php esc_html_e( 'Clean Now →', 'turbo-guard' ); ?>
				</a>
			<?php else : ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-scanner' ) ); ?>" class="button button-small">
					<?php esc_html_e( 'Run Scan', 'turbo-guard' ); ?>
				</a>
			<?php endif; ?>
			<span class="dashicons dashicons-warning turbo-guard-stat-icon"></span>
		</div>

		<!-- Firewall Blocks -->
		<div class="turbo-guard-card turbo-guard-stat-card tg-fire">
			<h3><?php esc_html_e( 'Blocked Today', 'turbo-guard' ); ?></h3>
			<div class="turbo-guard-stat-value <?php echo $stats['blocks_today'] > 0 ? 'tg-orange' : ''; ?>">
				<?php echo esc_html( $stats['blocks_today'] ); ?>
			</div>
			<p class="turbo-guard-stat-label">
				<?php esc_html_e( 'Firewall blocks today', 'turbo-guard' ); ?>
			</p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-firewall' ) ); ?>" class="button button-small">
				<?php esc_html_e( 'View Logs', 'turbo-guard' ); ?>
			</a>
			<span class="dashicons dashicons-shield-alt turbo-guard-stat-icon"></span>
		</div>

		<!-- Last Scan -->
		<div class="turbo-guard-card turbo-guard-stat-card tg-scan">
			<h3><?php esc_html_e( 'Last Scan', 'turbo-guard' ); ?></h3>
			<div class="turbo-guard-stat-value" style="font-size:28px; line-height:1.2;">
				<?php
				if ( $stats['latest_scan'] ) {
					echo esc_html( human_time_diff( strtotime( $stats['latest_scan']->completed_at ), current_time( 'timestamp' ) ) );
					echo '<br><span style="font-size:13px;font-weight:400;color:#9ca3af;">' . esc_html__( 'ago', 'turbo-guard' ) . '</span>';
				} else {
					echo '<span style="font-size:20px;">' . esc_html__( 'Never', 'turbo-guard' ) . '</span>';
				}
				?>
			</div>
			<p class="turbo-guard-stat-label">
				<?php
				if ( $stats['latest_scan'] ) {
					echo esc_html(
						sprintf(
							/* translators: %d: files scanned */
							__( '%d files scanned', 'turbo-guard' ),
							$stats['latest_scan']->scanned_files
						)
					);
				} else {
					esc_html_e( 'No scans yet', 'turbo-guard' );
				}
				?>
			</p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-scanner' ) ); ?>" class="button button-primary button-small">
				<?php esc_html_e( 'Scan Now', 'turbo-guard' ); ?>
			</a>
			<span class="dashicons dashicons-search turbo-guard-stat-icon"></span>
		</div>

	</div><!-- /.turbo-guard-stats-grid -->

	<!-- Recent Security Events -->
	<div class="turbo-guard-card">
		<div class="turbo-guard-card-header">
			<h2 style="margin:0;border:none;padding:0;"><?php esc_html_e( 'Recent Security Events', 'turbo-guard' ); ?></h2>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-firewall' ) ); ?>" style="font-size:12px;color:#6b7280;"><?php esc_html_e( 'View all →', 'turbo-guard' ); ?></a>
		</div>

		<?php if ( ! empty( $stats['recent_events'] ) ) : ?>
			<table class="turbo-guard-events-table">
				<thead>
					<tr>
						<th style="width:120px;"><?php esc_html_e( 'Time', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Event', 'turbo-guard' ); ?></th>
						<th style="width:100px;"><?php esc_html_e( 'Severity', 'turbo-guard' ); ?></th>
						<th style="width:110px;"><?php esc_html_e( 'IP Address', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $stats['recent_events'] as $event ) : ?>
						<tr>
							<td style="color:#9ca3af;font-size:12px;">
								<?php echo esc_html( human_time_diff( strtotime( $event->created_at ), current_time( 'timestamp' ) ) . ' ' . __( 'ago', 'turbo-guard' ) ); ?>
							</td>
							<td class="turbo-guard-event-message"><?php echo esc_html( $event->message ); ?></td>
							<td>
								<span class="turbo-guard-badge turbo-guard-badge-<?php echo esc_attr( $event->severity ); ?>">
									<?php echo esc_html( ucfirst( $event->severity ) ); ?>
								</span>
							</td>
							<td style="font-family:monospace;font-size:12px;color:#6b7280;">
								<?php echo $event->ip_address ? esc_html( $event->ip_address ) : '<span style="color:#d1d5db;">—</span>'; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php else : ?>
			<div style="text-align:center;padding:30px 20px;color:#9ca3af;">
				<span class="dashicons dashicons-yes-alt" style="font-size:32px;width:32px;height:32px;color:#d1d5db;display:block;margin:0 auto 8px;"></span>
				<p style="margin:0;font-size:13px;"><?php esc_html_e( 'No security events recorded yet. Your site is quiet!', 'turbo-guard' ); ?></p>
			</div>
		<?php endif; ?>
	</div>

	<!-- Quick Actions -->
	<div class="turbo-guard-quick-actions">
		<h2><?php esc_html_e( 'Quick Actions', 'turbo-guard' ); ?></h2>
		<div class="turbo-guard-actions-grid">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-scanner' ) ); ?>" class="turbo-guard-action-button">
				<span class="dashicons dashicons-search"></span>
				<div>
					<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Run Full Scan', 'turbo-guard' ); ?></strong>
					<span style="font-size:11px;font-weight:400;color:#9ca3af;"><?php esc_html_e( 'Scan for malware &amp; backdoors', 'turbo-guard' ); ?></span>
				</div>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-firewall' ) ); ?>" class="turbo-guard-action-button">
				<span class="dashicons dashicons-shield-alt"></span>
				<div>
					<strong style="display:block;font-size:13px;"><?php esc_html_e( 'Firewall &amp; IP Blocks', 'turbo-guard' ); ?></strong>
					<span style="font-size:11px;font-weight:400;color:#9ca3af;"><?php esc_html_e( 'View logs, block IPs', 'turbo-guard' ); ?></span>
				</div>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-gsc' ) ); ?>" class="turbo-guard-action-button">
				<span class="dashicons dashicons-search"></span>
				<div>
					<strong style="display:block;font-size:13px;"><?php esc_html_e( 'GSC Spam Cleanup', 'turbo-guard' ); ?></strong>
					<span style="font-size:11px;font-weight:400;color:#9ca3af;"><?php esc_html_e( 'Remove indexed SEO spam', 'turbo-guard' ); ?></span>
				</div>
			</a>
		</div>
	</div>

</div><!-- /.wrap -->
