<?php
/**
 * Firewall Page Template.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="wrap turbo-guard-firewall">

	<!-- Page Header Banner -->
	<div class="turbo-guard-page-header">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-shield-alt"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'Firewall', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'WAF logs, IP blocklist &amp; attack monitoring', 'turbo-guard' ); ?></p>
			</div>
		</div>
	</div>

	<!-- Firewall Status -->
	<div class="turbo-guard-card">
		<h2><?php esc_html_e( 'Firewall Status', 'turbo-guard' ); ?></h2>
		<div class="turbo-guard-status-row">
			<?php
			$turbo_guard_enabled = 'yes' === get_option( 'turbo_guard_firewall_enabled', 'yes' );
			?>
			<span class="turbo-guard-status-dot <?php echo $turbo_guard_enabled ? 'turbo-guard-status-on' : 'turbo-guard-status-off'; ?>"></span>
			<strong>
				<?php echo $turbo_guard_enabled ? esc_html__( 'Firewall is Active', 'turbo-guard' ) : esc_html__( 'Firewall is Disabled', 'turbo-guard' ); ?>
			</strong>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-settings' ) ); ?>" class="button button-small">
				<?php esc_html_e( 'Configure', 'turbo-guard' ); ?>
			</a>
		</div>
	</div>

	<!-- Rate Limiting Settings -->
	<div class="turbo-guard-card">
		<div class="turbo-guard-card-header">
			<h2><?php esc_html_e( 'Rate Limiting', 'turbo-guard' ); ?></h2>
		</div>
		<?php
		$turbo_guard_rl_enabled  = 'yes' === get_option( 'turbo_guard_rate_limiting_enabled', 'yes' );
		$turbo_guard_rl_limit    = absint( get_option( 'turbo_guard_rate_limit', 120 ) );
		$turbo_guard_rl_404      = absint( get_option( 'turbo_guard_rate_limit_404', 60 ) );
		$turbo_guard_rl_duration = absint( get_option( 'turbo_guard_rate_limit_block_duration', 300 ) );
		?>
		<p class="description">
			<?php esc_html_e( 'Throttle IPs that make an abnormally high number of requests, then auto-block them for the duration below. Recommended values are shown next to each field.', 'turbo-guard' ); ?>
		</p>

		<form id="turbo-guard-rate-limit-form">
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Rate Limiting', 'turbo-guard' ); ?></th>
					<td>
						<label class="turbo-guard-toggle">
							<input type="checkbox" id="turbo-guard-rate-limit-enabled" name="rate_limiting_enabled" value="yes" <?php checked( $turbo_guard_rl_enabled ); ?> />
							<span class="turbo-guard-toggle-slider" aria-hidden="true"></span>
							<span class="turbo-guard-toggle-label"><?php esc_html_e( 'Block IPs that exceed the limits below', 'turbo-guard' ); ?></span>
						</label>
						<span id="turbo-guard-rate-limit-toggle-status" class="description" style="margin-left:8px;"></span>
					</td>
				</tr>
				<tr class="turbo-guard-rate-limit-field">
					<th scope="row"><label for="turbo-guard-rate-limit"><?php esc_html_e( 'Requests per minute', 'turbo-guard' ); ?></label></th>
					<td>
						<input type="number" id="turbo-guard-rate-limit" name="rate_limit" value="<?php echo esc_attr( $turbo_guard_rl_limit ); ?>" min="10" max="10000" class="small-text" />
						<p class="description"><?php esc_html_e( 'Recommended: 120. A normal visitor rarely exceeds this.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr class="turbo-guard-rate-limit-field">
					<th scope="row"><label for="turbo-guard-rate-limit-404"><?php esc_html_e( '404s per minute', 'turbo-guard' ); ?></label></th>
					<td>
						<input type="number" id="turbo-guard-rate-limit-404" name="rate_limit_404" value="<?php echo esc_attr( $turbo_guard_rl_404 ); ?>" min="5" max="10000" class="small-text" />
						<p class="description"><?php esc_html_e( 'Recommended: 60. Scanners hit many missing URLs in bursts.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr class="turbo-guard-rate-limit-field">
					<th scope="row"><label for="turbo-guard-rate-limit-duration"><?php esc_html_e( 'Block duration (seconds)', 'turbo-guard' ); ?></label></th>
					<td>
						<input type="number" id="turbo-guard-rate-limit-duration" name="rate_limit_block_duration" value="<?php echo esc_attr( $turbo_guard_rl_duration ); ?>" min="60" max="<?php echo esc_attr( DAY_IN_SECONDS ); ?>" class="small-text" />
						<p class="description"><?php esc_html_e( 'Recommended: 300 (5 minutes). How long a violator stays blocked.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
			</table>
			<p class="turbo-guard-rate-limit-field">
				<input type="hidden" name="nonce" value="<?php echo esc_attr( wp_create_nonce( 'turbo_guard_admin' ) ); ?>" />
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Save Rate Limiting', 'turbo-guard' ); ?></button>
				<span id="turbo-guard-rate-limit-result" style="margin-left:10px;"></span>
			</p>
		</form>
	</div>

	<!-- Blocked IPs -->
	<div class="turbo-guard-card">
		<div class="turbo-guard-card-header">
			<h2><?php esc_html_e( 'Blocked IP Addresses', 'turbo-guard' ); ?></h2>
			<!-- Block IP Form -->
			<form id="turbo-guard-block-ip-form" class="turbo-guard-inline-form">
				<input type="text" id="turbo-guard-block-ip-input" placeholder="<?php esc_attr_e( 'Enter IP address...', 'turbo-guard' ); ?>" class="regular-text" />
				<input type="hidden" name="nonce" value="<?php echo esc_attr( wp_create_nonce( 'turbo_guard_admin' ) ); ?>" />
				<button type="submit" class="button button-secondary">
					<?php esc_html_e( 'Block IP', 'turbo-guard' ); ?>
				</button>
			</form>
		</div>

		<?php if ( ! empty( $turbo_guard_blocked_ips ) ) : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'IP Address', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Blocked', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Expires', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $turbo_guard_blocked_ips as $turbo_guard_blocked_ip ) : ?>
						<tr>
							<td><code><?php echo esc_html( $turbo_guard_blocked_ip->ip_address ); ?></code></td>
							<td><?php echo esc_html( $turbo_guard_blocked_ip->reason ? $turbo_guard_blocked_ip->reason : '—' ); ?></td>
							<td><?php echo esc_html( human_time_diff( strtotime( $turbo_guard_blocked_ip->created_at ), current_time( 'timestamp' ) ) . ' ' . __( 'ago', 'turbo-guard' ) ); ?></td>
							<td>
								<?php
								if ( $turbo_guard_blocked_ip->expires_at ) {
									echo esc_html( human_time_diff( current_time( 'timestamp' ), strtotime( $turbo_guard_blocked_ip->expires_at ) ) );
								} else {
									esc_html_e( 'Permanent', 'turbo-guard' );
								}
								?>
							</td>
							<td>
								<button class="button button-small turbo-guard-unblock-ip"
									data-ip="<?php echo esc_attr( $turbo_guard_blocked_ip->ip_address ); ?>"
									data-nonce="<?php echo esc_attr( wp_create_nonce( 'turbo_guard_admin' ) ); ?>">
									<?php esc_html_e( 'Unblock', 'turbo-guard' ); ?>
								</button>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php else : ?>
			<p><?php esc_html_e( 'No IPs are currently blocked.', 'turbo-guard' ); ?></p>
		<?php endif; ?>
	</div>

	<!-- Recent Firewall Activity -->
	<div class="turbo-guard-card">
		<h2><?php esc_html_e( 'Recent Blocked Requests', 'turbo-guard' ); ?></h2>
		<?php if ( ! empty( $turbo_guard_recent_blocks ) ) : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Time', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'IP Address', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'URL', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Block Reason', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $turbo_guard_recent_blocks as $turbo_guard_block ) : ?>
						<tr>
							<td><?php echo esc_html( human_time_diff( strtotime( $turbo_guard_block->created_at ), current_time( 'timestamp' ) ) . ' ' . __( 'ago', 'turbo-guard' ) ); ?></td>
							<td><code><?php echo esc_html( $turbo_guard_block->ip_address ); ?></code></td>
							<td><small><?php echo esc_html( $turbo_guard_block->request_uri ); ?></small></td>
							<td><?php echo esc_html( $turbo_guard_block->block_reason ); ?></td>
							<td>
								<button class="button button-small turbo-guard-block-from-log"
									data-ip="<?php echo esc_attr( $turbo_guard_block->ip_address ); ?>"
									data-nonce="<?php echo esc_attr( wp_create_nonce( 'turbo_guard_admin' ) ); ?>">
									<?php esc_html_e( 'Block IP', 'turbo-guard' ); ?>
								</button>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php else : ?>
			<p><?php esc_html_e( 'No blocked requests logged yet.', 'turbo-guard' ); ?></p>
		<?php endif; ?>
	</div>

	<!-- Recent Rate Limiting Activity -->
	<div class="turbo-guard-card">
		<h2><?php esc_html_e( 'Recent Rate Limiting', 'turbo-guard' ); ?></h2>
		<?php if ( ! empty( $turbo_guard_recent_rate_limits ) ) : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Time', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'IP Address', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Rule', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Requests', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $turbo_guard_recent_rate_limits as $turbo_guard_rate_limit_row ) : ?>
						<tr>
							<td><?php echo esc_html( human_time_diff( strtotime( $turbo_guard_rate_limit_row->created_at ), current_time( 'timestamp' ) ) . ' ' . __( 'ago', 'turbo-guard' ) ); ?></td>
							<td><code><?php echo esc_html( $turbo_guard_rate_limit_row->ip_address ); ?></code></td>
							<td>
								<?php
								if ( '404' === $turbo_guard_rate_limit_row->rule_type ) {
									esc_html_e( '404s per minute', 'turbo-guard' );
								} else {
									esc_html_e( 'Requests per minute', 'turbo-guard' );
								}
								?>
							</td>
							<td>
								<?php
								printf(
									/* translators: 1: requests made, 2: configured limit */
									esc_html__( '%1$d / %2$d', 'turbo-guard' ),
									(int) $turbo_guard_rate_limit_row->requests,
									(int) $turbo_guard_rate_limit_row->limit
								);
								?>
							</td>
							<td>
								<button class="button button-small turbo-guard-block-from-log"
									data-ip="<?php echo esc_attr( $turbo_guard_rate_limit_row->ip_address ); ?>"
									data-nonce="<?php echo esc_attr( wp_create_nonce( 'turbo_guard_admin' ) ); ?>">
									<?php esc_html_e( 'Block IP', 'turbo-guard' ); ?>
								</button>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php else : ?>
			<p><?php esc_html_e( 'No rate-limiting events yet. IPs that exceed the limits will appear here and be auto-blocked.', 'turbo-guard' ); ?></p>
		<?php endif; ?>
	</div>
</div>
