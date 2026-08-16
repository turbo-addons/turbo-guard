<?php
/**
 * Live Traffic Page Template.
 *
 * @package TurboGuard
 * @since 1.1.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// All variables prefixed with tg_ to satisfy WordPress.NamingConventions.PrefixAllGlobals sniff.
$tg_filter      = isset( $_GET['filter'] ) ? sanitize_key( $_GET['filter'] ) : 'all'; // phpcs:ignore WordPress.Security.NonceVerification
$tg_paged       = isset( $_GET['paged'] )  ? max( 1, absint( $_GET['paged'] ) ) : 1;  // phpcs:ignore WordPress.Security.NonceVerification
$tg_per_page    = 50;
$tg_offset      = ( $tg_paged - 1 ) * $tg_per_page;
$tg_rows        = Turbo_Guard_Live_Traffic::get_traffic_paged( $tg_per_page, $tg_offset, $tg_filter );
$tg_total_count = Turbo_Guard_Live_Traffic::get_traffic_count( $tg_filter );
$tg_total_pages = max( 1, (int) ceil( $tg_total_count / $tg_per_page ) );
$tg_stats       = Turbo_Guard_Live_Traffic::get_stats();
$tg_filters     = array(
	'all'     => __( 'All Requests', 'turbo-guard' ),
	'humans'  => __( 'Humans Only', 'turbo-guard' ),
	'bots'    => __( 'Bots Only', 'turbo-guard' ),
	'blocked' => __( '403 Blocked', 'turbo-guard' ),
	'404'     => __( '404 Errors', 'turbo-guard' ),
);
?>

<div class="wrap turbo-guard-live-traffic">

	<!-- Page Header -->
	<div class="turbo-guard-page-header">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-chart-area"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'Live Traffic', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Real-time requests — humans, bots, blocked &amp; errors (last 24 hours)', 'turbo-guard' ); ?></p>
			</div>
		</div>
		<span class="turbo-guard-header-badge"><?php esc_html_e( '50 requests per page', 'turbo-guard' ); ?></span>
	</div>

	<!-- 24h Stats -->
	<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px;">
		<?php
		$tg_stat_cards = array(
			array( 'label' => __( 'Total', 'turbo-guard' ),    'value' => $tg_stats['total'],   'color' => '' ),
			array( 'label' => __( 'Humans', 'turbo-guard' ),   'value' => $tg_stats['humans'],  'color' => '#16a34a' ),
			array( 'label' => __( 'Bots', 'turbo-guard' ),     'value' => $tg_stats['bots'],    'color' => '#6b7280' ),
			array( 'label' => __( 'Blocked', 'turbo-guard' ),  'value' => $tg_stats['blocked'], 'color' => '#dc2626' ),
			array( 'label' => __( 'Errors', 'turbo-guard' ),   'value' => $tg_stats['errors'],  'color' => '#d97706' ),
		);
		foreach ( $tg_stat_cards as $tg_card ) :
		?>
		<div class="turbo-guard-card" style="padding:14px 16px;text-align:center;">
			<h3 style="<?php echo $tg_card['color'] ? 'color:' . esc_attr( $tg_card['color'] ) . ';' : ''; ?>"><?php echo esc_html( $tg_card['label'] ); ?></h3>
			<div class="turbo-guard-stat-value" style="font-size:32px;<?php echo $tg_card['color'] ? 'color:' . esc_attr( $tg_card['color'] ) . ';' : ''; ?>">
				<?php echo absint( $tg_card['value'] ); ?>
			</div>
		</div>
		<?php endforeach; ?>
	</div>

	<!-- Traffic Table -->
	<div class="turbo-guard-card">

		<!-- Top pagination + filter tabs -->
		<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:14px;">
			<div style="display:flex;gap:4px;flex-wrap:wrap;">
				<?php foreach ( $tg_filters as $tg_key => $tg_label ) : ?>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-traffic&filter=' . $tg_key ) ); ?>"
						class="button <?php echo $tg_filter === $tg_key ? 'button-primary' : ''; ?>"
						style="font-size:12px;height:28px;line-height:26px;padding:0 12px;">
						<?php echo esc_html( $tg_label ); ?>
					</a>
				<?php endforeach; ?>
			</div>
			<button id="turbo-guard-refresh-traffic" class="button" style="font-size:12px;height:28px;line-height:26px;">
				<span class="dashicons dashicons-update" style="font-size:14px;width:14px;height:14px;vertical-align:middle;margin-right:3px;"></span>
				<?php esc_html_e( 'Refresh', 'turbo-guard' ); ?>
			</button>
		</div>

		<?php if ( $tg_total_pages > 1 ) : ?>
		<div style="margin-bottom:12px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
			<span style="font-size:12px;color:#9ca3af;margin-right:6px;">
				<?php
				printf(
					/* translators: 1: current page number, 2: total page count, 3: total traffic row count */
					esc_html__( 'Page %1$d of %2$d (%3$d total)', 'turbo-guard' ),
					absint( $tg_paged ),
					absint( $tg_total_pages ),
					absint( $tg_total_count )
				);
				?>
			</span>
			<?php if ( $tg_paged > 1 ) : ?>
				<a href="<?php echo esc_url( add_query_arg( array( 'filter' => $tg_filter, 'paged' => $tg_paged - 1 ) ) ); ?>" class="button button-small">
					&laquo; <?php esc_html_e( 'Prev', 'turbo-guard' ); ?>
				</a>
			<?php endif; ?>
			<?php
			$tg_p_start = max( 1, $tg_paged - 2 );
			$tg_p_end   = min( $tg_total_pages, $tg_paged + 2 );
			for ( $tg_p = $tg_p_start; $tg_p <= $tg_p_end; $tg_p++ ) :
				?>
				<a href="<?php echo esc_url( add_query_arg( array( 'filter' => $tg_filter, 'paged' => $tg_p ) ) ); ?>"
					class="button button-small <?php echo $tg_p === $tg_paged ? 'button-primary' : ''; ?>">
					<?php echo absint( $tg_p ); ?>
				</a>
			<?php endfor; ?>
			<?php if ( $tg_paged < $tg_total_pages ) : ?>
				<a href="<?php echo esc_url( add_query_arg( array( 'filter' => $tg_filter, 'paged' => $tg_paged + 1 ) ) ); ?>" class="button button-small">
					<?php esc_html_e( 'Next', 'turbo-guard' ); ?> &raquo;
				</a>
			<?php endif; ?>
		</div>
		<?php endif; ?>

		<?php if ( ! empty( $tg_rows ) ) : ?>
			<table class="turbo-guard-results-table">
				<thead>
					<tr>
						<th style="width:130px;"><?php esc_html_e( 'Time', 'turbo-guard' ); ?></th>
						<th style="width:120px;"><?php esc_html_e( 'IP', 'turbo-guard' ); ?></th>
						<th style="width:60px;"><?php esc_html_e( 'Type', 'turbo-guard' ); ?></th>
						<th style="width:55px;"><?php esc_html_e( 'Method', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'URL', 'turbo-guard' ); ?></th>
						<th style="width:55px;"><?php esc_html_e( 'Status', 'turbo-guard' ); ?></th>
						<th style="width:140px;"><?php esc_html_e( 'User Agent', 'turbo-guard' ); ?></th>
						<th style="width:80px;"><?php esc_html_e( 'Actions', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $tg_rows as $tg_row ) : ?>
						<?php
						$tg_status       = (int) $tg_row->status_code;
						$tg_status_color = $tg_status >= 500 ? '#dc2626' : ( $tg_status >= 400 ? '#d97706' : '#16a34a' );
						$tg_row_bg       = 403 === $tg_status ? 'background:#fff8f8;' : '';
						?>
						<tr style="<?php echo esc_attr( $tg_row_bg ); ?>">
							<td style="font-size:11px;color:#9ca3af;white-space:nowrap;">
								<?php
								echo esc_html(
									human_time_diff( strtotime( $tg_row->created_at ), current_time( 'timestamp' ) )
									/* translators: suffix after human time diff, e.g. "5 minutes ago" */
									. ' ' . __( 'ago', 'turbo-guard' )
								);
								?>
							</td>
							<td style="font-family:monospace;font-size:11px;">
								<?php echo esc_html( $tg_row->ip_address ); ?>
								<?php if ( $tg_row->user_id ) : ?>
									<br><small style="color:#9ca3af;">
										<?php
										$tg_ud = get_userdata( $tg_row->user_id );
										echo $tg_ud ? esc_html( $tg_ud->user_login ) : '';
										?>
									</small>
								<?php endif; ?>
							</td>
							<td>
								<?php if ( $tg_row->is_bot ) : ?>
									<span class="turbo-guard-badge" style="background:#f3f4f6;color:#6b7280;border-color:#e5e7eb;font-size:9px;">
										<?php echo esc_html( $tg_row->bot_name ? $tg_row->bot_name : __( 'Bot', 'turbo-guard' ) ); ?>
									</span>
								<?php else : ?>
									<span class="turbo-guard-badge" style="background:#f0fdf4;color:#16a34a;border-color:#bbf7d0;font-size:9px;">
										<?php esc_html_e( 'Human', 'turbo-guard' ); ?>
									</span>
								<?php endif; ?>
							</td>
							<td style="font-size:11px;font-weight:600;">
								<code style="background:#f3f4f6;padding:1px 4px;border-radius:3px;font-size:10px;">
									<?php echo esc_html( $tg_row->method ); ?>
								</code>
							</td>
							<td style="font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
								title="<?php echo esc_attr( $tg_row->request_uri ); ?>">
								<?php echo esc_html( $tg_row->request_uri ); ?>
							</td>
							<td style="font-weight:700;font-size:12px;color:<?php echo esc_attr( $tg_status_color ); ?>;">
								<?php echo absint( $tg_status ); ?>
							</td>
							<td style="font-size:10px;color:#9ca3af;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
								title="<?php echo esc_attr( $tg_row->user_agent ); ?>">
								<?php echo esc_html( substr( $tg_row->user_agent, 0, 60 ) ); ?>
							</td>
							<td>
								<button class="button button-small turbo-guard-block-traffic-ip"
									data-ip="<?php echo esc_attr( $tg_row->ip_address ); ?>"
									data-nonce="<?php echo esc_attr( wp_create_nonce( 'turbo_guard_admin' ) ); ?>"
									style="font-size:10px;height:22px;line-height:20px;padding:0 8px;color:#dc2626;border-color:#fca5a5;">
									<?php esc_html_e( 'Block', 'turbo-guard' ); ?>
								</button>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<!-- Bottom pagination -->
			<?php if ( $tg_total_pages > 1 ) : ?>
				<div style="margin-top:12px;display:flex;align-items:center;gap:6px;justify-content:center;flex-wrap:wrap;">
					<?php if ( $tg_paged > 1 ) : ?>
						<a href="<?php echo esc_url( add_query_arg( array( 'filter' => $tg_filter, 'paged' => $tg_paged - 1 ) ) ); ?>" class="button button-small">
							&laquo; <?php esc_html_e( 'Prev', 'turbo-guard' ); ?>
						</a>
					<?php endif; ?>
					<?php
					$tg_bp_start = max( 1, $tg_paged - 2 );
					$tg_bp_end   = min( $tg_total_pages, $tg_paged + 2 );
					for ( $tg_bp = $tg_bp_start; $tg_bp <= $tg_bp_end; $tg_bp++ ) :
						?>
						<a href="<?php echo esc_url( add_query_arg( array( 'filter' => $tg_filter, 'paged' => $tg_bp ) ) ); ?>"
							class="button button-small <?php echo $tg_bp === $tg_paged ? 'button-primary' : ''; ?>">
							<?php echo absint( $tg_bp ); ?>
						</a>
					<?php endfor; ?>
					<?php if ( $tg_paged < $tg_total_pages ) : ?>
						<a href="<?php echo esc_url( add_query_arg( array( 'filter' => $tg_filter, 'paged' => $tg_paged + 1 ) ) ); ?>" class="button button-small">
							<?php esc_html_e( 'Next', 'turbo-guard' ); ?> &raquo;
						</a>
					<?php endif; ?>
				</div>
			<?php endif; ?>

		<?php else : ?>
			<div class="turbo-guard-no-scan">
				<span class="dashicons dashicons-chart-area"></span>
				<p>
					<?php
					if ( 'all' === $tg_filter ) {
						esc_html_e( 'No traffic logged yet. Traffic logging is active and will populate as visitors arrive.', 'turbo-guard' );
					} else {
						esc_html_e( 'No matching traffic requests found for this filter.', 'turbo-guard' );
					}
					?>
				</p>
			</div>
		<?php endif; ?>
	</div>

</div>

<script>
jQuery(document).ready(function($) {
	$('#turbo-guard-refresh-traffic').on('click', function() { location.reload(); });

	$(document).on('click', '.turbo-guard-block-traffic-ip', function() {
		var ip    = $(this).data('ip');
		var nonce = $(this).data('nonce');
		if ( ! ip || ! window.confirm( 'Block IP ' + ip + '?' ) ) return;
		var $btn = $(this).prop('disabled', true).text('Blocking...');
		$.post( ajaxurl, { action: 'turbo_guard_block_ip', nonce: nonce, ip_address: ip }, function(r) {
			if ( r.success ) {
				$btn.text( 'Blocked' ).css( 'color', '#16a34a' );
			} else {
				$btn.prop( 'disabled', false ).text( 'Block' );
				alert( r.data ? r.data.message : 'Error' );
			}
		});
	});
});
</script>
