<?php
/**
 * Pro Feature Upsell Page.
 *
 * Shown for locked Pro features when only the free version is active.
 *
 * @package TurboGuard
 * @since 2.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$turbo_guard_feature_names = array(
	'turbo-guard-pro-live-traffic' => __( 'Live Traffic Monitor', 'turbo-guard' ),
	'turbo-guard-pro-ai-advisor'   => __( 'AI Security Advisor', 'turbo-guard' ),
);

$turbo_guard_feature_name = isset( $turbo_guard_feature_names[ $turbo_guard_pro_feature ] ) ? $turbo_guard_feature_names[ $turbo_guard_pro_feature ] : __( 'this Turbo Guard Pro feature', 'turbo-guard' );
?>
<div class="wrap turbo-guard-upsell">

	<div class="turbo-guard-page-header" style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 50%,#7c3aed 100%);">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon" style="background:rgba(255,255,255,.2);">
				<span class="dashicons dashicons-lock"></span>
			</div>
			<div>
				<h1><?php echo esc_html( $turbo_guard_feature_name ); ?></h1>
				<p><?php esc_html_e( 'This is a Turbo Guard Pro feature.', 'turbo-guard' ); ?></p>
			</div>
		</div>
		<span class="turbo-guard-header-badge"><?php esc_html_e( 'Pro', 'turbo-guard' ); ?></span>
	</div>

	<div class="turbo-guard-card">
		<h2><?php esc_html_e( 'Unlock the full security suite', 'turbo-guard' ); ?></h2>
		<p><?php esc_html_e( 'Upgrade to Turbo Guard Pro to get every feature below — on top of everything you already have for free.', 'turbo-guard' ); ?></p>

		<ul style="list-style:none;padding:0;margin:16px 0;">
			<li style="padding:8px 0;"><?php esc_html_e( '✅ Live Traffic Monitor — log every request, detect bots & AI crawlers', 'turbo-guard' ); ?></li>
			<li style="padding:8px 0;"><?php esc_html_e( '✅ AI Security Advisor — plain-English attack analysis & fix guides', 'turbo-guard' ); ?></li>
			<li style="padding:8px 0;"><?php esc_html_e( '✅ Geo-Fence — restrict wp-admin to trusted IPs & countries', 'turbo-guard' ); ?></li>
			<li style="padding:8px 0;"><?php esc_html_e( '✅ Unlimited malware cleanup — no per-action file limit', 'turbo-guard' ); ?></li>
			<li style="padding:8px 0;"><?php esc_html_e( '✅ Complete bot protection — 25+ scrapers, scanners & harvesters', 'turbo-guard' ); ?></li>
			<li style="padding:8px 0;"><?php esc_html_e( '✅ SEO spam removal — delete spam posts & fix hacked pages', 'turbo-guard' ); ?></li>
		</ul>

		<p>
			<a href="<?php echo esc_url( turbo_guard_pro_url() ); ?>" target="_blank" rel="noopener noreferrer" class="button button-primary button-large">
				<?php esc_html_e( 'Upgrade to Turbo Guard Pro', 'turbo-guard' ); ?>
			</a>
		</p>
	</div>

</div>
