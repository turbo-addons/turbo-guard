<?php
/**
 * Admin Notices.
 *
 * Displays dismissible admin notice banners inside the Turbo Guard dashboard.
 *
 * LOCAL-ONLY: this class makes no external HTTP requests. It does not fetch
 * any remote JSON feed and never contacts a third-party server. Notices are
 * registered locally in `get_notices()`, each with a fixed start/end time,
 * and are shown only to free users (never when Turbo Guard Pro is active).
 *
 * @package TurboGuard
 * @since   1.3.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turbo_Guard_Notices — local admin notice manager.
 *
 * No network requests are made anywhere in this class.
 *
 * @since 1.3.0
 */
class Turbo_Guard_Notices {

	/**
	 * WordPress option key for per-user dismissed notice IDs.
	 * Stored as user meta so each admin tracks their own dismissals.
	 *
	 * @var string
	 */
	const DISMISSED_META_KEY = 'turbo_guard_dismissed_notices';

	/**
	 * Singleton instance.
	 *
	 * @var Turbo_Guard_Notices|null
	 */
	private static $instance = null;

	/**
	 * Get singleton instance.
	 *
	 * @since 1.3.0
	 * @return Turbo_Guard_Notices
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor — registers hooks.
	 *
	 * @since 1.3.0
	 */
	private function __construct() {
		// Show notices only on our own plugin pages.
		add_action( 'turbo_guard_after_header', array( $this, 'render_notices' ) );

		// AJAX: dismiss a notice.
		add_action( 'wp_ajax_turbo_guard_dismiss_notice', array( $this, 'ajax_dismiss_notice' ) );
	}

	// =========================================================
	// NOTICE SOURCE
	// =========================================================

	/**
	 * Get all local notices.
	 *
	 * Each notice: id, type, title, message, code (optional promo code),
	 * cta_text, cta_url, start / end (UTC timestamps). No network request.
	 *
	 * @since 1.3.0
	 * @since 1.1.8 Black Friday / Cyber Monday 2026 offer.
	 * @return array Array of notice arrays.
	 */
	public function get_notices() {
		$notices = array(
			array(
				'id'       => 'bfcm2026',
				'type'     => 'blackfriday',
				'eyebrow'  => __( 'Black Friday · Cyber Monday', 'turbo-guard' ),
				'badge'    => __( '50% OFF', 'turbo-guard' ),
				'title'    => __( 'Is this site protected? Free malware scan with Turbo Guard — 50% off this Friday', 'turbo-guard' ),
				'message'  => __( 'Black Friday: get 50% off Turbo Guard Pro for unlimited cleanup, Live Traffic, AI Security Advisor and Geo-Fence. Use code', 'turbo-guard' ),
				'code'     => 'FSBFCM2026',
				'cta_text' => __( 'Get 50% Off Pro', 'turbo-guard' ),
				'cta_url'  => add_query_arg(
					array(
						'utm_source'   => 'plugin',
						'utm_medium'   => 'dashboard-notice',
						'utm_campaign' => 'bfcm2026',
					),
					turbo_guard_pro_url()
				),
				// Shown until the end of Cyber Monday (30 Nov 2026) in every time zone.
				'start'    => gmmktime( 0, 0, 0, 11, 1, 2026 ),
				'end'      => gmmktime( 23, 59, 59, 12, 1, 2026 ),
			),
		);

		/**
		 * Filter the local notice list.
		 *
		 * @since 1.1.8
		 * @param array $notices Notice arrays.
		 */
		return (array) apply_filters( 'turbo_guard_notices', $notices );
	}

	/**
	 * Return notices that should be shown to the current user right now.
	 *
	 * Promotions are for free users only: nothing is shown when Pro is
	 * active. Notices outside their time window, or dismissed by this user,
	 * are skipped.
	 *
	 * @since 1.3.0
	 * @return array Filtered, active notices.
	 */
	public function get_active_notices() {
		if ( turbo_guard_is_pro() || ! current_user_can( 'manage_options' ) ) {
			return array();
		}

		$now       = time();
		$dismissed = $this->get_dismissed_ids();
		$active    = array();

		foreach ( $this->get_notices() as $notice ) {
			if ( empty( $notice['id'] ) || in_array( $notice['id'], $dismissed, true ) ) {
				continue;
			}
			if ( ! empty( $notice['start'] ) && $now < (int) $notice['start'] ) {
				continue;
			}
			if ( ! empty( $notice['end'] ) && $now > (int) $notice['end'] ) {
				continue;
			}
			$active[] = $notice;
		}

		return $active;
	}

	// =========================================================
	// DISMISSED NOTICE TRACKING
	// =========================================================

	/**
	 * Get array of notice IDs already dismissed by the current user.
	 *
	 * @since 1.3.0
	 * @return string[]
	 */
	private function get_dismissed_ids() {
		$user_id   = get_current_user_id();
		$dismissed = get_user_meta( $user_id, self::DISMISSED_META_KEY, true );
		return is_array( $dismissed ) ? $dismissed : array();
	}

	/**
	 * Mark a notice as dismissed for the current user.
	 *
	 * @since 1.3.0
	 * @param string $notice_id Notice ID to dismiss.
	 * @return void
	 */
	public function dismiss_notice( $notice_id ) {
		$user_id   = get_current_user_id();
		$dismissed = $this->get_dismissed_ids();

		if ( ! in_array( $notice_id, $dismissed, true ) ) {
			$dismissed[] = sanitize_key( $notice_id );
			update_user_meta( $user_id, self::DISMISSED_META_KEY, $dismissed );
		}
	}

	// =========================================================
	// RENDER
	// =========================================================

	/**
	 * Render all active notices in the dashboard.
	 * Called via the `turbo_guard_after_header` action hook
	 * which you place in each admin view template.
	 *
	 * @since 1.3.0
	 */
	public function render_notices() {
		$notices = $this->get_active_notices();

		if ( empty( $notices ) ) {
			return;
		}

		foreach ( $notices as $notice ) {
			$this->render_single_notice( $notice );
		}
	}

	/**
	 * Render one notice banner.
	 *
	 * @since 1.1.8
	 * @param array $notice Notice array from get_notices().
	 */
	private function render_single_notice( $notice ) {
		$id   = sanitize_key( $notice['id'] );
		$type = isset( $notice['type'] ) ? sanitize_key( $notice['type'] ) : 'info';
		?>
		<div id="tg-notice-<?php echo esc_attr( $id ); ?>" class="turbo-guard-remote-notice turbo-guard-remote-notice--<?php echo esc_attr( $type ); ?>" role="region" aria-label="<?php esc_attr_e( 'Turbo Guard offer', 'turbo-guard' ); ?>">
			<?php if ( ! empty( $notice['badge'] ) ) : ?>
				<span class="tg-notice-badge"><?php echo esc_html( $notice['badge'] ); ?></span>
			<?php else : ?>
				<span class="tg-notice-icon dashicons dashicons-shield-alt" aria-hidden="true"></span>
			<?php endif; ?>
			<div class="tg-notice-body">
				<?php if ( ! empty( $notice['eyebrow'] ) ) : ?>
					<span class="tg-notice-eyebrow"><?php echo esc_html( $notice['eyebrow'] ); ?></span>
				<?php endif; ?>
				<span class="tg-notice-title"><?php echo esc_html( $notice['title'] ); ?></span>
				<span class="tg-notice-message">
					<?php echo esc_html( $notice['message'] ); ?>
					<?php if ( ! empty( $notice['code'] ) ) : ?>
						<code class="tg-notice-code"><?php echo esc_html( $notice['code'] ); ?></code>
					<?php endif; ?>
				</span>
				<?php if ( ! empty( $notice['cta_url'] ) ) : ?>
					<a class="button button-primary tg-notice-cta" href="<?php echo esc_url( $notice['cta_url'] ); ?>" target="_blank" rel="noopener noreferrer">
						<?php echo esc_html( $notice['cta_text'] ); ?>
					</a>
				<?php endif; ?>
			</div>
			<button type="button" class="tg-notice-dismiss"
				data-notice-id="<?php echo esc_attr( $id ); ?>"
				data-nonce="<?php echo esc_attr( wp_create_nonce( 'tg_dismiss_notice_' . $id ) ); ?>"
				aria-label="<?php esc_attr_e( 'Dismiss this offer', 'turbo-guard' ); ?>">&times;</button>
		</div>
		<?php
	}

	// =========================================================
	// AJAX
	// =========================================================

	/**
	 * AJAX handler: dismiss a notice for the current user.
	 *
	 * @since 1.3.0
	 */
	public function ajax_dismiss_notice() {
		$notice_id = isset( $_POST['notice_id'] ) ? sanitize_key( wp_unslash( $_POST['notice_id'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified below.

		if ( ! $notice_id ) {
			wp_send_json_error( array( 'message' => 'Missing notice ID.' ) );
		}

		// Verify nonce tied to this specific notice ID.
		if ( ! check_ajax_referer( 'tg_dismiss_notice_' . $notice_id, 'nonce', false ) ) {
			wp_send_json_error( array( 'message' => 'Security check failed.' ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ) );
		}

		$this->dismiss_notice( $notice_id );

		wp_send_json_success( array( 'notice_id' => $notice_id ) );
	}
}
