<?php
/**
 * Admin Notices.
 *
 * Displays dismissible admin notice banners inside the Turbo Guard dashboard.
 *
 * LOCAL-ONLY: this class makes no external HTTP requests. It does not fetch
 * any remote JSON feed and never contacts a third-party server. Notices are
 * expected to be registered locally by the plugin itself; `get_notices()`
 * currently returns an empty array (no notices are shipped with the plugin).
 * The dismiss AJAX handler and render hook point remain available so local
 * notices can be rendered later without any network dependency.
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
	 * Always returns an empty array — no remote feed exists and no local
	 * notices are currently registered. No network request is ever made.
	 *
	 * @since 1.3.0
	 * @return array Array of notice arrays (always empty).
	 */
	public function get_notices() {
		return array();
	}

	/**
	 * Return notices that should be shown to the current user right now.
	 *
	 * Local-only: delegates to `get_notices()`, which is always empty.
	 *
	 * @since 1.3.0
	 * @return array Filtered, active notices (always empty).
	 */
	public function get_active_notices() {
		return $this->get_notices();
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
		$notice_id = isset( $_POST['notice_id'] ) ? sanitize_key( $_POST['notice_id'] ) : '';

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
