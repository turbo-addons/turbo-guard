<?php
/**
 * Remote Notification System.
 *
 * Fetches a JSON feed from turbo-addons.com every 5 minutes (testing) and
 * displays targeted, dismissible promotion/notice banners inside the Turbo
 * Guard admin dashboard — with zero plugin releases required.
 *
 * HOW IT WORKS:
 *  1. On any Turbo Guard admin page load, this class checks a WP transient.
 *  2. If expired (or first run), it does wp_remote_get() to your server JSON.
 *  3. Notices are filtered by: target segment, expiry date, and dismissed status.
 *  4. Matching notices render inside the plugin dashboard (not WordPress-wide).
 *  5. Admin clicks "×" → AJAX → user meta saved → notice never shows again.
 *
 * SEGMENTATION supported (evaluated locally — no data sent to server):
 *  - "all"            → shown to everyone
 *  - "free"           → shown only when no PRO licence key is saved
 *  - "pro"            → shown only when a PRO licence key IS saved
 *  - "new_users"      → activated within the last 30 days
 *  - "aged_users"     → activated more than 90 days ago
 *  - "low_score"      → current security score < 70
 *  - "behavior"       → matches a behavior rule evaluated locally
 *
 * @package TurboGuard
 * @since   1.3.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turbo_Guard_Notices — remote notification manager.
 *
 * @since 1.3.0
 */
class Turbo_Guard_Notices {

	/**
	 * Remote endpoint — the per-plugin JSON feed on turbo-addons.com.
	 *
	 * @var string
	 */
	const REMOTE_URL = 'https://turbo-addons.com/turbo-guard-notifications/turbo-guard.json';

	/**
	 * How often (seconds) to re-fetch the remote JSON when fetch succeeds.
	 * 300 = 5 minutes for testing. Change to 43200 (12 hours) for production.
	 *
	 * @var int
	 */
	const CACHE_TTL = 300;

	/**
	 * How long (seconds) to wait before retrying after a failed fetch.
	 * Short so users aren't stuck waiting after a transient network glitch.
	 *
	 * @var int
	 */
	const ERROR_TTL = 60;

	/**
	 * WordPress transient key for cached notices.
	 *
	 * @var string
	 */
	const TRANSIENT_KEY = 'turbo_guard_remote_notices';

	/**
	 * Separate transient to track fetch errors (avoids caching [] as "valid").
	 *
	 * @var string
	 */
	const ERROR_TRANSIENT_KEY = 'turbo_guard_notices_fetch_error';

	/**
	 * Option key storing the plugin version that last fetched notices.
	 * Used to force-refresh on plugin update.
	 *
	 * @var string
	 */
	const VERSION_KEY = 'turbo_guard_notices_version';

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
		// Force cache refresh on plugin update so existing users immediately
		// see any campaigns published while they were on the old version.
		$this->maybe_flush_on_upgrade();

		// Show notices only on our own plugin pages.
		add_action( 'turbo_guard_after_header', array( $this, 'render_notices' ) );

		// AJAX: dismiss a notice.
		add_action( 'wp_ajax_turbo_guard_dismiss_notice', array( $this, 'ajax_dismiss_notice' ) );

		// AJAX: flush notification cache.
		add_action( 'wp_ajax_turbo_guard_flush_notices', array( $this, 'ajax_flush_notices' ) );
	}

	// =========================================================
	// UPGRADE-AWARE CACHE MANAGEMENT
	// =========================================================

	/**
	 * If the plugin version changed since last fetch, flush the transient
	 * so the next page load gets a fresh JSON feed. This guarantees that
	 * existing users who update the plugin will immediately receive any
	 * campaigns that were published while they were on an older version.
	 *
	 * @since 1.3.1
	 */
	private function maybe_flush_on_upgrade() {
		$stored_version = get_option( self::VERSION_KEY, '' );

		if ( $stored_version !== TURBO_GUARD_VERSION ) {
			// Plugin was just updated (or fresh install). Flush notice cache.
			delete_transient( self::TRANSIENT_KEY );
			delete_transient( self::ERROR_TRANSIENT_KEY );
			update_option( self::VERSION_KEY, TURBO_GUARD_VERSION, false );
		}
	}

	// =========================================================
	// FETCH & CACHE
	// =========================================================

	/**
	 * Get notices — from transient cache or remote server.
	 *
	 * Logic:
	 *  - If transient has valid cached notices → return them.
	 *  - If transient is expired AND no error cooldown → fetch fresh.
	 *  - If error cooldown is active → return empty (don't hammer server).
	 *
	 * @since 1.3.0
	 * @return array Array of notice objects (may be empty).
	 */
	public function get_notices() {
		// Opt-in check: do not phone home unless user explicitly enabled remote notices.
		$settings = get_option( 'turbo_guard_settings', array() );
		if ( empty( $settings['enable_remote_notices'] ) ) {
			return array();
		}

		// 1. Try cached notices first.
		$cached = get_transient( self::TRANSIENT_KEY );

		if ( is_array( $cached ) && ! empty( $cached ) ) {
			// Check for our "empty but valid" sentinel — means server had no notices.
			if ( isset( $cached['__empty'] ) ) {
				return array();
			}
			// We have valid cached notices.
			return $cached;
		}

		// 2. If we recently failed, don't retry yet (avoid hammering the server).
		if ( get_transient( self::ERROR_TRANSIENT_KEY ) ) {
			return array();
		}

		// 3. Cache is expired or empty — fetch fresh from the server.
		return $this->fetch_remote_notices();
	}

	/**
	 * Fetch fresh notices from the remote JSON endpoint.
	 * On success: stores notices in transient with full CACHE_TTL.
	 * On failure: sets a short error cooldown, does NOT cache empty as "valid".
	 *
	 * @since 1.3.0
	 * @return array
	 */
	private function fetch_remote_notices() {
		$response = wp_remote_get(
			self::REMOTE_URL,
			array(
				'timeout'    => 8,
				'sslverify'  => true,
				'user-agent' => 'TurboGuard/' . TURBO_GUARD_VERSION . '; ' . home_url(),
			)
		);

		// Network error — set error cooldown, don't cache empty as valid.
		if ( is_wp_error( $response ) ) {
			set_transient( self::ERROR_TRANSIENT_KEY, 'error', self::ERROR_TTL );
			return array();
		}

		$code = wp_remote_retrieve_response_code( $response );

		// Non-200 response (404, 500, etc.) — set error cooldown.
		if ( 200 !== (int) $code ) {
			set_transient( self::ERROR_TRANSIENT_KEY, 'http_' . $code, self::ERROR_TTL );
			return array();
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		// Valid response but no notices — cache empty for normal TTL.
		// This is different from a failed fetch: the server responded OK
		// but there are genuinely no active campaigns right now.
		if ( ! is_array( $data ) || empty( $data['notices'] ) ) {
			// Store a sentinel so we know "fetch succeeded, nothing active".
			set_transient( self::TRANSIENT_KEY, array( '__empty' => true ), self::CACHE_TTL );
			return array();
		}

		// Success! Cache the notices for the full TTL.
		$notices = $data['notices'];
		set_transient( self::TRANSIENT_KEY, $notices, self::CACHE_TTL );

		// Clear any lingering error state.
		delete_transient( self::ERROR_TRANSIENT_KEY );

		return $notices;
	}

	// =========================================================
	// FILTERING & SEGMENTATION
	// =========================================================

	/**
	 * Return notices that should be shown to the current user right now.
	 * Maximum 1 notice shown at a time — highest priority first.
	 * Priority order: warning > promotion > info > success
	 *
	 * @since 1.3.0
	 * @return array Filtered, active notices (max 1).
	 */
	public function get_active_notices() {
		$all       = $this->get_notices();
		$dismissed = $this->get_dismissed_ids();
		$active    = array();

		foreach ( $all as $notice ) {
			if ( empty( $notice['id'] ) ) continue;
			if ( in_array( $notice['id'], $dismissed, true ) ) continue;

			if ( ! empty( $notice['expires'] ) ) {
				$expires_ts = strtotime( $notice['expires'] );
				if ( false !== $expires_ts && current_time( 'timestamp' ) > $expires_ts ) continue;
			}

			if ( ! $this->user_matches_segment( $notice ) ) continue;

			$active[] = $notice;
		}

		if ( empty( $active ) ) {
			return array();
		}

		// Sort by priority: warning first, then promotion, info, success.
		$priority = [ 'warning' => 0, 'promotion' => 1, 'info' => 2, 'success' => 3 ];
		usort( $active, function( $a, $b ) use ( $priority ) {
			$pa = $priority[ $a['type'] ?? 'info' ] ?? 2;
			$pb = $priority[ $b['type'] ?? 'info' ] ?? 2;
			return $pa - $pb;
		} );

		// Return only the highest priority notice.
		return [ $active[0] ];
	}

	/**
	 * Evaluate whether the current site/user matches a notice's segment.
	 *
	 * @since 1.3.0
	 * @param array $notice Notice data array.
	 * @return bool
	 */
	private function user_matches_segment( array $notice ) {
		$target = isset( $notice['target'] ) ? $notice['target'] : 'all';

		// ------------------------------------------------------------------
		// Domain targeting — if notice has a "domains" array, only show it
		// on sites whose home_url matches one of the listed domains.
		// This lets you target akijlogistics.com without affecting others.
		// ------------------------------------------------------------------
		if ( ! empty( $notice['domains'] ) && is_array( $notice['domains'] ) ) {
			$current_host = wp_parse_url( home_url(), PHP_URL_HOST );
			// Strip www. prefix for loose matching.
			$current_host = preg_replace( '/^www\./i', '', (string) $current_host );
			$matched      = false;

			foreach ( $notice['domains'] as $domain ) {
				$domain = preg_replace( '/^www\./i', '', strtolower( trim( $domain ) ) );
				if ( $domain === strtolower( $current_host ) ) {
					$matched = true;
					break;
				}
			}

			if ( ! $matched ) {
				return false;
			}
		}

		switch ( $target ) {

			case 'all':
				return true;

			case 'free':
				return empty( get_option( 'turbo_guard_pro_license_key', '' ) );

			case 'pro':
				return ! empty( get_option( 'turbo_guard_pro_license_key', '' ) );

			case 'new_users':
				$activated = get_option( 'turbo_guard_activated_at', 0 );
				return $activated && ( time() - (int) $activated ) < ( 30 * DAY_IN_SECONDS );

			case 'aged_users':
				$activated = get_option( 'turbo_guard_activated_at', 0 );
				return $activated && ( time() - (int) $activated ) > ( 90 * DAY_IN_SECONDS );

			case 'low_score':
				$stats = Turbo_Guard_Settings::get_dashboard_stats();
				return isset( $stats['security_score'] ) && (int) $stats['security_score'] < 70;

			// ------------------------------------------------------------------
			// behavior: evaluated against locally tracked activity data.
			// Requires a "behavior_rule" field in the notice JSON.
			// All 14 rules are defined in Turbo_Guard_Activity::evaluate_rule().
			// ------------------------------------------------------------------
			case 'behavior':
				$rule = isset( $notice['behavior_rule'] ) ? sanitize_key( $notice['behavior_rule'] ) : '';
				if ( empty( $rule ) ) {
					return false; // No rule defined — skip notice.
				}
				return Turbo_Guard_Activity::evaluate_rule( $rule );

			default:
				return true;
		}
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
	 * Render a single notice banner.
	 *
	 * Supported notice types (controls colour/icon):
	 *  - "promotion"  → blue  (default for offers)
	 *  - "info"       → blue-grey
	 *  - "warning"    → amber
	 *  - "success"    → green
	 *
	 * @since 1.3.0
	 * @param array $notice Notice data.
	 */
	private function render_single_notice( array $notice ) {
		$id          = sanitize_key( $notice['id'] );
		$type        = isset( $notice['type'] ) ? sanitize_key( $notice['type'] ) : 'promotion';
		$title       = isset( $notice['title'] )   ? wp_kses_post( $notice['title'] )   : '';
		$message     = isset( $notice['message'] ) ? wp_kses_post( $notice['message'] ) : '';
		$cta_text    = isset( $notice['cta_text'] ) ? sanitize_text_field( $notice['cta_text'] ) : '';
		$cta_url     = isset( $notice['cta_url'] )  ? esc_url( $notice['cta_url'] )     : '';
		$dismissible = ! isset( $notice['dismissible'] ) || (bool) $notice['dismissible'];

		if ( empty( $message ) ) {
			return;
		}

		$icon_map = array(
			'promotion' => '🎁',
			'info'      => 'ℹ️',
			'warning'   => '⚠️',
			'success'   => '✅',
		);
		$icon = isset( $icon_map[ $type ] ) ? $icon_map[ $type ] : 'ℹ️';
		?>
		<div class="turbo-guard-remote-notice turbo-guard-remote-notice--<?php echo esc_attr( $type ); ?>"
		     data-notice-id="<?php echo esc_attr( $id ); ?>"
		     id="tg-notice-<?php echo esc_attr( $id ); ?>">

			<span class="tg-notice-icon"><?php echo $icon; // phpcs:ignore WordPress.Security.EscapeOutput ?></span>

			<div class="tg-notice-body">
				<?php if ( $title ) : ?>
					<strong class="tg-notice-title"><?php echo esc_html( $title ); ?></strong>
				<?php endif; ?>
				<span class="tg-notice-message"><?php echo wp_kses_post( $message ); ?></span>

				<?php if ( $cta_text && $cta_url ) : ?>
					<a href="<?php echo esc_url( $cta_url ); ?>"
					   class="tg-notice-cta button button-primary button-small"
					   target="_blank" rel="noopener noreferrer">
						<?php echo esc_html( $cta_text ); ?>
					</a>
				<?php endif; ?>
			</div>

			<?php if ( $dismissible ) : ?>
				<button class="tg-notice-dismiss"
				        data-notice-id="<?php echo esc_attr( $id ); ?>"
				        data-nonce="<?php echo esc_attr( wp_create_nonce( 'tg_dismiss_notice_' . $id ) ); ?>"
				        aria-label="<?php esc_attr_e( 'Dismiss this notice', 'turbo-guard-security-malware-scanner' ); ?>">
					&times;
				</button>
			<?php endif; ?>

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

	// =========================================================
	// UTILITY (for manual cache refresh from admin)
	// =========================================================

	/**
	 * AJAX handler: flush notification cache for the current site.
	 * Safe — only deletes a transient, no data loss.
	 *
	 * @since 1.3.0
	 */
	public function ajax_flush_notices() {
		check_ajax_referer( 'turbo_guard_flush_notices', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ) );
		}

		self::flush_cache();

		wp_send_json_success( array( 'message' => 'Notification cache cleared. Refresh the page to see the latest campaigns.' ) );
	}

	/**
	 * Force-delete the cached notices transient.
	 *
	 * @since 1.3.0
	 */
	public static function flush_cache() {
		delete_transient( self::TRANSIENT_KEY );
		delete_transient( self::ERROR_TRANSIENT_KEY );
	}
}
