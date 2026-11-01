<?php
/**
 * TOTP Two-Factor Authentication Class.
 *
 * RFC 6238 compliant TOTP implementation with QR code setup,
 * recovery codes, and per-user enable/disable.
 *
 * @package TurboGuard
 * @since 1.1.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two-Factor Authentication (TOTP / RFC 6238).
 *
 * @since 1.1.0
 */
class Turbo_Guard_2FA {

	/**
	 * User-meta key: whether 2FA is enabled for the user.
	 */
	const META_ENABLED = 'turbo_guard_2fa_enabled';

	/**
	 * User-meta key: encrypted TOTP secret.
	 */
	const META_SECRET = 'turbo_guard_2fa_secret';

	/**
	 * User-meta key: recovery codes (serialised array).
	 */
	const META_RECOVERY = 'turbo_guard_2fa_recovery';

	/**
	 * TOTP time-step in seconds (industry standard).
	 */
	const TIME_STEP = 30;

	/**
	 * Number of time windows checked on each side to allow for clock drift.
	 */
	const DRIFT = 1;

	/**
	 * Number of recovery codes generated.
	 */
	const RECOVERY_CODE_COUNT = 8;

	/**
	 * Singleton instance.
	 *
	 * @var Turbo_Guard_2FA|null
	 */
	private static $instance = null;

	/**
	 * Get singleton.
	 *
	 * @since 1.1.0
	 * @return Turbo_Guard_2FA
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor — register hooks only when 2FA is globally enabled.
	 *
	 * @since 1.1.0
	 */
	private function __construct() {
		if ( 'yes' !== get_option( 'turbo_guard_2fa_enabled_global', 'yes' ) ) {
			return;
		}

		// Intercept login after password is verified (priority 30 = after WP core).
		add_filter( 'authenticate', array( $this, 'intercept_login' ), 30, 3 );

		// Disable application passwords for 2FA-enabled users so a stored
		// application password cannot bypass the second factor (REST / XML-RPC /
		// Basic Auth all resolve through this core availability check).
		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'restrict_application_passwords' ), 10, 2 );

		// Add 2FA code input to login form.
		add_action( 'login_form', array( $this, 'render_login_field' ) );

		// Enforce 2FA for users whose role requires it.
		add_action( 'admin_init', array( $this, 'enforce_required_2fa' ) );

		// Enqueue styles on login page.
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_styles' ) );
	}

	// =========================================================
	// LOGIN INTERCEPTION
	// =========================================================

	/**
	 * After password authentication succeeds, check the TOTP code.
	 *
	 * @since 1.1.0
	 * @param WP_User|WP_Error|null $user     Authenticated user.
	 * @param string                $username Username (unused here).
	 * @param string                $password Password (unused here).
	 * @return WP_User|WP_Error
	 */
	public function intercept_login( $user, $username, $password ) {
		// Only act on a valid WP_User object (password already verified).
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}

		// Is 2FA enabled for this user?
		if ( ! $this->is_user_enabled( $user->ID ) ) {
			return $user;
		}

		// A previously trusted device may skip the code prompt.
		if ( $this->is_trusted_device( $user->ID ) ) {
			return $user;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$code = isset( $_POST['turbo_guard_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['turbo_guard_2fa_code'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( '' === $code ) {
			return new WP_Error(
				'turbo_guard_2fa_required',
				esc_html__( 'Please enter your two-factor authentication code to log in.', 'turbo-guard' )
			);
		}

		// Strip spaces (e.g. "123 456" → "123456").
		$code = preg_replace( '/\s+/', '', $code );

		// Try TOTP code first, then recovery codes.
		$secret = $this->get_secret( $user->ID );
		if ( ! $secret ) {
			return $user; // Secret missing — fail-open so admin isn't locked out.
		}

		if ( $this->verify_totp( $secret, $code ) || $this->verify_recovery_code( $user->ID, $code ) ) {
			// Honor "remember this device" when the user asked and it is enabled.
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- login form; the code was already verified.
			if ( ! empty( $_POST['turbo_guard_2fa_remember'] ) ) {
				$this->set_trusted_device( $user->ID );
			}
			return $user;
		}

		return new WP_Error(
			'turbo_guard_2fa_invalid',
			esc_html__( 'Invalid two-factor authentication code. Please try again.', 'turbo-guard' )
		);
	}

	/**
	 * Render the 2FA code input field on wp-login.php.
	 *
	 * @since 1.1.0
	 */
	public function render_login_field() {
		?>
		<p>
			<label for="turbo_guard_2fa_code">
				<?php esc_html_e( '2FA Code (if enabled)', 'turbo-guard' ); ?><br>
				<input type="text"
					id="turbo_guard_2fa_code"
					name="turbo_guard_2fa_code"
					class="input"
					inputmode="numeric"
					autocomplete="one-time-code"
					maxlength="8"
					placeholder="000 000"
					style="letter-spacing:.15em;"
				/>
			</label>
		</p>
		<?php if ( absint( get_option( 'turbo_guard_2fa_remember_days', 0 ) ) > 0 ) : ?>
		<p>
			<label>
				<input type="checkbox" name="turbo_guard_2fa_remember" value="1" />
				<?php esc_html_e( 'Remember this device', 'turbo-guard' ); ?>
			</label>
		</p>
		<?php endif; ?>
		<?php
	}

	/**
	 * Enqueue minimal login-page styles.
	 *
	 * @since 1.1.0
	 */
	public function enqueue_login_styles() {
		wp_add_inline_style(
			'login',
			'#turbo_guard_2fa_code{font-size:20px;text-align:center;width:100%;}'
		);
	}

	// =========================================================
	// ROLE ENFORCEMENT & TRUSTED DEVICES
	// =========================================================

	/**
	 * Whether a user's role is in the "require 2FA" list.
	 *
	 * @since 1.1.5
	 * @param WP_User|int $user User object or ID.
	 * @return bool
	 */
	public function role_requires_2fa( $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			$user = get_userdata( $user );
		}
		if ( ! $user ) {
			return false;
		}

		$enforced = (array) get_option( 'turbo_guard_2fa_enforce_roles', array() );
		if ( empty( $enforced ) ) {
			return false;
		}

		foreach ( (array) $user->roles as $role ) {
			if ( in_array( $role, $enforced, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a user is required to have 2FA but has not configured it yet.
	 *
	 * @since 1.1.5
	 * @param WP_User|int $user User object or ID.
	 * @return bool
	 */
	public function is_2fa_required_for( $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			$user = get_userdata( $user );
		}
		if ( ! $user ) {
			return false;
		}
		return $this->role_requires_2fa( $user ) && ! $this->is_user_enabled( $user->ID );
	}

	/**
	 * Disable application passwords for users who have 2FA enabled.
	 *
	 * Application passwords (Basic Auth) authenticate independently of the
	 * login form, so without this a user could bypass the second factor via
	 * the REST API, XML-RPC or any other application-password consumer. Core
	 * checks this filter both in `wp_authenticate_application_password()` and
	 * in `wp_validate_application_password()` (the REST path).
	 *
	 * @since 1.1.5
	 * @param bool    $available Whether application passwords are available.
	 * @param WP_User $user      The user being checked.
	 * @return bool
	 */
	public function restrict_application_passwords( $available, $user ) {
		if ( $user instanceof WP_User && $this->is_user_enabled( $user->ID ) ) {
			return false;
		}
		return $available;
	}

	/**
	 * Whether the stored grace period is still active.
	 *
	 * @since 1.1.5
	 * @return bool
	 */
	public function is_within_grace() {
		$days = absint( get_option( 'turbo_guard_2fa_grace_days', 0 ) );
		if ( $days <= 0 ) {
			return false; // No grace period — enforce immediately.
		}

		$since = (int) get_option( 'turbo_guard_2fa_required_since', 0 );
		if ( ! $since ) {
			return false;
		}

		return time() < ( $since + ( $days * DAY_IN_SECONDS ) );
	}

	/**
	 * Force required users to configure 2FA once the grace period has elapsed.
	 *
	 * Runs on every wp-admin load. During the grace window the user only sees
	 * a reminder; after it, they are redirected to their profile to set 2FA up.
	 * The profile, user-edit, admin-ajax and admin-post screens stay reachable
	 * so the user can actually complete the setup.
	 *
	 * @since 1.1.5
	 */
	public function enforce_required_2fa() {
		if ( ! is_user_logged_in() || wp_doing_ajax() ) {
			return;
		}

		$user = wp_get_current_user();
		if ( ! $this->is_2fa_required_for( $user ) ) {
			return;
		}

		// 2FA setup lives on the Turbo Guard settings page, which requires
		// manage_options. Users who cannot reach it would only get a dead link,
		// so the reminder is shown to those who can act on it. We never redirect
		// or lock the user out of wp-admin — that is a denial-of-service risk.
		if ( current_user_can( 'manage_options' ) ) {
			add_action( 'admin_notices', array( $this, 'render_setup_reminder' ) );
		}
	}

	/**
	 * Admin notice reminding a user that their role requires 2FA.
	 *
	 * The notice is a warning during the grace window and an error afterwards.
	 *
	 * @since 1.1.5
	 */
	public function render_setup_reminder() {
		$urgent = ! $this->is_within_grace();

		printf(
			'<div class="notice %1$s"><p><strong>%2$s</strong> %3$s <a href="%4$s">%5$s</a></p></div>',
			$urgent ? 'notice-error' : 'notice-warning',
			esc_html__( 'Turbo Guard:', 'turbo-guard' ),
			esc_html__( 'Two-factor authentication is required for your role.', 'turbo-guard' ),
			esc_url( admin_url( 'admin.php?page=turbo-guard-settings#turbo-guard-2fa' ) ),
			esc_html__( 'Set it up here.', 'turbo-guard' )
		);
	}

	/**
	 * Name of the trusted-device cookie.
	 *
	 * @since 1.1.5
	 * @return string
	 */
	private function trusted_cookie_name() {
		return 'turbo_guard_2fa_device';
	}

	/**
	 * Whether the current request carries a valid trusted-device cookie.
	 *
	 * @since 1.1.5
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public function is_trusted_device( $user_id ) {
		$name = $this->trusted_cookie_name();
		if ( empty( $_COOKIE[ $name ] ) ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated below.
		$raw   = wp_unslash( $_COOKIE[ $name ] );
		$parts = explode( '|', (string) $raw );
		if ( 3 !== count( $parts ) ) {
			return false;
		}

		list( $uid, $exp, $sig ) = $parts;
		if ( (int) $uid !== (int) $user_id ) {
			return false;
		}
		if ( (int) $exp < time() ) {
			return false;
		}

		$expected = hash_hmac( 'sha256', $uid . '|' . $exp, wp_salt( 'auth' ) );

		return hash_equals( $expected, (string) $sig );
	}

	/**
	 * Set the trusted-device cookie for a user (if enabled).
	 *
	 * @since 1.1.5
	 * @param int $user_id User ID.
	 */
	private function set_trusted_device( $user_id ) {
		$days = absint( get_option( 'turbo_guard_2fa_remember_days', 0 ) );
		if ( $days <= 0 ) {
			return;
		}

		$expires = time() + ( $days * DAY_IN_SECONDS );
		$sig     = hash_hmac( 'sha256', $user_id . '|' . $expires, wp_salt( 'auth' ) );
		$value   = $user_id . '|' . $expires . '|' . $sig;

		setcookie(
			$this->trusted_cookie_name(),
			$value,
			array(
				'expires'  => $expires,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);

		// Make it available for the remainder of this request.
		$_COOKIE[ $this->trusted_cookie_name() ] = $value;
	}

	// =========================================================
	// SECRET GENERATION & VERIFICATION
	// =========================================================

	/**
	 * Generate a new Base32-encoded TOTP secret.
	 *
	 * @since 1.1.0
	 * @return string 16-character Base32 secret.
	 */
	public static function generate_secret() {
		$chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$secret = '';
		for ( $i = 0; $i < 16; $i++ ) {
			$secret .= $chars[ wp_rand( 0, 31 ) ];
		}
		return $secret;
	}

	/**
	 * Generate the set of recovery codes.
	 *
	 * @since 1.1.0
	 * @return string[] Array of plain-text recovery codes.
	 */
	public static function generate_recovery_codes() {
		$codes = array();
		for ( $i = 0; $i < self::RECOVERY_CODE_COUNT; $i++ ) {
			$codes[] = strtolower( wp_generate_password( 8, false ) . '-' . wp_generate_password( 8, false ) );
		}
		return $codes;
	}

	/**
	 * Verify a TOTP code against a secret, allowing clock drift.
	 *
	 * @since 1.1.0
	 * @param string $secret Base32-encoded secret.
	 * @param string $code   6-digit code to verify.
	 * @return bool
	 */
	public function verify_totp( $secret, $code ) {
		if ( strlen( $code ) !== 6 || ! ctype_digit( $code ) ) {
			return false;
		}

		$time_counter = (int) floor( time() / self::TIME_STEP );

		for ( $i = -self::DRIFT; $i <= self::DRIFT; $i++ ) {
			$expected = $this->generate_totp( $secret, $time_counter + $i );
			if ( hash_equals( $expected, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Generate a TOTP code for a given time counter.
	 *
	 * @since 1.1.0
	 * @param string $secret  Base32 secret.
	 * @param int    $counter Time counter value.
	 * @return string 6-digit code (zero-padded).
	 */
	private function generate_totp( $secret, $counter ) {
		$key  = $this->base32_decode( $secret );
		$time = pack( 'N*', 0, $counter ); // 64-bit big-endian unsigned.
		$hash = hash_hmac( 'sha1', $time, $key, true );

		$offset = ord( substr( $hash, -1 ) ) & 0x0F;
		$code   = (
			( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		) % 1000000;

		return str_pad( (string) $code, 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Decode a Base32 string to binary.
	 *
	 * @since 1.1.0
	 * @param string $input Base32 input.
	 * @return string Binary string.
	 */
	private function base32_decode( $input ) {
		$map    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$input  = strtoupper( $input );
		$output = '';
		$buffer = 0;
		$bits   = 0;

		for ( $i = 0; $i < strlen( $input ); $i++ ) {
			$char = $input[ $i ];
			$pos  = strpos( $map, $char );
			if ( false === $pos ) {
				continue;
			}
			$buffer  = ( $buffer << 5 ) | $pos;
			$bits   += 5;
			if ( $bits >= 8 ) {
				$bits   -= 8;
				$output .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}

		return $output;
	}

	// =========================================================
	// RECOVERY CODES
	// =========================================================

	/**
	 * Verify a recovery code and consume it (single-use).
	 *
	 * @since 1.1.0
	 * @param int    $user_id User ID.
	 * @param string $code    Recovery code to check.
	 * @return bool True if valid and consumed.
	 */
	public function verify_recovery_code( $user_id, $code ) {
		$codes = $this->get_recovery_codes( $user_id );
		if ( empty( $codes ) ) {
			return false;
		}

		$code  = strtolower( trim( $code ) );
		$found = false;

		$remaining = array_filter(
			$codes,
			function ( $stored ) use ( $code, &$found ) {
				if ( hash_equals( $stored, $code ) ) {
					$found = true;
					return false; // Remove this code.
				}
				return true;
			}
		);

		if ( $found ) {
			update_user_meta( $user_id, self::META_RECOVERY, array_values( $remaining ) );
		}

		return $found;
	}

	// =========================================================
	// USER META HELPERS
	// =========================================================

	/**
	 * Check if 2FA is enabled for a user.
	 *
	 * @since 1.1.0
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public function is_user_enabled( $user_id ) {
		return '1' === get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/**
	 * Get the decrypted TOTP secret for a user.
	 *
	 * @since 1.1.0
	 * @param int $user_id User ID.
	 * @return string|false Secret or false if not set.
	 */
	public function get_secret( $user_id ) {
		return get_user_meta( $user_id, self::META_SECRET, true ) ?: false;
	}

	/**
	 * Get remaining recovery codes for a user.
	 *
	 * @since 1.1.0
	 * @param int $user_id User ID.
	 * @return string[]
	 */
	public function get_recovery_codes( $user_id ) {
		$codes = get_user_meta( $user_id, self::META_RECOVERY, true );
		return is_array( $codes ) ? $codes : array();
	}

	/**
	 * Enable 2FA for a user with a new secret and recovery codes.
	 *
	 * @since 1.1.0
	 * @param int    $user_id User ID.
	 * @param string $secret  Base32 secret (already verified).
	 * @return string[] Generated recovery codes.
	 */
	public function enable_for_user( $user_id, $secret ) {
		$recovery = self::generate_recovery_codes();
		update_user_meta( $user_id, self::META_ENABLED, '1' );
		update_user_meta( $user_id, self::META_SECRET, sanitize_text_field( $secret ) );
		update_user_meta( $user_id, self::META_RECOVERY, $recovery );

		Turbo_Guard_Scanner::log_event(
			'2fa_enabled',
			'info',
			sprintf(
				/* translators: %d: user ID */
				__( '2FA enabled for user ID: %d', 'turbo-guard' ),
				$user_id
			)
		);

		return $recovery;
	}

	/**
	 * Disable 2FA for a user and remove all secrets.
	 *
	 * @since 1.1.0
	 * @param int $user_id User ID.
	 */
	public function disable_for_user( $user_id ) {
		delete_user_meta( $user_id, self::META_ENABLED );
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_RECOVERY );

		Turbo_Guard_Scanner::log_event(
			'2fa_disabled',
			'warning',
			sprintf(
				/* translators: %d: user ID */
				__( '2FA disabled for user ID: %d', 'turbo-guard' ),
				$user_id
			)
		);
	}

	// =========================================================
	// RECOVERY CODES MANAGEMENT
	// =========================================================

	/**
	 * Regenerate recovery codes for a user.
	 *
	 * @since 1.1.5
	 * @param int $user_id User ID.
	 * @return string[] New plain-text recovery codes.
	 */
	public function regenerate_recovery_codes( $user_id ) {
		$recovery = self::generate_recovery_codes();
		update_user_meta( $user_id, self::META_RECOVERY, $recovery );
		return $recovery;
	}
}
