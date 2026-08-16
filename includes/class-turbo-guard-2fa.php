<?php
/**
 * TOTP Two-Factor Authentication Class.
 *
 * RFC 6238 compliant TOTP implementation with manual secret setup,
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

		// Add 2FA code input to login form.
		add_action( 'login_form', array( $this, 'render_login_field' ) );

		// Profile page: show setup UI.
		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );

		// Save profile 2FA settings.
		add_action( 'personal_options_update', array( $this, 'save_profile' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_profile' ) );

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

		if ( $this->verify_totp( $secret, $code ) ) {
			return $user;
		}

		if ( $this->verify_recovery_code( $user->ID, $code ) ) {
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
	// PROFILE PAGE
	// =========================================================

	/**
	 * Render 2FA setup section on user profile page.
	 *
	 * @since 1.1.0
	 * @param WP_User $user Current user.
	 */
	public function render_profile_section( $user ) {
		// Only admins can edit other users' 2FA. Users can edit their own.
		if ( $user->ID !== get_current_user_id() && ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$enabled        = $this->is_user_enabled( $user->ID );
		$secret         = $this->get_secret( $user->ID );
		$new_secret     = $enabled ? $secret : self::generate_secret();
		$recovery_codes = $this->get_recovery_codes( $user->ID );

		wp_nonce_field( 'turbo_guard_2fa_profile_' . $user->ID, 'turbo_guard_2fa_nonce' );
		?>
		<h2><?php esc_html_e( 'Two-Factor Authentication (Turbo Guard)', 'turbo-guard' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( '2FA Status', 'turbo-guard' ); ?></th>
				<td>
					<?php if ( $enabled ) : ?>
						<span style="color:#16a34a;font-weight:600;">&#10003; <?php esc_html_e( 'Enabled', 'turbo-guard' ); ?></span>
					<?php else : ?>
						<span style="color:#9ca3af;"><?php esc_html_e( 'Disabled', 'turbo-guard' ); ?></span>
					<?php endif; ?>
				</td>
			</tr>
			<?php if ( ! $enabled ) : ?>
			<tr>
				<th><?php esc_html_e( 'Manual Setup', 'turbo-guard' ); ?></th>
				<td>
					<p class="description">
						<?php esc_html_e( 'Enter this key manually in Google Authenticator, Authy, or any TOTP app.', 'turbo-guard' ); ?>
					</p>
					<p>
						<code style="background:#f3f4f6;padding:4px 8px;border-radius:4px;user-select:all;">
							<?php echo esc_html( $new_secret ); ?>
						</code>
					</p>
					<input type="hidden" name="turbo_guard_2fa_secret" value="<?php echo esc_attr( $new_secret ); ?>" />
					<p style="margin-top:12px;">
						<label>
							<strong><?php esc_html_e( 'Verify code to activate:', 'turbo-guard' ); ?></strong><br>
							<input type="text"
								name="turbo_guard_2fa_verify"
								maxlength="6"
								inputmode="numeric"
								placeholder="000000"
								class="regular-text"
								style="font-size:18px;letter-spacing:.2em;text-align:center;max-width:140px;margin-top:6px;"
							/>
						</label>
					</p>
					<p>
						<label>
							<input type="checkbox" name="turbo_guard_2fa_enable" value="1" />
							<?php esc_html_e( 'Enable Two-Factor Authentication for my account', 'turbo-guard' ); ?>
						</label>
					</p>
				</td>
			</tr>
			<?php else : ?>
			<tr>
				<th><?php esc_html_e( 'Recovery Codes', 'turbo-guard' ); ?></th>
				<td>
					<?php if ( ! empty( $recovery_codes ) ) : ?>
						<p class="description">
							<?php
							printf(
								/* translators: %d: remaining code count */
								esc_html__( '%d recovery codes remaining. Store them safely — each can only be used once.', 'turbo-guard' ),
								count( $recovery_codes )
							);
							?>
						</p>
					<?php else : ?>
						<p style="color:#dc2626;"><?php esc_html_e( 'No recovery codes remaining. Disable and re-enable 2FA to generate new codes.', 'turbo-guard' ); ?></p>
					<?php endif; ?>
					<p>
						<label>
							<input type="checkbox" name="turbo_guard_2fa_disable" value="1" />
							<span style="color:#dc2626;"><?php esc_html_e( 'Disable Two-Factor Authentication', 'turbo-guard' ); ?></span>
						</label>
					</p>
				</td>
			</tr>
			<?php endif; ?>
		</table>
		<?php
	}

	/**
	 * Save 2FA profile changes.
	 *
	 * @since 1.1.0
	 * @param int $user_id User ID being updated.
	 */
	public function save_profile( $user_id ) {
		if ( ! isset( $_POST['turbo_guard_2fa_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['turbo_guard_2fa_nonce'] ) ), 'turbo_guard_2fa_profile_' . $user_id ) ) {
			return;
		}

		if ( $user_id !== get_current_user_id() && ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Disable 2FA.
		if ( ! empty( $_POST['turbo_guard_2fa_disable'] ) ) {
			$this->disable_for_user( $user_id );
			return;
		}

		// Enable 2FA — verify the code first.
		if ( ! empty( $_POST['turbo_guard_2fa_enable'] ) ) {
			$secret = isset( $_POST['turbo_guard_2fa_secret'] ) ? sanitize_text_field( wp_unslash( $_POST['turbo_guard_2fa_secret'] ) ) : '';
			$verify = isset( $_POST['turbo_guard_2fa_verify'] ) ? preg_replace( '/\D/', '', sanitize_text_field( wp_unslash( $_POST['turbo_guard_2fa_verify'] ) ) ) : '';

			if ( $secret && $verify && $this->verify_totp( $secret, $verify ) ) {
				$recovery = $this->enable_for_user( $user_id, $secret );
				// Show recovery codes in a transient — displayed on next page load.
				set_transient( 'turbo_guard_2fa_new_codes_' . $user_id, $recovery, 60 );
				add_action( 'user_profile_update_errors', function( $errors ) {
					$errors->add( 'turbo_guard_2fa_enabled', __( 'Turbo Guard: Two-Factor Authentication enabled! Save your recovery codes now.', 'turbo-guard' ), 'info' );
				} );
			} else {
				add_action( 'user_profile_update_errors', function( $errors ) {
					$errors->add( 'turbo_guard_2fa_invalid', __( 'Turbo Guard: Invalid verification code — 2FA was NOT enabled. Please try again.', 'turbo-guard' ) );
				} );
			}
		}
	}
}
