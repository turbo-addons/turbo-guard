<?php
/**
 * Settings Page Template.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="wrap turbo-guard-settings">

	<!-- Page Header Banner -->
	<div class="turbo-guard-page-header">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-admin-settings"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'Settings', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Configure scanner, firewall, login security, hardening &amp; notifications', 'turbo-guard' ); ?></p>
			</div>
		</div>
	</div>

	<form id="turbo-guard-settings-form">
		<?php wp_nonce_field( 'turbo_guard_admin', 'turbo_guard_nonce' ); ?>

		<!-- Scanner Settings -->
		<div class="turbo-guard-card">
			<h2><?php esc_html_e( 'Scanner Settings', 'turbo-guard' ); ?></h2>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="scan_enabled"><?php esc_html_e( 'Enable Scanner', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="scan_enabled" name="scan_enabled" value="yes"
								<?php checked( $turbo_guard_settings['scan_enabled'], 'yes' ); ?> />
							<?php esc_html_e( 'Enable automatic malware scanning', 'turbo-guard' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="scan_schedule"><?php esc_html_e( 'Scan Schedule', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<select id="scan_schedule" name="scan_schedule" class="regular-text">
							<option value="hourly" <?php selected( $turbo_guard_settings['scan_schedule'], 'hourly' ); ?>><?php esc_html_e( 'Every Hour', 'turbo-guard' ); ?></option>
							<option value="twicedaily" <?php selected( $turbo_guard_settings['scan_schedule'], 'twicedaily' ); ?>><?php esc_html_e( 'Twice Daily', 'turbo-guard' ); ?></option>
							<option value="daily" <?php selected( $turbo_guard_settings['scan_schedule'], 'daily' ); ?>><?php esc_html_e( 'Daily', 'turbo-guard' ); ?></option>
						</select>
						<p class="description"><?php esc_html_e( 'How often should automatic scans run?', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="scan_images"><?php esc_html_e( 'Scan All Images', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="scan_images" name="scan_images" value="yes"
								<?php checked( $turbo_guard_settings['scan_images'], 'yes' ); ?> />
							<?php esc_html_e( 'Include all image files in the scan', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Detects PHP backdoors disguised as .jpg/.png/.ico files. Slightly slower scans.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="scan_outside_wp"><?php esc_html_e( 'Scan Outside WordPress', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="scan_outside_wp" name="scan_outside_wp" value="yes"
								<?php checked( $turbo_guard_settings['scan_outside_wp'], 'yes' ); ?> />
							<?php esc_html_e( 'Also scan the parent directory (above public_html)', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Catches cPanel-level injected files above the WordPress installation.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="enable_scheduled_vuln_scan"><?php esc_html_e( 'Scheduled Vulnerability Scan', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<?php if ( turbo_guard_is_pro() ) : ?>
							<label>
								<input type="checkbox" id="enable_scheduled_vuln_scan" name="enable_scheduled_vuln_scan" value="yes"
									<?php checked( $turbo_guard_settings['enable_scheduled_vuln_scan'], 'yes' ); ?> />
								<?php esc_html_e( 'Enable scheduled vulnerability scans', 'turbo-guard' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'Automatically re-checks plugin/theme versions against the WPScan API on the scheduled scan.', 'turbo-guard' ); ?></p>
						<?php else : ?>
							<label>
								<input type="checkbox" disabled
									<?php checked( $turbo_guard_settings['enable_scheduled_vuln_scan'], 'yes' ); ?> />
								<?php esc_html_e( 'Enable scheduled vulnerability scans', 'turbo-guard' ); ?>
							</label>
							<p class="description">
								<?php
								printf(
									wp_kses(
										/* translators: %s: pro URL */
										__( 'Scheduled vulnerability scans are a Pro feature. <a href="%s" target="_blank" rel="noopener noreferrer">Upgrade to Turbo Guard Pro</a> to enable.', 'turbo-guard' ),
										array( 'a' => array( 'href' => array(), 'target' => array(), 'rel' => array() ) )
									),
									esc_url( turbo_guard_pro_url() )
								);
								?>
							</p>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="wpscan_api_key"><?php esc_html_e( 'WPScan API Key', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<input type="text" id="wpscan_api_key" name="wpscan_api_key" class="regular-text"
							value="<?php echo esc_attr( get_option( 'turbo_guard_wpscan_api_key', '' ) ); ?>"
							placeholder="<?php esc_attr_e( 'Free key from wpscan.com', 'turbo-guard' ); ?>" />
						<p class="description">
							<?php esc_html_e( 'Optional. A free WPScan API key unlocks detailed vulnerability results. Get one at wpscan.com.', 'turbo-guard' ); ?>
						</p>
					</td>
				</tr>
			</table>
		</div>

		<!-- SEO Spam Detector Settings -->
		<div class="turbo-guard-card">
			<h2><?php esc_html_e( 'SEO Spam Detector', 'turbo-guard' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="seo_allow_cjk_content"><?php esc_html_e( 'CJK Content', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="seo_allow_cjk_content" name="seo_allow_cjk_content" value="yes"
								<?php checked( $turbo_guard_settings['seo_allow_cjk_content'], 'yes' ); ?> />
							<?php esc_html_e( 'My site has legitimate Japanese/Chinese/Korean content', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'When enabled, CJK text alone is not flagged as SEO spam (prevents false positives on multilingual sites).', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="enable_scheduled_seo_spam_scan"><?php esc_html_e( 'Scheduled SEO Spam Scan', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="enable_scheduled_seo_spam_scan" name="enable_scheduled_seo_spam_scan" value="yes"
								<?php checked( $turbo_guard_settings['enable_scheduled_seo_spam_scan'], 'yes' ); ?> />
							<?php esc_html_e( 'Run the SEO spam scan on the scheduled scan', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Runs locally on your server — no external connection. Email alerts are a Pro feature.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Firewall Settings -->
		<div class="turbo-guard-card">
			<h2><?php esc_html_e( 'Firewall Settings', 'turbo-guard' ); ?></h2>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="firewall_enabled"><?php esc_html_e( 'Enable Firewall', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="firewall_enabled" name="firewall_enabled" value="yes"
								<?php checked( $turbo_guard_settings['firewall_enabled'], 'yes' ); ?> />
							<?php esc_html_e( 'Enable Web Application Firewall (WAF)', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Protects against SQL injection, XSS, and other attacks.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Bot Protection Settings -->
		<div class="turbo-guard-card">
			<h2>
				<span class="dashicons dashicons-shield-alt" style="color:#2563eb;vertical-align:middle;margin-right:6px;"></span>
				<?php esc_html_e( 'Bot Protection', 'turbo-guard' ); ?>
			</h2>
			<?php
			$turbo_guard_bot_stats = Turbo_Guard_Bot_Protection::get_stats();
			?>
			<?php if ( $turbo_guard_bot_stats['total'] > 0 ) : ?>
				<p class="description" style="margin-bottom:14px;">
					<span class="dashicons dashicons-shield" style="color:#16a34a;vertical-align:middle;"></span>
					<?php
					printf(
						/* translators: 1: number of blocked requests, 2: number of unique IPs */
						esc_html__( '%1$s malicious requests blocked in the last 7 days (%2$s unique IPs).', 'turbo-guard' ),
						'<strong>' . esc_html( number_format_i18n( $turbo_guard_bot_stats['total'] ) ) . '</strong>',
						esc_html( number_format_i18n( $turbo_guard_bot_stats['unique'] ) )
					);
					?>
				</p>
			<?php endif; ?>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="bot_protection_enabled"><?php esc_html_e( 'Block Bad Bots', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="bot_protection_enabled" name="bot_protection_enabled" value="yes"
								<?php checked( $turbo_guard_settings['bot_protection_enabled'], 'yes' ); ?> />
							<?php esc_html_e( 'Block vulnerability scanners and attack tools by user agent', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Blocks known attack tools (SQLMap, Nikto, WPScan, Nuclei, and more) while always allowing verified search-engine crawlers. Blocked IPs are added to the firewall for 24 hours.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="bot_verify_crawlers"><?php esc_html_e( 'Verify Crawlers', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="bot_verify_crawlers" name="bot_verify_crawlers" value="yes"
								<?php checked( $turbo_guard_settings['bot_verify_crawlers'], 'yes' ); ?> />
							<?php esc_html_e( 'Confirm claimed crawlers (Googlebot, Bingbot, etc.) by reverse DNS', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Blocks bots that spoof a trusted crawler user agent. Recommended. Fails open if your server cannot perform reverse DNS lookups, so genuine crawlers are never blocked.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="bot_aggressive_mode"><?php esc_html_e( 'Aggressive Mode', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="bot_aggressive_mode" name="bot_aggressive_mode" value="yes"
								<?php checked( $turbo_guard_settings['bot_aggressive_mode'], 'yes' ); ?> />
							<?php esc_html_e( 'Also block generic HTTP clients and empty user agents', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Blocks curl, wget, python-requests, headless browsers, and requests with no user agent. More aggressive — enable only if you do not rely on server-to-server integrations, uptime monitors, or webhook callbacks.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="bot_custom_blocked"><?php esc_html_e( 'Custom Blocked User Agents', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<textarea id="bot_custom_blocked" name="bot_custom_blocked" rows="4" class="large-text code"
							placeholder="<?php esc_attr_e( 'One substring per line, e.g. SomeBadBot', 'turbo-guard' ); ?>"><?php echo esc_textarea( $turbo_guard_settings['bot_custom_blocked'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Optional. Block any request whose user agent contains one of these substrings (case-insensitive), one per line.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Login Security Settings -->
		<div class="turbo-guard-card">
			<h2><?php esc_html_e( 'Login Security Settings', 'turbo-guard' ); ?></h2>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="login_security_enabled"><?php esc_html_e( 'Enable Login Security', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="login_security_enabled" name="login_security_enabled" value="yes"
								<?php checked( $turbo_guard_settings['login_security_enabled'], 'yes' ); ?> />
							<?php esc_html_e( 'Enable login security features', 'turbo-guard' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="brute_force_protection"><?php esc_html_e( 'Brute Force Protection', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="brute_force_protection" name="brute_force_protection" value="yes"
								<?php checked( $turbo_guard_settings['brute_force_protection'], 'yes' ); ?> />
							<?php esc_html_e( 'Protect against brute force login attacks', 'turbo-guard' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="max_login_attempts"><?php esc_html_e( 'Max Login Attempts', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<input type="number" id="max_login_attempts" name="max_login_attempts"
							value="<?php echo esc_attr( $turbo_guard_settings['max_login_attempts'] ); ?>"
							min="1" max="20" class="small-text" />
						<p class="description"><?php esc_html_e( 'Failed login attempts allowed before lockout (1-20).', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="lockout_duration"><?php esc_html_e( 'Lockout Duration', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<input type="number" id="lockout_duration" name="lockout_duration"
							value="<?php echo esc_attr( $turbo_guard_settings['lockout_duration'] / 60 ); ?>"
							min="1" max="1440" class="small-text" />
						<?php esc_html_e( 'minutes', 'turbo-guard' ); ?>
						<p class="description"><?php esc_html_e( 'How long to lock out an IP after max attempts (in minutes).', 'turbo-guard' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Two-Factor Authentication Settings -->
		<div class="turbo-guard-card" id="turbo-guard-2fa">
			<h2>
				<span class="dashicons dashicons-lock" style="color:#16a34a;vertical-align:middle;margin-right:6px;"></span>
				<?php esc_html_e( 'Two-Factor Authentication', 'turbo-guard' ); ?>
			</h2>
			<p class="description" style="margin-bottom:14px;">
				<?php esc_html_e( 'Protect logins with a time-based one-time code from an authenticator app (Google Authenticator, Authy, etc.).', 'turbo-guard' ); ?>
			</p>

			<?php
			$turbo_guard_all_roles  = wp_roles()->get_names();
			$turbo_guard_2fa        = Turbo_Guard_2FA::get_instance();
			$turbo_guard_2fa_uid    = get_current_user_id();
			$turbo_guard_2fa_active = ( 'yes' === $turbo_guard_settings['2fa_enabled_global'] );
			$turbo_guard_2fa_on     = $turbo_guard_2fa->is_user_enabled( $turbo_guard_2fa_uid );
			$turbo_guard_2fa_secret = $turbo_guard_2fa_on ? $turbo_guard_2fa->get_secret( $turbo_guard_2fa_uid ) : Turbo_Guard_2FA::generate_secret();
			$turbo_guard_2fa_codes  = $turbo_guard_2fa_on ? $turbo_guard_2fa->get_recovery_codes( $turbo_guard_2fa_uid ) : array();
			$turbo_guard_2fa_acct   = wp_get_current_user()->user_login;
			$turbo_guard_2fa_issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
			?>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="2fa_enabled_global"><?php esc_html_e( 'Enable 2FA', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="2fa_enabled_global" name="2fa_enabled_global" value="yes"
								<?php checked( $turbo_guard_settings['2fa_enabled_global'], 'yes' ); ?> />
							<?php esc_html_e( 'Allow two-factor authentication on this site', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'When disabled, the login code check is not run and per-account setup is unavailable.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Require 2FA for', 'turbo-guard' ); ?></th>
					<td>
						<?php foreach ( $turbo_guard_all_roles as $turbo_guard_role_slug => $turbo_guard_role_name ) : ?>
							<label style="display:block;margin-bottom:4px;">
								<input type="checkbox" name="2fa_enforce_roles[]" value="<?php echo esc_attr( $turbo_guard_role_slug ); ?>"
									<?php checked( in_array( $turbo_guard_role_slug, (array) $turbo_guard_settings['2fa_enforce_roles'], true ) ); ?> />
								<?php echo esc_html( translate_user_role( $turbo_guard_role_name ) ); ?>
							</label>
						<?php endforeach; ?>
						<p class="description"><?php esc_html_e( 'Users in the selected roles see a reminder to set up 2FA. They are never locked out of wp-admin.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="2fa_grace_days"><?php esc_html_e( 'Grace Period', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<input type="number" id="2fa_grace_days" name="2fa_grace_days"
							value="<?php echo esc_attr( $turbo_guard_settings['2fa_grace_days'] ); ?>"
							min="0" max="365" class="small-text" />
						<?php esc_html_e( 'days', 'turbo-guard' ); ?>
						<p class="description"><?php esc_html_e( 'How long required users get a gentle reminder before the notice becomes an error. Set 0 for an immediate error notice.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="2fa_remember_days"><?php esc_html_e( 'Remember Device', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<input type="number" id="2fa_remember_days" name="2fa_remember_days"
							value="<?php echo esc_attr( $turbo_guard_settings['2fa_remember_days'] ); ?>"
							min="0" max="365" class="small-text" />
						<?php esc_html_e( 'days', 'turbo-guard' ); ?>
						<p class="description"><?php esc_html_e( 'Let users skip the 2FA code on a trusted device for this many days. Set 0 to always require a code.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
			</table>

			<hr style="margin:22px 0;" />

			<h3 style="margin:0 0 10px;">
				<span class="dashicons dashicons-admin-users" style="vertical-align:middle;margin-right:4px;"></span>
				<?php esc_html_e( 'Your Account', 'turbo-guard' ); ?>
			</h3>

			<?php if ( ! $turbo_guard_2fa_active ) : ?>
				<p class="description"><?php esc_html_e( 'Enable 2FA above and save your settings, then set it up here.', 'turbo-guard' ); ?></p>
			<?php elseif ( $turbo_guard_2fa_on ) : ?>
				<p>
					<span style="color:#16a34a;font-weight:600;">&#10003; <?php esc_html_e( 'Two-factor authentication is enabled for your account.', 'turbo-guard' ); ?></span>
				</p>
				<p class="description">
					<?php
					printf(
						/* translators: %d: remaining recovery codes */
						esc_html__( '%d recovery codes remaining. Each can be used once.', 'turbo-guard' ),
						count( $turbo_guard_2fa_codes )
					);
					?>
				</p>
				<p>
					<button type="button" class="button" id="turbo-guard-2fa-regen"><?php esc_html_e( 'Regenerate Recovery Codes', 'turbo-guard' ); ?></button>
					<button type="button" class="button" id="turbo-guard-2fa-disable" style="color:#b91c1c;border-color:#b91c1c;"><?php esc_html_e( 'Disable 2FA', 'turbo-guard' ); ?></button>
				</p>
			<?php else : ?>
				<div class="tg-2fa-setup"
					data-secret="<?php echo esc_attr( $turbo_guard_2fa_secret ); ?>"
					data-account="<?php echo esc_attr( $turbo_guard_2fa_acct ); ?>"
					data-issuer="<?php echo esc_attr( $turbo_guard_2fa_issuer ); ?>">
					<p style="margin-bottom:6px;"><strong>1.</strong> <?php esc_html_e( 'Scan this QR code with Google Authenticator, Authy, or any TOTP app:', 'turbo-guard' ); ?></p>
					<div id="turbo-guard-2fa-qr" style="background:#fff;padding:10px;display:inline-block;border:1px solid #e5e7eb;border-radius:8px;"></div>
					<p style="margin:12px 0 6px;">
						<strong>2.</strong>
						<?php esc_html_e( 'Or enter this key manually:', 'turbo-guard' ); ?>
						<code id="turbo-guard-2fa-key" style="background:#f3f4f6;padding:4px 8px;border-radius:4px;user-select:all;margin-left:6px;"><?php echo esc_html( $turbo_guard_2fa_secret ); ?></code>
					</p>
					<p style="margin-top:12px;">
						<strong>3.</strong>
						<?php esc_html_e( 'Enter the 6-digit code to activate:', 'turbo-guard' ); ?>
						<input type="text" id="turbo-guard-2fa-code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" class="regular-text"
							style="font-size:18px;letter-spacing:.2em;text-align:center;max-width:140px;margin:0 8px;" />
						<button type="button" class="button button-primary" id="turbo-guard-2fa-enable"><?php esc_html_e( 'Enable 2FA', 'turbo-guard' ); ?></button>
					</p>
				</div>
			<?php endif; ?>

			<div id="turbo-guard-2fa-result" class="turbo-guard-notice" style="display:none;margin-top:12px;"></div>
		</div>

		<!-- Notifications -->
		<div class="turbo-guard-card">
			<h2><?php esc_html_e( 'Email Notifications', 'turbo-guard' ); ?></h2>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="notify_admin_email"><?php esc_html_e( 'Notification Email', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<input type="email" id="notify_admin_email" name="notify_admin_email"
							value="<?php echo esc_attr( $turbo_guard_settings['notify_admin_email'] ); ?>"
							class="regular-text" />
						<p class="description"><?php esc_html_e( 'Email address for security alerts.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="notify_on_threats"><?php esc_html_e( 'Threat Alerts', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="notify_on_threats" name="notify_on_threats" value="yes"
								<?php checked( $turbo_guard_settings['notify_on_threats'], 'yes' ); ?> />
							<?php esc_html_e( 'Send email when malware is detected', 'turbo-guard' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="notify_on_scan_complete"><?php esc_html_e( 'Scan Complete Alerts', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="notify_on_scan_complete" name="notify_on_scan_complete" value="yes"
								<?php checked( $turbo_guard_settings['notify_on_scan_complete'], 'yes' ); ?> />
							<?php esc_html_e( 'Send email after each scan completes', 'turbo-guard' ); ?>
						</label>
					</td>
				</tr>
			</table>
		</div>

		<!-- Advanced Settings -->
		<div class="turbo-guard-card">
			<h2><?php esc_html_e( 'Advanced Settings', 'turbo-guard' ); ?></h2>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="remove_data_on_uninstall"><?php esc_html_e( 'Remove Data on Uninstall', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="remove_data_on_uninstall" name="remove_data_on_uninstall" value="yes"
								<?php checked( $turbo_guard_settings['remove_data_on_uninstall'], 'yes' ); ?> />
							<?php esc_html_e( 'Delete all plugin data when uninstalling', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'WARNING: This will permanently delete all scans, logs, and settings.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Site Hardening Settings -->
		<div class="turbo-guard-card" id="hardening">
			<h2>
				<span class="dashicons dashicons-hammer" style="color:#d97706;vertical-align:middle;margin-right:6px;"></span>
				<?php esc_html_e( 'Site Hardening', 'turbo-guard' ); ?>
			</h2>
			<p class="description" style="margin-bottom:14px;">
				<?php esc_html_e( 'Reduce your attack surface. These settings follow security best practices used by Wordfence, MalCare, and Patchstack.', 'turbo-guard' ); ?>
			</p>

			<?php $turbo_guard_h = Turbo_Guard_Hardening::get_hardening_options(); ?>

			<table class="form-table">
				<tr>
					<th scope="row"><label for="security_headers"><?php esc_html_e( 'HTTP Security Headers', 'turbo-guard' ); ?></label></th>
					<td>
						<label>
							<input type="checkbox" id="security_headers" name="security_headers" value="yes" <?php checked( $turbo_guard_h['security_headers'], 'yes' ); ?> />
							<?php esc_html_e( 'Add X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy headers', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Protects against clickjacking, MIME sniffing, and browser XSS attacks.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="hide_wp_version"><?php esc_html_e( 'Hide WordPress Version', 'turbo-guard' ); ?></label></th>
					<td>
						<label>
							<input type="checkbox" id="hide_wp_version" name="hide_wp_version" value="yes" <?php checked( $turbo_guard_h['hide_wp_version'], 'yes' ); ?> />
							<?php esc_html_e( 'Remove WordPress version from page source and RSS feeds', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Prevents attackers from targeting your specific WordPress version.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="prevent_user_enum"><?php esc_html_e( 'Block User Enumeration', 'turbo-guard' ); ?></label></th>
					<td>
						<label>
							<input type="checkbox" id="prevent_user_enum" name="prevent_user_enum" value="yes" <?php checked( $turbo_guard_h['prevent_user_enum'], 'yes' ); ?> />
							<?php esc_html_e( 'Block ?author=1 and /wp-json/wp/v2/users for guests', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Prevents attackers from discovering valid admin usernames.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="remove_readme_links"><?php esc_html_e( 'Remove RSD/WLW Links', 'turbo-guard' ); ?></label></th>
					<td>
						<label>
							<input type="checkbox" id="remove_readme_links" name="remove_readme_links" value="yes" <?php checked( $turbo_guard_h['remove_readme_links'], 'yes' ); ?> />
							<?php esc_html_e( 'Remove RSD and Windows Live Writer manifest links from &lt;head&gt;', 'turbo-guard' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="disable_xmlrpc"><?php esc_html_e( 'Disable XML-RPC', 'turbo-guard' ); ?></label></th>
					<td>
						<label>
							<input type="checkbox" id="disable_xmlrpc" name="disable_xmlrpc" value="yes" <?php checked( $turbo_guard_h['disable_xmlrpc'], 'yes' ); ?> />
							<?php esc_html_e( 'Completely disable XML-RPC (used for brute force amplification attacks)', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Only enable if you do not use Jetpack, mobile WordPress app, or remote publishing.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="protect_rest_api"><?php esc_html_e( 'Protect REST API', 'turbo-guard' ); ?></label></th>
					<td>
						<label>
							<input type="checkbox" id="protect_rest_api" name="protect_rest_api" value="yes" <?php checked( $turbo_guard_h['protect_rest_api'], 'yes' ); ?> />
							<?php esc_html_e( 'Require login for REST API access (allows CF7, WooCommerce, and Gutenberg routes)', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Use with caution — some themes and plugins need public REST API access.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="disable_file_edit"><?php esc_html_e( 'Disable Theme/Plugin Editor', 'turbo-guard' ); ?></label></th>
					<td>
						<label>
							<input type="checkbox" id="disable_file_edit" name="disable_file_edit" value="yes" <?php checked( $turbo_guard_h['disable_file_edit'], 'yes' ); ?> />
							<?php esc_html_e( 'Disable the WordPress file editor (Appearance → Editor, Plugins → Editor)', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Prevents attackers who gain admin access from editing PHP files directly.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="block_php_uploads"><?php esc_html_e( 'Block PHP in Uploads Folder', 'turbo-guard' ); ?></label></th>
					<td>
						<label>
							<input type="checkbox" id="block_php_uploads" name="block_php_uploads" value="yes" <?php checked( $turbo_guard_h['block_php_uploads'], 'yes' ); ?> />
							<?php esc_html_e( 'Add .htaccess rule to block PHP execution in wp-content/uploads/', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Strongest protection against upload-based backdoors. Even if a hacker uploads a PHP shell, the server will refuse to run it. Recommended: ON.', 'turbo-guard' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<?php do_action( 'turbo_guard_settings_after' ); ?>

		<?php if ( ! turbo_guard_is_pro() ) : ?>
		<!-- Locked Pro Settings -->
		<div class="turbo-guard-card" id="geo-fence" style="opacity:.75;">
			<h2>
				<span style="margin-right:6px;">🌍</span>
				<?php esc_html_e( 'Geo-Fence &amp; Trusted Location', 'turbo-guard' ); ?>
				<span style="margin-left:6px;" class="dashicons dashicons-lock"></span>
			</h2>
			<p class="description" style="margin-bottom:14px;">
				<?php esc_html_e( 'Restrict wp-admin and file uploads to trusted IPs and countries.', 'turbo-guard' ); ?>
			</p>
			<p>
				<a href="<?php echo esc_url( turbo_guard_pro_url() ); ?>" target="_blank" rel="noopener noreferrer" class="button button-primary">
					<?php esc_html_e( 'Upgrade to Pro to enable', 'turbo-guard' ); ?>
				</a>
			</p>
		</div>

		<div class="turbo-guard-card" id="ai" style="opacity:.75;">
			<h2>
				<span style="margin-right:6px;">🤖</span>
				<?php esc_html_e( 'AI Advisor — OpenAI Integration', 'turbo-guard' ); ?>
				<span style="margin-left:6px;" class="dashicons dashicons-lock"></span>
			</h2>
			<p class="description" style="margin-bottom:14px;">
				<?php esc_html_e( 'GPT-powered security analysis after every scan.', 'turbo-guard' ); ?>
			</p>
			<p>
				<a href="<?php echo esc_url( turbo_guard_pro_url() ); ?>" target="_blank" rel="noopener noreferrer" class="button button-primary">
					<?php esc_html_e( 'Upgrade to Pro to enable', 'turbo-guard' ); ?>
				</a>
			</p>
		</div>
		<?php endif; ?>

		<!-- Google Search Console Settings -->
		<div class="turbo-guard-card">
			<h2>
				<span class="dashicons dashicons-google" style="color:#4285f4;"></span>
				<?php esc_html_e( 'Google Search Console (GSC)', 'turbo-guard' ); ?>
			</h2>
			<p class="description">
				<?php
				printf(
					/* translators: %s: GSC cleanup page URL */
					esc_html__( 'Connect to Google Search Console to detect and remove SEO spam URLs from Google index. %s', 'turbo-guard' ),
					'<a href="' . esc_url( admin_url( 'admin.php?page=turbo-guard-gsc' ) ) . '">' . esc_html__( 'Go to GSC Cleanup →', 'turbo-guard' ) . '</a>'
				);
				?>
			</p>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="gsc_client_id"><?php esc_html_e( 'OAuth Client ID', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<input type="text"
							id="gsc_client_id"
							name="gsc_client_id"
							value="<?php echo esc_attr( get_option( 'turbo_guard_gsc_client_id', '' ) ); ?>"
							class="regular-text"
							placeholder="<?php esc_attr_e( 'Paste your Google OAuth Client ID here', 'turbo-guard' ); ?>"
						/>
						<p class="description">
							<?php
							printf(
								/* translators: %s: Google Cloud Console URL */
								esc_html__( 'Get this from %s → APIs & Services → Credentials.', 'turbo-guard' ),
								'<a href="https://console.cloud.google.com" target="_blank" rel="noopener noreferrer">Google Cloud Console</a>'
							);
							?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="gsc_client_secret"><?php esc_html_e( 'OAuth Client Secret', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<input type="password"
							id="gsc_client_secret"
							name="gsc_client_secret"
							value="<?php echo esc_attr( get_option( 'turbo_guard_gsc_client_secret', '' ) ); ?>"
							class="regular-text"
							autocomplete="new-password"
						/>
						<p class="description"><?php esc_html_e( 'Your Google OAuth Client Secret (kept private).', 'turbo-guard' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<p class="submit">
			<button type="submit" class="button button-primary button-large" id="turbo-guard-save-settings">
				<span class="dashicons dashicons-saved"></span>
				<?php esc_html_e( 'Save Settings', 'turbo-guard' ); ?>
			</button>
		</p>
	</form>

	<div id="turbo-guard-settings-result" class="turbo-guard-notice" style="display:none;"></div>

</div><!-- /.wrap -->
