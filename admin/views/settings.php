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
							<option value="weekly" <?php selected( $turbo_guard_settings['scan_schedule'], 'weekly' ); ?>><?php esc_html_e( 'Weekly', 'turbo-guard' ); ?></option>
						</select>
						<p class="description"><?php esc_html_e( 'How often should automatic scans run?', 'turbo-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="quarantine_malware"><?php esc_html_e( 'Quarantine Files', 'turbo-guard' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="quarantine_malware" name="quarantine_malware" value="yes"
								<?php checked( $turbo_guard_settings['quarantine_malware'], 'yes' ); ?> />
							<?php esc_html_e( 'Move malware to quarantine instead of deleting immediately', 'turbo-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Recommended for safety - allows file recovery if needed.', 'turbo-guard' ); ?></p>
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
