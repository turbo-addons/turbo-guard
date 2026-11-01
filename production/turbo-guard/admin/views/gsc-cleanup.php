<?php
/**
 * SEO Spam URL Cleanup Page Template.
 *
 * @package TurboGuard
 * @since   1.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$turbo_guard_is_connected = $turbo_guard_gsc->is_connected();
$turbo_guard_site_url     = esc_url( home_url( '/' ) );

// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only OAuth status flag for display; no form processing.
$turbo_guard_gsc_connected = isset( $_GET['connected'] ) ? sanitize_key( wp_unslash( $_GET['connected'] ) ) : '';
// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only OAuth status flag for display; no form processing.
$turbo_guard_gsc_oauth_error = isset( $_GET['oauth_error'] ) ? sanitize_text_field( wp_unslash( $_GET['oauth_error'] ) ) : '';
?>

<div class="wrap turbo-guard-gsc">

	<!-- Page Header Banner -->
	<div class="turbo-guard-page-header">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-admin-site"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'SEO Spam URL Cleanup', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Find spam URLs on your site and block them with 410 Gone so Google deindexes them', 'turbo-guard' ); ?></p>
			</div>
		</div>
	</div>

	<?php if ( '1' === $turbo_guard_gsc_connected ) : ?>
		<div class="notice notice-success is-dismissible">
			<p><strong><?php esc_html_e( 'Successfully connected to Google Search Console.', 'turbo-guard' ); ?></strong></p>
		</div>
	<?php endif; ?>

	<?php
	if ( '' !== $turbo_guard_gsc_oauth_error ) :
		$turbo_guard_oauth_hint = '';
		switch ( $turbo_guard_gsc_oauth_error ) {
			case 'access_denied':
				$turbo_guard_oauth_hint = __( 'You cancelled the permission. Click "Connect to Google Search Console" again and choose Allow.', 'turbo-guard' );
				break;
			case 'redirect_uri_mismatch':
				$turbo_guard_oauth_hint = __( 'The Authorized Redirect URI in Google Cloud Console does not exactly match the URI in Step 3. Copy it exactly (no extra spaces, no trailing slash).', 'turbo-guard' );
				break;
			case 'invalid_client':
				$turbo_guard_oauth_hint = __( 'The Client ID or Client Secret is incorrect. Re-check them in Turbo Guard Settings.', 'turbo-guard' );
				break;
			case 'invalid_grant':
				$turbo_guard_oauth_hint = __( 'The authorization code is invalid or already used. Click "Connect to Google Search Console" again.', 'turbo-guard' );
				break;
			case 'invalid_state':
				$turbo_guard_oauth_hint = __( 'Your session expired. Click "Connect to Google Search Console" again.', 'turbo-guard' );
				break;
			default:
				$turbo_guard_oauth_hint = __( 'If Google shows "Access blocked", your OAuth consent screen is likely in Testing mode — add your email as a Test User in Google Cloud Console, or Publish the app.', 'turbo-guard' );
		}
		?>
		<div class="notice notice-error is-dismissible">
			<p>
				<strong><?php esc_html_e( 'Google Search Console connection failed.', 'turbo-guard' ); ?></strong>
				<code><?php echo esc_html( $turbo_guard_gsc_oauth_error ); ?></code>
			</p>
			<p><?php echo esc_html( $turbo_guard_oauth_hint ); ?></p>
		</div>
	<?php endif; ?>

	<!-- How cleanup works -->
	<div class="turbo-guard-card" style="border-left:4px solid #ea580c;">
		<h2 style="color:#c2410c;"><?php esc_html_e( 'How It Works', 'turbo-guard' ); ?></h2>
		<p style="font-size:13px;color:#374151;line-height:1.6;margin:0;">
			<?php esc_html_e( 'Google does not offer a bulk URL-removal API, so the correct way to deindex spam is to make those URLs return "410 Gone". Turbo Guard scans your sitemap for spam URLs (no setup needed), generates the 410 blocking rules, and Google deindexes them on its next crawl. First, delete the source files with the SEO Spam Detector or Scanner.', 'turbo-guard' ); ?>
		</p>
	</div>

	<!-- Scan Card (zero setup — no Google OAuth) -->
	<div class="turbo-guard-card">
		<div class="turbo-guard-scan-hero">
			<div class="turbo-guard-scan-intro">
				<h2><?php esc_html_e( 'Scan Your Site for Spam URLs', 'turbo-guard' ); ?></h2>
				<p><?php esc_html_e( 'Scans your sitemap for Japanese/Chinese spam, doorway and brand-keyword URLs. Instant, no Google account or setup required.', 'turbo-guard' ); ?></p>
			</div>
			<button id="turbo-guard-scan-site" class="button button-primary button-large">
				<span class="dashicons dashicons-search"></span>
				<?php esc_html_e( 'Scan Site for Spam', 'turbo-guard' ); ?>
			</button>
		</div>
		<div id="turbo-guard-gsc-loading" style="display:none;margin-top:14px;padding-top:14px;border-top:1px solid #f3f4f6;">
			<span class="spinner is-active" style="float:none;vertical-align:middle;margin-right:6px;"></span>
			<strong><?php esc_html_e( 'Scanning your sitemap for spam URLs...', 'turbo-guard' ); ?></strong>
		</div>
	</div>

	<!-- Results Card (always visible) -->
	<div class="turbo-guard-card">
		<h2>
			<?php esc_html_e( 'Spam URLs Found', 'turbo-guard' ); ?>
		</h2>
		<p style="font-size:12px;color:#6b7280;margin:2px 0 12px;">
			<?php esc_html_e( 'Select the spam URLs and generate .htaccess 410-Gone rules so Google deindexes them on its next crawl.', 'turbo-guard' ); ?>
		</p>

		<div id="turbo-guard-gsc-results" style="display:none;">
			<div class="turbo-guard-gsc-stats" style="margin:15px 0;">
				<strong id="turbo-guard-url-count">0</strong> <?php esc_html_e( 'URLs found', 'turbo-guard' ); ?>
				<span id="turbo-guard-spam-count" style="margin-left:20px;"></span>
			</div>

			<div class="turbo-guard-bulk-actions">
				<label>
					<input type="checkbox" id="turbo-guard-gsc-select-all" />
					<?php esc_html_e( 'Select All', 'turbo-guard' ); ?>
				</label>
				<button id="turbo-guard-select-spam-only" class="button">
					<?php esc_html_e( 'Select Spam Only', 'turbo-guard' ); ?>
				</button>
				<label style="margin-left:10px;">
					<input type="checkbox" id="turbo-guard-filter-spam" checked />
					<?php esc_html_e( 'Show only suspected spam URLs', 'turbo-guard' ); ?>
				</label>
				<button id="turbo-guard-generate-htaccess" class="button button-primary">
					<span class="dashicons dashicons-media-code"></span>
					<?php esc_html_e( 'Generate .htaccess 410 Blocks', 'turbo-guard' ); ?>
				</button>
				<?php if ( turbo_guard_is_pro() ) : ?>
					<button id="turbo-guard-apply-htaccess" class="button button-primary" style="background:#15803d;border-color:#166534;">
						<span class="dashicons dashicons-yes-alt"></span>
						<?php esc_html_e( 'Apply to .htaccess', 'turbo-guard' ); ?>
					</button>
				<?php else : ?>
					<a href="<?php echo esc_url( turbo_guard_pro_url() ); ?>" target="_blank" rel="noopener noreferrer" class="button button-secondary">
						<span class="dashicons dashicons-lock"></span>
						<?php esc_html_e( 'Apply to .htaccess (Pro)', 'turbo-guard' ); ?>
					</a>
				<?php endif; ?>
				<span id="turbo-guard-gsc-selection-count" class="turbo-guard-count-badge">0 selected</span>
			</div>
			<p style="margin:8px 0 0;font-size:12px;color:#6b7280;">
				<?php esc_html_e( 'Google has no bulk URL-removal API. The 410-Gone block is the permanent fix; the Search Console "Removals" tool is only a manual, temporary fallback.', 'turbo-guard' ); ?>
			</p>

			<table class="widefat turbo-guard-gsc-table" id="turbo-guard-url-table" style="margin-top:12px;">
				<thead>
					<tr>
						<th style="width:30px;"></th>
						<th><?php esc_html_e( 'URL', 'turbo-guard' ); ?></th>
						<th><?php esc_html_e( 'Type', 'turbo-guard' ); ?></th>
					</tr>
				</thead>
				<tbody id="turbo-guard-url-tbody">
					<!-- Populated via JS -->
				</tbody>
			</table>
		</div>

		<!-- .htaccess Preview -->
		<div id="turbo-guard-htaccess-preview" class="turbo-guard-card" style="display:none;margin-top:16px;">
			<h2><?php esc_html_e( '.htaccess 410-Gone Blocking Code', 'turbo-guard' ); ?></h2>
			<p><?php esc_html_e( 'Add this code to your .htaccess file (top of the file, after RewriteEngine On). It makes the spam URLs return "410 Gone" so Google permanently deindexes them on its next crawl.', 'turbo-guard' ); ?></p>
			<textarea id="turbo-guard-htaccess-code" readonly style="width:100%; height:200px; font-family:monospace; font-size:12px;"></textarea>
			<button id="turbo-guard-copy-htaccess" class="button">
				<span class="dashicons dashicons-clipboard"></span>
				<?php esc_html_e( 'Copy to Clipboard', 'turbo-guard' ); ?>
			</button>
		</div>
	</div>

	<!-- Action Result Notice -->
	<div id="turbo-guard-gsc-notice" class="turbo-guard-notice" style="display:none;"></div>

	<!-- Google Search Console (Optional) -->
	<div class="turbo-guard-card">
		<h2><?php esc_html_e( 'Google Search Console (Optional)', 'turbo-guard' ); ?></h2>
		<p style="font-size:13px;color:#6b7280;margin:0 0 14px;">
			<?php esc_html_e( 'The sitemap scan above needs no setup. Connect GSC only if you want to see the URLs Google has actually indexed in the last 30 days (Search Analytics).', 'turbo-guard' ); ?>
		</p>

		<?php if ( $turbo_guard_is_connected ) : ?>
			<div class="turbo-guard-status-row">
				<span class="turbo-guard-status-dot turbo-guard-status-on"></span>
				<strong><?php esc_html_e( 'Connected', 'turbo-guard' ); ?></strong>
				<button id="turbo-guard-fetch-urls" class="button button-primary" style="margin-left:8px;">
					<span class="dashicons dashicons-download"></span>
					<?php esc_html_e( 'Fetch Indexed URLs from Google', 'turbo-guard' ); ?>
				</button>
				<button id="turbo-guard-gsc-disconnect" class="button">
					<?php esc_html_e( 'Disconnect', 'turbo-guard' ); ?>
				</button>
			</div>
		<?php else : ?>
			<?php $turbo_guard_client_id = get_option( 'turbo_guard_gsc_client_id', '' ); ?>
			<?php if ( $turbo_guard_client_id ) : ?>
				<p>
					<a href="<?php echo esc_url( $turbo_guard_gsc->get_auth_url() ); ?>" class="button">
						<span class="dashicons dashicons-admin-site" style="font-size:16px;width:16px;height:16px;vertical-align:middle;margin-right:4px;"></span>
						<?php esc_html_e( 'Connect to Google Search Console', 'turbo-guard' ); ?>
					</a>
				</p>
			<?php else : ?>
				<details>
					<summary style="cursor:pointer;color:#1d4ed8;"><?php esc_html_e( 'Set up Google Search Console (optional)', 'turbo-guard' ); ?></summary>
					<div class="turbo-guard-gsc-setup" style="margin-top:14px;">
						<div class="turbo-guard-setup-step">
							<div class="turbo-guard-step-number">1</div>
							<div class="turbo-guard-step-content">
								<strong><?php esc_html_e( 'Create a Google Cloud Project', 'turbo-guard' ); ?></strong>
								<p><?php esc_html_e( 'Go to Google Cloud Console and create a free project.', 'turbo-guard' ); ?></p>
								<a href="https://console.cloud.google.com/projectcreate" target="_blank" rel="noopener noreferrer" class="button button-small">
									<?php esc_html_e( 'Open Google Cloud Console →', 'turbo-guard' ); ?>
								</a>
							</div>
						</div>
						<div class="turbo-guard-setup-step">
							<div class="turbo-guard-step-number">2</div>
							<div class="turbo-guard-step-content">
								<strong><?php esc_html_e( 'Enable the Search Console API', 'turbo-guard' ); ?></strong>
								<p><?php esc_html_e( 'APIs & Services → Library → "Google Search Console API" → Enable.', 'turbo-guard' ); ?></p>
								<a href="https://console.cloud.google.com/apis/library/searchconsole.googleapis.com" target="_blank" rel="noopener noreferrer" class="button button-small">
									<?php esc_html_e( 'Enable API →', 'turbo-guard' ); ?>
								</a>
							</div>
						</div>
						<div class="turbo-guard-setup-step">
							<div class="turbo-guard-step-number">3</div>
							<div class="turbo-guard-step-content">
								<strong><?php esc_html_e( 'Create OAuth 2.0 Credentials', 'turbo-guard' ); ?></strong>
								<p><?php esc_html_e( 'Credentials → Create Credentials → OAuth client ID → Web application. Add this redirect URI exactly:', 'turbo-guard' ); ?></p>
								<div style="display:flex;align-items:center;gap:8px;margin:8px 0;">
									<code style="background:#f3f4f6;padding:6px 10px;border-radius:5px;font-size:12px;flex:1;word-break:break-all;border:1px solid #e5e7eb;">
										<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-gsc&oauth_callback=1' ) ); ?>
									</code>
									<button type="button" class="button button-small turbo-guard-copy-redirect-uri"
										data-uri="<?php echo esc_attr( admin_url( 'admin.php?page=turbo-guard-gsc&oauth_callback=1' ) ); ?>">
										<?php esc_html_e( 'Copy', 'turbo-guard' ); ?>
									</button>
								</div>
								<a href="https://console.cloud.google.com/apis/credentials/oauthclient" target="_blank" rel="noopener noreferrer" class="button button-small">
									<?php esc_html_e( 'Create Credentials →', 'turbo-guard' ); ?>
								</a>
							</div>
						</div>
						<div class="turbo-guard-setup-step">
							<div class="turbo-guard-step-number">4</div>
							<div class="turbo-guard-step-content">
								<strong><?php esc_html_e( 'Paste Credentials in Settings', 'turbo-guard' ); ?></strong>
								<p><?php esc_html_e( 'Copy your Client ID and Client Secret into Turbo Guard Settings.', 'turbo-guard' ); ?></p>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-settings#gsc' ) ); ?>" class="button button-primary button-small">
									<?php esc_html_e( 'Go to Settings → GSC →', 'turbo-guard' ); ?>
								</a>
							</div>
						</div>
					</div>
				</details>
			<?php endif; ?>
		<?php endif; ?>
	</div>

</div>
