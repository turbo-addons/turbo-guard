<?php
/**
 * Google Search Console Cleanup Page Template.
 *
 * @package TurboGuard
 * @since 1.1.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$turbo_guard_is_connected = $gsc->is_connected();
$turbo_guard_site_url     = esc_url( home_url( '/' ) );
?>

<div class="wrap turbo-guard-gsc">

	<!-- Page Header Banner -->
	<div class="turbo-guard-page-header">
		<div class="turbo-guard-page-header-left">
			<div class="turbo-guard-page-header-icon">
				<span class="dashicons dashicons-admin-site"></span>
			</div>
			<div>
				<h1><?php esc_html_e( 'Google Search Console Cleanup', 'turbo-guard' ); ?></h1>
				<p><?php esc_html_e( 'Remove SEO spam URLs from Google index — even when files no longer exist', 'turbo-guard' ); ?></p>
			</div>
		</div>
		<span class="turbo-guard-header-badge"><?php esc_html_e( 'Unique Feature', 'turbo-guard' ); ?></span>
	</div>

	<!-- Connection Status -->
	<div class="turbo-guard-card">
		<h2><?php esc_html_e( 'Connection Status', 'turbo-guard' ); ?></h2>

		<?php if ( $turbo_guard_is_connected ) : ?>
			<div class="turbo-guard-status-row">
				<span class="turbo-guard-status-dot turbo-guard-status-on"></span>
				<strong><?php esc_html_e( 'Connected to Google Search Console', 'turbo-guard' ); ?></strong>
				<button id="turbo-guard-gsc-disconnect" class="button">
					<?php esc_html_e( 'Disconnect', 'turbo-guard' ); ?>
				</button>
			</div>
			<p>
				<?php
				printf(
					/* translators: %s: site URL */
					esc_html__( 'Managing property: %s', 'turbo-guard' ),
					'<code>' . esc_html( $turbo_guard_site_url ) . '</code>'
				);
				?>
			</p>
		<?php else : ?>
			<div class="turbo-guard-status-row">
				<span class="turbo-guard-status-dot turbo-guard-status-off"></span>
				<strong><?php esc_html_e( 'Not Connected to Google Search Console', 'turbo-guard' ); ?></strong>
			</div>

			<!-- Why connect? -->
			<div style="margin:16px 0;padding:14px 16px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;">
				<strong style="color:#1d4ed8;font-size:13px;">
					<span class="dashicons dashicons-info" style="font-size:15px;width:15px;height:15px;vertical-align:middle;margin-right:4px;"></span>
					<?php esc_html_e( 'Why connect?', 'turbo-guard' ); ?>
				</strong>
				<p style="margin:6px 0 0;font-size:13px;color:#1e40af;line-height:1.5;">
					<?php esc_html_e( 'When your site gets hacked with Japanese/Chinese SEO spam, Google indexes those fake URLs. Even after you delete the files, those URLs stay in Google for months — harming your SEO and reputation. This tool removes them in bulk with one click.', 'turbo-guard' ); ?>
				</p>
			</div>

			<!-- Step-by-step setup -->
			<div class="turbo-guard-gsc-setup">
				<h3 style="font-size:14px;font-weight:700;color:#1f2937;text-transform:none;letter-spacing:0;margin-bottom:16px;">
					<?php esc_html_e( '4-Step Setup Guide', 'turbo-guard' ); ?>
				</h3>

				<!-- Step 1 -->
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

				<!-- Step 2 -->
				<div class="turbo-guard-setup-step">
					<div class="turbo-guard-step-number">2</div>
					<div class="turbo-guard-step-content">
						<strong><?php esc_html_e( 'Enable the Search Console API', 'turbo-guard' ); ?></strong>
						<p><?php esc_html_e( 'In your project, go to APIs & Services → Library → search for "Google Search Console API" → Enable.', 'turbo-guard' ); ?></p>
						<a href="https://console.cloud.google.com/apis/library/searchconsole.googleapis.com" target="_blank" rel="noopener noreferrer" class="button button-small">
							<?php esc_html_e( 'Enable API →', 'turbo-guard' ); ?>
						</a>
					</div>
				</div>

				<!-- Step 3 -->
				<div class="turbo-guard-setup-step">
					<div class="turbo-guard-step-number">3</div>
					<div class="turbo-guard-step-content">
						<strong><?php esc_html_e( 'Create OAuth 2.0 Credentials', 'turbo-guard' ); ?></strong>
						<p><?php esc_html_e( 'Go to APIs & Services → Credentials → Create Credentials → OAuth client ID → Web application.', 'turbo-guard' ); ?></p>
						<p style="margin:8px 0 4px;font-size:12px;font-weight:600;color:#374151;"><?php esc_html_e( 'Add this Authorized Redirect URI exactly:', 'turbo-guard' ); ?></p>
						<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
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

				<!-- Step 4 -->
				<div class="turbo-guard-setup-step">
					<div class="turbo-guard-step-number">4</div>
					<div class="turbo-guard-step-content">
						<strong><?php esc_html_e( 'Paste Credentials in Settings', 'turbo-guard' ); ?></strong>
						<p><?php esc_html_e( 'Copy your Client ID and Client Secret from Google Cloud Console, then save them in Turbo Guard Settings.', 'turbo-guard' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=turbo-guard-settings#gsc' ) ); ?>" class="button button-primary button-small">
							<?php esc_html_e( 'Go to Settings → GSC →', 'turbo-guard' ); ?>
						</a>
					</div>
				</div>

				<?php
				$turbo_guard_client_id = get_option( 'turbo_guard_gsc_client_id', '' );
				if ( ! $turbo_guard_client_id ) : ?>
					<div class="notice notice-warning inline" style="margin-top:16px;">
						<p>
							<?php
							printf(
								/* translators: %s: settings page link */
								esc_html__( 'Step 4 incomplete — %s to enter your OAuth Client ID and Secret.', 'turbo-guard' ),
								'<a href="' . esc_url( admin_url( 'admin.php?page=turbo-guard-settings' ) ) . '"><strong>' . esc_html__( 'click here', 'turbo-guard' ) . '</strong></a>'
							);
							?>
						</p>
					</div>
				<?php else : ?>
					<div style="margin-top:16px;">
						<a href="<?php echo esc_url( $gsc->get_auth_url() ); ?>" class="button button-primary">
							<span class="dashicons dashicons-admin-site" style="font-size:16px;width:16px;height:16px;vertical-align:middle;margin-right:4px;"></span>
							<?php esc_html_e( 'Connect to Google Search Console', 'turbo-guard' ); ?>
						</a>
					</div>
				<?php endif; ?>
			</div><!-- /.turbo-guard-gsc-setup -->
		<?php endif; ?>
	</div>

	<?php if ( $turbo_guard_is_connected ) : ?>
		<!-- Fetch Indexed URLs -->
		<div class="turbo-guard-card">
			<h2><?php esc_html_e( 'Indexed URLs', 'turbo-guard' ); ?></h2>

			<div class="turbo-guard-gsc-controls">
				<button id="turbo-guard-fetch-urls" class="button button-primary">
					<span class="dashicons dashicons-download"></span>
					<?php esc_html_e( 'Fetch Indexed URLs from Google', 'turbo-guard' ); ?>
				</button>

				<label style="margin-left: 20px;">
					<input type="checkbox" id="turbo-guard-filter-spam" checked />
					<?php esc_html_e( 'Show only suspected spam URLs', 'turbo-guard' ); ?>
				</label>
			</div>

			<div id="turbo-guard-gsc-loading" style="display:none; margin:20px 0;">
				<p>
					<span class="spinner is-active" style="float:none;"></span>
					<?php esc_html_e( 'Fetching URLs from Google Search Console...', 'turbo-guard' ); ?>
				</p>
			</div>

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
					<button id="turbo-guard-remove-selected" class="button button-primary">
						<span class="dashicons dashicons-trash"></span>
						<?php esc_html_e( 'Request Removal from Google', 'turbo-guard' ); ?>
					</button>
					<button id="turbo-guard-generate-htaccess" class="button button-secondary">
						<span class="dashicons dashicons-media-code"></span>
						<?php esc_html_e( 'Generate .htaccess Redirects', 'turbo-guard' ); ?>
					</button>
					<span id="turbo-guard-gsc-selection-count" class="turbo-guard-count-badge">0 selected</span>
				</div>

				<table class="widefat turbo-guard-gsc-table" id="turbo-guard-url-table">
					<thead>
						<tr>
							<th style="width:30px;"></th>
							<th><?php esc_html_e( 'URL', 'turbo-guard' ); ?></th>
							<th><?php esc_html_e( 'Status', 'turbo-guard' ); ?></th>
							<th><?php esc_html_e( 'Type', 'turbo-guard' ); ?></th>
						</tr>
					</thead>
					<tbody id="turbo-guard-url-tbody">
						<!-- Populated via JS -->
					</tbody>
				</table>
			</div>
		</div>

		<!-- .htaccess Preview -->
		<div id="turbo-guard-htaccess-preview" class="turbo-guard-card" style="display:none;">
			<h2><?php esc_html_e( '.htaccess Redirect Code', 'turbo-guard' ); ?></h2>
			<p><?php esc_html_e( 'Add this code to your .htaccess file to redirect spam URLs to your homepage:', 'turbo-guard' ); ?></p>
			<textarea id="turbo-guard-htaccess-code" readonly style="width:100%; height:200px; font-family:monospace; font-size:12px;"></textarea>
			<button id="turbo-guard-copy-htaccess" class="button">
				<span class="dashicons dashicons-clipboard"></span>
				<?php esc_html_e( 'Copy to Clipboard', 'turbo-guard' ); ?>
			</button>
		</div>

		<!-- Action Result Notice -->
		<div id="turbo-guard-gsc-notice" class="turbo-guard-notice" style="display:none;"></div>

	<?php endif; ?>
</div>
