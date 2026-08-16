<?php
/**
 * Google Search Console Integration Class.
 *
 * Handles OAuth authentication, URL fetching, removal requests, and sitemap resubmission.
 *
 * @package TurboGuard
 * @since 1.1.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Google Search Console integration.
 *
 * @since 1.1.0
 */
class Turbo_Guard_GSC {

	/**
	 * Google OAuth client ID.
	 *
	 * @var string
	 */
	private $client_id = '';

	/**
	 * Google OAuth client secret.
	 *
	 * @var string
	 */
	private $client_secret = '';

	/**
	 * OAuth redirect URI.
	 *
	 * @var string
	 */
	private $redirect_uri = '';

	/**
	 * Access token.
	 *
	 * @var string
	 */
	private $access_token = '';

	/**
	 * Refresh token.
	 *
	 * @var string
	 */
	private $refresh_token = '';

	/**
	 * Constructor.
	 *
	 * @since 1.1.0
	 */
	public function __construct() {
		// Load saved credentials.
		$this->client_id     = get_option( 'turbo_guard_gsc_client_id', '' );
		$this->client_secret = get_option( 'turbo_guard_gsc_client_secret', '' );
		$this->redirect_uri  = admin_url( 'admin.php?page=turbo-guard-gsc&oauth_callback=1' );
		$this->access_token  = get_option( 'turbo_guard_gsc_access_token', '' );
		$this->refresh_token = get_option( 'turbo_guard_gsc_refresh_token', '' );

		// Handle OAuth callback.
		add_action( 'admin_init', array( $this, 'handle_oauth_callback' ) );
	}

	/**
	 * Check if GSC is connected.
	 *
	 * @since 1.1.0
	 * @return bool True if access token exists.
	 */
	public function is_connected() {
		return ! empty( $this->access_token );
	}

	/**
	 * Get OAuth authorization URL.
	 *
	 * @since 1.1.0
	 * @return string Authorization URL.
	 */
	public function get_auth_url() {
		// CSRF protection for the OAuth redirect: verified in handle_oauth_callback().
		$state = wp_create_nonce( 'turbo_guard_gsc_oauth' );

		$params = array(
			'client_id'     => $this->client_id,
			'redirect_uri'  => $this->redirect_uri,
			'response_type' => 'code',
			'scope'         => 'https://www.googleapis.com/auth/webmasters',
			'access_type'   => 'offline',
			'prompt'        => 'consent',
			'state'         => $state,
		);

		return 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query( $params );
	}

	/**
	 * Handle OAuth callback from Google.
	 *
	 * @since 1.1.0
	 */
	public function handle_oauth_callback() {
		if ( ! isset( $_GET['oauth_callback'] ) || ! isset( $_GET['code'] ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'turbo-guard' ) );
		}

		// Verify the OAuth state to prevent CSRF (an attacker linking their own Google account to this site).
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		if ( ! wp_verify_nonce( $state, 'turbo_guard_gsc_oauth' ) ) {
			wp_die( esc_html__( 'Invalid or expired OAuth request. Please try connecting again.', 'turbo-guard' ) );
		}

		$code = sanitize_text_field( wp_unslash( $_GET['code'] ) );

		// Exchange code for access token.
		$response = wp_remote_post(
			'https://oauth2.googleapis.com/token',
			array(
				'body' => array(
					'code'          => $code,
					'client_id'     => $this->client_id,
					'client_secret' => $this->client_secret,
					'redirect_uri'  => $this->redirect_uri,
					'grant_type'    => 'authorization_code',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			wp_die(
				esc_html(
					sprintf(
						/* translators: %s: error message */
						__( 'OAuth error: %s', 'turbo-guard' ),
						$response->get_error_message()
					)
				)
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( isset( $body['access_token'] ) ) {
			update_option( 'turbo_guard_gsc_access_token', sanitize_text_field( $body['access_token'] ) );
			update_option( 'turbo_guard_gsc_refresh_token', sanitize_text_field( $body['refresh_token'] ) );
			update_option( 'turbo_guard_gsc_token_expires', time() + absint( $body['expires_in'] ) );

			wp_safe_redirect( admin_url( 'admin.php?page=turbo-guard-gsc&connected=1' ) );
			exit;
		} else {
			wp_die(
				esc_html(
					sprintf(
						/* translators: %s: error message */
						__( 'OAuth error: %s', 'turbo-guard' ),
						$body['error_description'] ?? __( 'Unknown error', 'turbo-guard' )
					)
				)
			);
		}
	}

	/**
	 * Refresh access token if expired.
	 *
	 * @since 1.1.0
	 * @return bool True on success.
	 */
	private function refresh_token_if_needed() {
		$expires = get_option( 'turbo_guard_gsc_token_expires', 0 );

		// Refresh if expired or expiring in next 5 minutes.
		if ( time() < ( $expires - 300 ) ) {
			return true; // Not expired.
		}

		$response = wp_remote_post(
			'https://oauth2.googleapis.com/token',
			array(
				'body' => array(
					'client_id'     => $this->client_id,
					'client_secret' => $this->client_secret,
					'refresh_token' => $this->refresh_token,
					'grant_type'    => 'refresh_token',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( isset( $body['access_token'] ) ) {
			update_option( 'turbo_guard_gsc_access_token', sanitize_text_field( $body['access_token'] ) );
			update_option( 'turbo_guard_gsc_token_expires', time() + absint( $body['expires_in'] ) );
			$this->access_token = $body['access_token'];
			return true;
		}

		return false;
	}

	/**
	 * Make authenticated API request to Google Search Console.
	 *
	 * @since 1.1.0
	 * @param string $endpoint API endpoint.
	 * @param string $method   HTTP method (GET, POST, DELETE).
	 * @param array  $body     Request body for POST.
	 * @return array|WP_Error Response body or error.
	 */
	private function api_request( $endpoint, $method = 'GET', $body = null ) {
		$this->refresh_token_if_needed();

		$args = array(
			'method'  => $method,
			'headers' => array(
				'Authorization' => 'Bearer ' . $this->access_token,
				'Content-Type'  => 'application/json',
			),
		);

		if ( 'POST' === $method && $body ) {
			$args['body'] = wp_json_encode( $body );
		}

		$response = wp_remote_request( $endpoint, $args );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( $code >= 400 ) {
			return new WP_Error( 'gsc_api_error', $body['error']['message'] ?? 'API error' );
		}

		return $body;
	}

	/**
	 * Get indexed URLs from Search Console.
	 *
	 * @since 1.1.0
	 * @param string $site_url Site URL (e.g., 'https://example.com/').
	 * @return array|WP_Error List of URLs or error.
	 */
	public function get_indexed_urls( $site_url ) {
		// GSC Search Analytics API endpoint.
		$endpoint = 'https://www.googleapis.com/webmasters/v3/sites/' . rawurlencode( $site_url ) . '/searchAnalytics/query';

		// Request last 30 days of indexed pages.
		$body = array(
			'startDate'  => gmdate( 'Y-m-d', strtotime( '-30 days' ) ),
			'endDate'    => gmdate( 'Y-m-d' ),
			'dimensions' => array( 'page' ),
			'rowLimit'   => 25000, // Max allowed by API.
		);

		$result = $this->api_request( $endpoint, 'POST', $body );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$urls = array();
		if ( isset( $result['rows'] ) ) {
			foreach ( $result['rows'] as $row ) {
				$urls[] = $row['keys'][0];
			}
		}

		return $urls;
	}

	/**
	 * Submit URL removal request.
	 *
	 * @since 1.1.0
	 * @param string $site_url Site URL.
	 * @param string $url      URL to remove.
	 * @return bool|WP_Error True on success, error on failure.
	 */
	public function request_url_removal( $site_url, $url ) {
		$endpoint = 'https://searchconsole.googleapis.com/v1/urlNotifications:publish';

		$body = array(
			'url'  => $url,
			'type' => 'URL_DELETED',
		);

		$result = $this->api_request( $endpoint, 'POST', $body );

		return ! is_wp_error( $result );
	}

	/**
	 * Submit sitemap to Google.
	 *
	 * @since 1.1.0
	 * @param string $site_url    Site URL.
	 * @param string $sitemap_url Sitemap URL.
	 * @return bool|WP_Error True on success.
	 */
	public function submit_sitemap( $site_url, $sitemap_url ) {
		$endpoint = 'https://www.googleapis.com/webmasters/v3/sites/' . rawurlencode( $site_url ) . '/sitemaps/' . rawurlencode( $sitemap_url );

		$result = $this->api_request( $endpoint, 'PUT' );

		return ! is_wp_error( $result );
	}

	/**
	 * Disconnect GSC integration.
	 *
	 * @since 1.1.0
	 */
	public static function disconnect() {
		delete_option( 'turbo_guard_gsc_access_token' );
		delete_option( 'turbo_guard_gsc_refresh_token' );
		delete_option( 'turbo_guard_gsc_token_expires' );
	}
}
