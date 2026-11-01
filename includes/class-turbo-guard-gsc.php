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
	 * Whether a URL looks like SEO spam (server-side spam detection).
	 *
	 * Used by the Pro add-on's scheduled (cron) GSC check so spam can be
	 * detected without a browser. This is intentionally more conservative than
	 * the client-side pattern list on the GSC page: it only fires on high-
	 * confidence signals (CJK text, prefix-agnostic numeric doorway IDs, brand
	 * keywords, PHP dropped in a core asset dir) so automated email alerts are
	 * not polluted by false positives like year archives.
	 *
	 * @since 1.1.7
	 * @param string $url Full URL.
	 * @return string|false Spam type label, or false if clean.
	 */
	public static function is_spam_url( $url ) {
		$url     = (string) $url;
		$decoded = rawurldecode( $url );
		$lower   = strtolower( $decoded );

		// Japanese/Chinese/Korean characters in the URL.
		if ( preg_match( Turbo_Guard_SEO_Spam_Detector::CJK_REGEX, $decoded ) ) {
			return 'cjk';
		}

		// Query-string doorway spam: /?some-key/194927850 or ?some-key=194927850.
		// The key is arbitrary (it changes per campaign/site) — the signal is
		// the 6+ digit numeric ID, never the word before it.
		// Checked BEFORE the path-doorway rule — a bare "/" path carries no
		// numeric signature itself, but its query string does, and the generic
		// path regex would otherwise misclassify it (its digits live after the
		// "?" inside the query, which the path regex must not match).
		if ( preg_match( '~[?&][a-z0-9_-]+(?:/|=|%2f)\d{6,}~i', $lower ) ) {
			return 'doorway_query';
		}

		// Doorway numeric-ID path spam: /<any-prefix>/98254733 (prefix-agnostic).
		if ( preg_match( '~/\d{6,}(?:[/?#]|$)~', $lower ) ) {
			return 'doorway';
		}

		// PHP dropped into a core asset directory.
		if ( preg_match( '~/wp-admin/(images|css|js)/.+\.php$~i', $lower ) ) {
			return 'php_in_admin';
		}

		// Luxury/pharma brand keywords (whole-word match).
		if ( false !== Turbo_Guard_SEO_Spam_Detector::has_spam_keyword( $decoded ) ) {
			return 'spam_keyword';
		}

		return false;
	}

	/**
	 * Human-readable label for a spam type returned by is_spam_url().
	 *
	 * @since 1.1.7
	 * @param string $type Spam type key.
	 * @return string Label.
	 */
	public static function get_spam_label( $type ) {
		$labels = array(
			'cjk'           => __( 'Japanese/Chinese Spam', 'turbo-guard' ),
			'doorway'       => __( 'Doorway Spam (numeric ID)', 'turbo-guard' ),
			'doorway_query' => __( 'Doorway Spam (query)', 'turbo-guard' ),
			'php_in_admin'  => __( 'PHP in Admin', 'turbo-guard' ),
			'spam_keyword'  => __( 'Brand Keyword Spam', 'turbo-guard' ),
			'sitemap'       => __( 'Sitemap Spam', 'turbo-guard' ),
		);

		return isset( $labels[ $type ] ) ? $labels[ $type ] : __( 'Spam', 'turbo-guard' );
	}

	/**
	 * Build .htaccess 410-Gone blocking rules for a list of spam URLs.
	 *
	 * Numeric doorway IDs are collapsed into one rule per prefix
	 * (e.g. /whatever/98254733 → block /whatever/<digits>) so the legitimate
	 * /whatever page stays untouched. The prefix is read from the URL itself —
	 * it is never hardcoded, because each campaign uses a different word.
	 *
	 * @since 1.1.7
	 * @param array $urls Spam URL strings.
	 * @return string .htaccess rules.
	 */
	public static function build_htaccess_rules( $urls ) {
		$urls        = is_array( $urls ) ? $urls : array();
		$doorways    = array(); // Numeric-ID doorway prefix path => true.
		$exacts      = array(); // Exact relative path => true.
		$query_conds = array(); // Query-string doorway regex => true.
		$skipped     = array(); // php_in_admin files: delete, don't block.

		foreach ( $urls as $url ) {
			$url  = (string) $url;
			$type = self::is_spam_url( $url );

			// PHP dropped into a core asset directory is a file to DELETE with
			// the scanner, not a URL to return 410 for.
			if ( 'php_in_admin' === $type ) {
				$skipped[ $url ] = true;
				continue;
			}

			$parts = wp_parse_url( $url );
			$path  = isset( $parts['path'] ) ? $parts['path'] : '';
			$query = isset( $parts['query'] ) ? $parts['query'] : '';

			// Query-string doorway spam → a %{QUERY_STRING} RewriteCond.
			if ( 'doorway_query' === $type && '' !== $query ) {
				$cond = self::query_doorway_regex( $query );
				if ( '' !== $cond ) {
					$query_conds[ $cond ] = true;
				}
				continue;
			}

			// Numeric-ID doorway in the path → collapse into one prefix rule.
			if ( 'doorway' === $type ) {
				$segments = array_values( array_filter( explode( '/', $path ), 'strlen' ) );
				if ( count( $segments ) >= 2 ) {
					$prefix           = array_slice( $segments, 0, -1 );
					$prefix           = '/' . implode( '/', array_map( 'rawurlencode', $prefix ) ) . '/';
					$doorways[ $prefix ] = true;
					continue;
				}
			}

			// Everything else (CJK, brand keyword, sitemap fallback): exact path.
			$rel = self::normalize_rewrite_path( $path );
			if ( '' !== $rel ) {
				$exacts[ $rel ] = true;
			}
		}

		$rules  = "# Turbo Guard - SEO Spam URL Blocking (410 Gone)\n";
		$rules .= "# Generated: " . gmdate( 'c' ) . "\n";
		$rules .= "# Serves \"410 Gone\" for spam URLs so Google permanently deindexes them on its next crawl.\n";

		if ( empty( $doorways ) && empty( $exacts ) && empty( $query_conds ) ) {
			$rules .= "# (No blockable URL patterns were found.)\n";
			foreach ( array_keys( $skipped ) as $skip ) {
				$rules .= "# Delete with Scanner (not a URL): {$skip}\n";
			}
			return $rules;
		}

		$rules .= "<IfModule mod_rewrite.c>\n";
		$rules .= "RewriteEngine On\n";

		foreach ( array_keys( $doorways ) as $prefix ) {
			$rel = ltrim( $prefix, '/' );
			$rules .= "\n# Block doorway: {$prefix}<number>\n";
			$rules .= 'RewriteRule ^' . preg_quote( $rel, '~' ) . "[0-9]+/?$ - [G,L]\n";
		}

		foreach ( array_keys( $exacts ) as $rel ) {
			$rules .= "\n# Block: /{$rel}\n";
			$rules .= 'RewriteRule ^' . preg_quote( $rel, '~' ) . "/?$ - [G,L]\n";
		}

		if ( ! empty( $query_conds ) ) {
			$conds = array_keys( $query_conds );
			$last  = count( $conds ) - 1;
			$rules .= "\n# Block query-string doorway spam.\n";
			foreach ( $conds as $i => $cond ) {
				$flags = 'NC' . ( $i < $last ? ',OR' : '' );
				$rules .= 'RewriteCond %{QUERY_STRING} ' . $cond . " [{$flags}]\n";
			}
			$rules .= "RewriteRule ^ - [G,L]\n";
		}

		foreach ( array_keys( $skipped ) as $skip ) {
			$rules .= "# Delete with Scanner (not a URL): {$skip}\n";
		}

		$rules .= "</IfModule>\n";

		return $rules;
	}

	/**
	 * Canonicalize a URL path into the percent-encoded form Apache matches.
	 *
	 * mod_rewrite matches the request path exactly as the browser sends it —
	 * percent-encoded. GSC/sitemap URLs may arrive raw (UTF-8) or already
	 * encoded, so decode first, then re-encode each segment to a canonical form
	 * that matches what a crawler actually requests.
	 *
	 * @since 1.1.7
	 * @param string $path URL path.
	 * @return string Canonical relative path (no leading/trailing slash), or ''.
	 */
	private static function normalize_rewrite_path( $path ) {
		$path     = rawurldecode( (string) $path );
		$segments = array_values( array_filter( explode( '/', $path ), 'strlen' ) );
		$segments = array_map( 'rawurlencode', $segments );
		return implode( '/', $segments );
	}

	/**
	 * Build a %{QUERY_STRING} regex for a single query-string doorway URL.
	 *
	 * The key is scoped so the rule only fires for the detected spam key (and
	 * not every numeric query parameter on the site).
	 *
	 * @since 1.1.7
	 * @param string $query Raw query string.
	 * @return string Apache RewriteCond regex, or '' if it doesn't match.
	 */
	private static function query_doorway_regex( $query ) {
		$query = (string) $query;
		if ( preg_match( '~(?:^|&)([a-z0-9_-]+)(?:/|=|%2[fF])([0-9]{6,})~i', $query, $m ) ) {
			return '(?:^|&)' . preg_quote( $m[1], '~' ) . '(?:/|=|%2[fF])[0-9]{6,}';
		}
		return '';
	}

	/**
	 * Sanitize a list of URLs for rule generation without mangling them.
	 *
	 * esc_url_raw() re-encodes/strips characters (it can mangle CJK and
	 * percent-encoded query strings), so we validate scheme + strip control
	 * characters instead. The result is only parsed and preg_quote()d when
	 * building .htaccess rules, so this is safe.
	 *
	 * @since 1.1.7
	 * @param array $urls Raw URL strings.
	 * @return array Cleaned http(s) URLs (unique, no control chars).
	 */
	public static function sanitize_url_list( $urls ) {
		$clean = array();
		foreach ( (array) $urls as $url ) {
			$url = trim( (string) $url );
			if ( '' === $url ) {
				continue;
			}

			$scheme = wp_parse_url( $url, PHP_URL_SCHEME );
			if ( empty( $scheme ) || ! in_array( strtolower( $scheme ), array( 'http', 'https' ), true ) ) {
				continue;
			}

			$url = preg_replace( '/[\x00-\x1F\x7F]/', '', $url );
			if ( '' !== $url ) {
				$clean[] = $url;
			}
		}
		return array_values( array_unique( $clean ) );
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
		if ( ! isset( $_GET['oauth_callback'] ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'turbo-guard' ) );
		}

		$fallback = admin_url( 'admin.php?page=turbo-guard-gsc' );

		// Google redirected back with an error (e.g. access_denied) instead of a code.
		if ( isset( $_GET['error'] ) ) {
			$error = sanitize_text_field( wp_unslash( $_GET['error'] ) );
			wp_safe_redirect( add_query_arg( 'oauth_error', rawurlencode( $error ), $fallback ) );
			exit;
		}

		if ( ! isset( $_GET['code'] ) ) {
			return;
		}

		// Verify the OAuth state to prevent CSRF (an attacker linking their own Google account to this site).
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		if ( ! wp_verify_nonce( $state, 'turbo_guard_gsc_oauth' ) ) {
			wp_safe_redirect( add_query_arg( 'oauth_error', rawurlencode( 'invalid_state' ), $fallback ) );
			exit;
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
			wp_safe_redirect( add_query_arg( 'oauth_error', rawurlencode( $response->get_error_message() ), $fallback ) );
			exit;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( isset( $body['access_token'] ) ) {
			update_option( 'turbo_guard_gsc_access_token', sanitize_text_field( $body['access_token'] ) );
			update_option( 'turbo_guard_gsc_refresh_token', sanitize_text_field( $body['refresh_token'] ?? '' ) );
			update_option( 'turbo_guard_gsc_token_expires', time() + absint( $body['expires_in'] ?? 3600 ) );

			wp_safe_redirect( add_query_arg( 'connected', '1', $fallback ) );
			exit;
		}

		// Token exchange failed (e.g. invalid_client, invalid_grant).
		$error = isset( $body['error'] ) ? $body['error'] : 'unknown_error';
		wp_safe_redirect( add_query_arg( 'oauth_error', rawurlencode( $error ), $fallback ) );
		exit;
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
			$message  = isset( $body['error']['message'] ) ? $body['error']['message'] : 'API error';
			$err_code = 'gsc_api_error';
			if ( 403 === (int) $code || false !== strpos( $message, 'sufficient permission' ) || false !== strpos( $message, 'does not have access' ) ) {
				$err_code = 'gsc_permission_denied';
			} elseif ( 404 === (int) $code || false !== strpos( $message, 'not found' ) ) {
				$err_code = 'gsc_not_found';
			}
			return new WP_Error( $err_code, $message );
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
		// Try the URL-prefix property first (e.g. https://example.com/), then fall
		// back to a Domain property (sc-domain:example.com) which many users
		// register instead.
		$result = $this->query_indexed_urls( $site_url );

		if ( is_wp_error( $result ) && in_array( $result->get_error_code(), array( 'gsc_permission_denied', 'gsc_not_found' ), true ) ) {
			$host = wp_parse_url( $site_url, PHP_URL_HOST );
			if ( $host ) {
				$result = $this->query_indexed_urls( 'sc-domain:' . $host );
			}
		}

		return $result;
	}

	/**
	 * Query the Search Analytics API for a single property.
	 *
	 * @since 1.4.0
	 * @param string $site_url Site property (URL-prefix or sc-domain:).
	 * @return array|WP_Error List of URLs or error.
	 */
	private function query_indexed_urls( $site_url ) {
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
	 * NOTE: Google does NOT provide a programmatic URL-removal API for general
	 * web pages. The Indexing API (urlNotifications:publish) is restricted to
	 * JobPosting and BroadcastEvent structured data, and the Search Console
	 * "Removals" tool is UI-only (manual, one URL at a time, ~6 months).
	 *
	 * The correct permanent deindex path is 404/410 + re-crawl, which the
	 * plugin supports by generating .htaccess 410-Gone blocking rules.
	 *
	 * @since 1.1.0
	 * @param string $site_url Site URL.
	 * @param string $url      URL to remove.
	 * @return WP_Error Always an error explaining why this is unavailable.
	 */
	public function request_url_removal( $site_url, $url ) {
		return new WP_Error(
			'gsc_no_removal_api',
			__( 'Google no longer provides a programmatic URL-removal API. Use the .htaccess 410-Gone blocking workflow instead, and submit critical URLs manually in the Search Console "Removals" tool.', 'turbo-guard' )
		);
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
