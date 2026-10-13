<?php
/**
 * Vulnerability Scanner Class.
 *
 * Checks installed plugins and themes against the WPScan Vulnerability Database
 * API and the free WordPress.org plugin/theme API for known CVEs and security issues.
 *
 * @package TurboGuard
 * @since 1.1.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Vulnerability scanner for plugins and themes.
 *
 * @since 1.1.0
 */
class Turbo_Guard_Vuln_Scanner {

	/**
	 * WPScan API endpoint. NOTE: v3 REQUIRES an API token — without one every
	 * request returns HTTP 403, so the scanner falls back to WordPress.org.
	 */
	const WPSCAN_API = 'https://wpscan.com/api/v3';

	/**
	 * Transient TTL — 12 hours to avoid hammering the API.
	 */
	const CACHE_TTL = 43200;

	/**
	 * Live WPScan API requests made during the current scan.
	 *
	 * @var int
	 */
	private static $api_live = 0;

	/**
	 * Items served from cache during the current scan.
	 *
	 * @var int
	 */
	private static $api_cached = 0;

	/**
	 * WPScan API requests that failed (network error, 401/403, 429, 5xx).
	 *
	 * @var int
	 */
	private static $api_errors = 0;

	/**
	 * Run a full vulnerability scan of installed plugins and themes.
	 *
	 * @since 1.1.0
	 * @return array {
	 *     @type array $plugins   Per-plugin vulnerability data.
	 *     @type array $themes    Per-theme vulnerability data.
	 *     @type array $wordpress WordPress core vulnerability data.
	 *     @type int   $total     Total number of vulnerabilities found.
	 *     @type string $scanned_at Datetime of scan.
	 * }
	 */
	public static function run_scan() {
		// Clear the site cache before scanning so results are fresh.
		turbo_guard_clear_site_cache();

		// Reset per-scan request counters.
		self::$api_live   = 0;
		self::$api_cached = 0;
		self::$api_errors = 0;

		$api_key = trim( get_option( 'turbo_guard_wpscan_api_key', '' ) );

		$results = array(
			'plugins'    => array(),
			'themes'     => array(),
			'wordpress'  => array(),
			'total'      => 0,
			'scanned_at' => current_time( 'mysql' ),
			'status'     => 'success',
			'source'     => 'wpscan',
			'message'    => '',
		);

		// WPScan v3 REQUIRES an API token — without it every request returns
		// HTTP 403. Decide up-front how to scan and validate the key if set.
		$use_wpscan = false;
		if ( '' !== $api_key ) {
			$validation = self::validate_api_key( $api_key );

			if ( 'ok' === $validation['status'] ) {
				$use_wpscan       = true;
				$results['quota'] = $validation['quota'];
			} elseif ( 'invalid' === $validation['status'] ) {
				$results['status']  = 'api_error';
				$results['source']  = 'wordpress_org';
				$results['message'] = sprintf(
					/* translators: %d: HTTP status code returned by the WPScan API. */
					__( 'WPScan rejected the configured API key (HTTP %d). The key may be invalid or expired, or your server may not be sending the Authorization header. Re-copy your key from wpscan.com and save it again in Settings. Showing limited WordPress.org status instead of detailed CVE data.', 'turbo-guard' ),
					(int) $validation['code']
				);
			} elseif ( 'rate_limited' === $validation['status'] ) {
				$results['status']  = 'api_error';
				$results['source']  = 'wordpress_org';
				$results['message'] = __( 'The WPScan API request limit for this key has been reached. Detailed CVE data will be available again once the limit resets (the free plan resets daily). Showing limited WordPress.org status instead.', 'turbo-guard' );
			} else {
				$results['status']  = 'api_error';
				$results['source']  = 'wordpress_org';
				$results['message'] = __( 'Could not reach the WPScan API. Showing limited WordPress.org status instead of detailed CVE data.', 'turbo-guard' );
			}
		} else {
			$results['status']  = 'no_api_key';
			$results['source']  = 'wordpress_org';
			$results['message'] = __( 'No WPScan API key is configured, so detailed CVE data is unavailable. Showing limited WordPress.org status instead. Add a free key in Settings for full results.', 'turbo-guard' );
		}

		// Scan plugins.
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();
		foreach ( $plugins as $plugin_file => $plugin_data ) {
			$slug = dirname( $plugin_file );
			if ( '.' === $slug ) {
				// Single-file plugin — use filename without extension.
				$slug = str_replace( '.php', '', $plugin_file );
			}

			if ( $use_wpscan ) {
				$vuln_list = self::check_plugin( $slug, $plugin_data['Version'], $api_key );
			} else {
				$vuln_list = self::check_wp_org( 'plugin', $slug, $plugin_data['Name'] );
			}

			if ( ! empty( $vuln_list ) ) {
				$results['plugins'][] = array(
					'slug'            => $slug,
					'name'            => $plugin_data['Name'],
					'version'         => $plugin_data['Version'],
					'vulnerabilities' => $vuln_list,
					'count'           => count( $vuln_list ),
				);
				$results['total'] += count( $vuln_list );
			}
		}

		// Scan themes.
		$themes = wp_get_themes();
		foreach ( $themes as $theme_slug => $theme ) {
			if ( $use_wpscan ) {
				$vuln_list = self::check_theme( $theme_slug, $theme->get( 'Version' ), $api_key );
			} else {
				$vuln_list = self::check_wp_org( 'theme', $theme_slug, $theme->get( 'Name' ) );
			}

			if ( ! empty( $vuln_list ) ) {
				$results['themes'][] = array(
					'slug'            => $theme_slug,
					'name'            => $theme->get( 'Name' ),
					'version'         => $theme->get( 'Version' ),
					'vulnerabilities' => $vuln_list,
					'count'           => count( $vuln_list ),
				);
				$results['total'] += count( $vuln_list );
			}
		}

		// Check WordPress core (WPScan only — WordPress.org has no equivalent).
		if ( $use_wpscan ) {
			$wp_vulns = self::check_wordpress_core( get_bloginfo( 'version' ), $api_key );
			if ( ! empty( $wp_vulns ) ) {
				$results['wordpress'] = $wp_vulns;
				$results['total']    += count( $wp_vulns );
			}
		}

		// Record how many items were checked and whether any request failed.
		$results['checked'] = self::$api_live + self::$api_cached;
		$results['errors']  = self::$api_errors;

		// If the WPScan API was used but some requests failed (e.g. the free
		// daily limit was reached mid-scan), don't report a clean result.
		if ( $use_wpscan && self::$api_errors > 0 && 'success' === $results['status'] ) {
			$results['status']  = 'api_error';
			$results['message'] = sprintf(
				/* translators: 1: failed request count, 2: total request count */
				__( 'WPScan was used, but %1$d of %2$d requests failed — results may be incomplete (the free daily limit may have been reached). Showing what was retrieved.', 'turbo-guard' ),
				self::$api_errors,
				$results['checked'] + self::$api_errors
			);
		}

		// Cache results.
		set_transient( 'turbo_guard_vuln_results', $results, self::CACHE_TTL );

		// Log event.
		Turbo_Guard_Scanner::log_event(
			'vuln_scan_complete',
			$results['total'] > 0 ? 'warning' : 'info',
			sprintf(
				/* translators: %d: vulnerability count */
				__( 'Vulnerability scan complete. %d vulnerabilities found.', 'turbo-guard' ),
				$results['total']
			)
		);

		// Send alert email if vulnerabilities found (Pro feature).
		if ( $results['total'] > 0 && turbo_guard_is_pro() && 'yes' === get_option( 'turbo_guard_notify_on_threats', 'yes' ) ) {
			self::send_vuln_alert( $results );
		}

		return $results;
	}

	/**
	 * Check a single plugin against WPScan API.
	 *
	 * Falls back to graceful empty result on API error.
	 *
	 * @since 1.1.0
	 * @param string $slug    Plugin slug.
	 * @param string $version Installed version.
	 * @return array
	 */
	public static function check_plugin( $slug, $version, $api_key = '' ) {
		$cache_key = 'turbo_guard_vuln_plugin_' . md5( $slug . $version );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			++self::$api_cached;
			return $cached;
		}

		$result = self::api_request( '/plugins/' . rawurlencode( $slug ), $api_key );

		$vulns = array();
		if ( ! is_wp_error( $result ) && isset( $result[ $slug ]['vulnerabilities'] ) ) {
			foreach ( $result[ $slug ]['vulnerabilities'] as $v ) {
				if ( self::affects_version( $v, $version ) ) {
					$vulns[] = self::normalise_vuln( $v );
				}
			}
		}

		set_transient( $cache_key, $vulns, self::CACHE_TTL );
		return $vulns;
	}

	/**
	 * Check a single theme against WPScan API.
	 *
	 * @since 1.1.0
	 * @param string $slug    Theme slug.
	 * @param string $version Installed version.
	 * @return array
	 */
	public static function check_theme( $slug, $version, $api_key = '' ) {
		$cache_key = 'turbo_guard_vuln_theme_' . md5( $slug . $version );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			++self::$api_cached;
			return $cached;
		}

		$result = self::api_request( '/themes/' . rawurlencode( $slug ), $api_key );

		$vulns = array();
		if ( ! is_wp_error( $result ) && isset( $result[ $slug ]['vulnerabilities'] ) ) {
			foreach ( $result[ $slug ]['vulnerabilities'] as $v ) {
				if ( self::affects_version( $v, $version ) ) {
					$vulns[] = self::normalise_vuln( $v );
				}
			}
		}

		set_transient( $cache_key, $vulns, self::CACHE_TTL );
		return $vulns;
	}

	/**
	 * Check WordPress core version against WPScan API.
	 *
	 * @since 1.1.0
	 * @param string $version Installed WP version.
	 * @return array
	 */
	public static function check_wordpress_core( $version, $api_key = '' ) {
		$cache_key = 'turbo_guard_vuln_wp_' . md5( $version );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			++self::$api_cached;
			return $cached;
		}

		$slug   = str_replace( '.', '', $version );
		$result = self::api_request( '/wordpresses/' . rawurlencode( $slug ), $api_key );

		$vulns = array();
		if ( ! is_wp_error( $result ) && isset( $result[ $slug ]['vulnerabilities'] ) ) {
			foreach ( $result[ $slug ]['vulnerabilities'] as $v ) {
				$vulns[] = self::normalise_vuln( $v );
			}
		}

		set_transient( $cache_key, $vulns, self::CACHE_TTL );
		return $vulns;
	}

	/**
	 * Make an authenticated request to the WPScan API.
	 *
	 * @since 1.1.0
	 * @param string $endpoint API path (without base URL).
	 * @param string $api_key  Optional WPScan API key.
	 * @return array|WP_Error Decoded response body or error.
	 */
	private static function api_request( $endpoint, $api_key = '' ) {
		$args = array(
			'timeout' => 10,
			'headers' => array(
				'Accept' => 'application/json',
			),
		);

		if ( $api_key ) {
			$args['headers']['Authorization'] = 'Token token=' . $api_key;
		}

		$response = wp_remote_get( self::WPSCAN_API . $endpoint, $args );

		if ( is_wp_error( $response ) ) {
			++self::$api_errors;
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 200 === $code ) {
			++self::$api_live;
			return json_decode( wp_remote_retrieve_body( $response ), true );
		}

		// 404 means WPScan does not track this slug — no data, not a failure.
		if ( 404 === $code ) {
			return array();
		}

		++self::$api_errors;
		return new WP_Error( 'wpscan_api_error', 'WPScan API returned HTTP ' . $code );
	}

	/**
	 * Validate a WPScan API key using the lightweight /status endpoint.
	 *
	 * Unlike the resource endpoints (which answer 403 for both a missing and an
	 * invalid token), `/status` returns 401 for a bad token and 200 for a good
	 * one — and the 200 body reports the remaining request quota, so we can tell
	 * an expired key apart from an exhausted daily limit.
	 *
	 * @since 1.1.3
	 * @param string $api_key WPScan API token.
	 * @return array {
	 *     @type string   $status 'ok' | 'invalid' | 'rate_limited' | 'unknown'.
	 *     @type int      $code   HTTP status code returned by the API.
	 *     @type int|null $quota  Remaining requests, when known.
	 * }
	 */
	private static function validate_api_key( $api_key ) {
		$response = wp_remote_get(
			self::WPSCAN_API . '/status',
			array(
				'timeout' => 10,
				'headers' => array(
					'Accept'        => 'application/json',
					'Authorization' => 'Token token=' . $api_key,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'status' => 'unknown',
				'code'   => 0,
				'quota'  => null,
			);
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 200 === $code ) {
			$body  = json_decode( wp_remote_retrieve_body( $response ), true );
			$quota = null;
			if ( is_array( $body ) && isset( $body['requests_remaining'] ) ) {
				$quota = (int) $body['requests_remaining'];
			}

			// A valid key with no requests left cannot fetch CVE data.
			if ( null !== $quota && $quota <= 0 ) {
				return array(
					'status' => 'rate_limited',
					'code'   => $code,
					'quota'  => $quota,
				);
			}

			return array(
				'status' => 'ok',
				'code'   => $code,
				'quota'  => $quota,
			);
		}

		if ( 401 === $code || 403 === $code ) {
			return array(
				'status' => 'invalid',
				'code'   => $code,
				'quota'  => null,
			);
		}

		if ( 429 === $code ) {
			return array(
				'status' => 'rate_limited',
				'code'   => $code,
				'quota'  => 0,
			);
		}

		return array(
			'status' => 'unknown',
			'code'   => $code,
			'quota'  => null,
		);
	}

	/**
	 * WordPress.org fallback: flag plugins/themes that have been removed
	 * ("closed") from the official repository — a common signal of a security
	 * problem or abandonment. Used when WPScan is unavailable.
	 *
	 * @since 1.1.3
	 * @param string $type 'plugin' or 'theme'.
	 * @param string $slug Repository slug.
	 * @param string $name Human-readable item name.
	 * @return array Normalised vulnerability list (0 or 1 entries).
	 */
	private static function check_wp_org( $type, $slug, $name ) {
		$cache_key = 'turbo_guard_wp_org_' . $type . '_' . md5( $slug );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return $cached;
		}

		$url = sprintf(
			'https://api.wordpress.org/%ss/info/1.2/?action=%s_information&request[slug]=%s',
			$type,
			$type,
			rawurlencode( $slug )
		);

		$response = wp_remote_get( $url, array( 'timeout' => 8 ) );

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			set_transient( $cache_key, array(), self::CACHE_TTL );
			return array();
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) || empty( $body['closed'] ) ) {
			set_transient( $cache_key, array(), self::CACHE_TTL );
			return array();
		}

		$vulns = array(
			array(
				'id'         => 'wp-org-closed-' . $type . '-' . $slug,
				'title'      => sprintf(
					/* translators: %s: plugin/theme name */
					__( '%s has been removed from WordPress.org', 'turbo-guard' ),
					$name
				),
				'type'       => 'CLOSED',
				'fixed_in'   => null,
				'cvss'       => null,
				'cve'        => array(),
				'url'        => sprintf( 'https://wordpress.org/%ss/%s/', $type, rawurlencode( $slug ) ),
				'created_at' => ! empty( $body['closed_date'] ) ? $body['closed_date'] : '',
				'severity'   => 'medium',
			),
		);

		set_transient( $cache_key, $vulns, self::CACHE_TTL );
		return $vulns;
	}

	/**
	 * Check whether a vulnerability affects a given installed version.
	 *
	 * @since 1.1.0
	 * @param array  $vuln    Vulnerability data from API.
	 * @param string $version Installed version.
	 * @return bool True if the installed version is affected.
	 */
	private static function affects_version( $vuln, $version ) {
		// If no fixed-in data, assume it affects the current version.
		if ( empty( $vuln['fixed_in'] ) ) {
			return true;
		}

		// Installed version is older than the fixed version → affected.
		return version_compare( $version, $vuln['fixed_in'], '<' );
	}

	/**
	 * Normalise a raw WPScan vulnerability array to a consistent shape.
	 *
	 * @since 1.1.0
	 * @param array $raw Raw vulnerability from API.
	 * @return array Normalised vulnerability.
	 */
	private static function normalise_vuln( $raw ) {
		return array(
			'id'         => $raw['id'] ?? '',
			'title'      => $raw['title'] ?? __( 'Unknown vulnerability', 'turbo-guard' ),
			'type'       => $raw['vuln_type'] ?? 'UNKNOWN',
			'fixed_in'   => $raw['fixed_in'] ?? null,
			'cvss'       => $raw['cvss'] ?? null,
			'cve'        => ! empty( $raw['references']['cve'] ) ? $raw['references']['cve'] : array(),
			'url'        => ! empty( $raw['references']['url'] ) ? $raw['references']['url'][0] : '',
			'created_at' => $raw['created_at'] ?? '',
			'severity'   => self::severity_from_cvss( $raw['cvss']['score'] ?? null ),
		);
	}

	/**
	 * Map a CVSS score to a severity label.
	 *
	 * @since 1.1.0
	 * @param float|null $score CVSS score (0-10).
	 * @return string Severity label.
	 */
	private static function severity_from_cvss( $score ) {
		if ( null === $score ) {
			return 'medium';
		}
		$score = (float) $score;
		if ( $score >= 9.0 ) {
			return 'critical';
		}
		if ( $score >= 7.0 ) {
			return 'high';
		}
		if ( $score >= 4.0 ) {
			return 'medium';
		}
		return 'low';
	}

	/**
	 * Get the cached vulnerability results (or null if not scanned yet).
	 *
	 * @since 1.1.0
	 * @return array|false
	 */
	public static function get_cached_results() {
		return get_transient( 'turbo_guard_vuln_results' );
	}

	/**
	 * Send email alert about new vulnerabilities.
	 *
	 * @since 1.1.0
	 * @param array $results Scan results.
	 */
	private static function send_vuln_alert( $results ) {
		$email = get_option( 'turbo_guard_notify_admin_email', get_option( 'admin_email' ) );
		if ( ! $email ) {
			return;
		}

		$subject = sprintf(
			/* translators: 1: site name, 2: count */
			__( '[%1$s] Turbo Guard: %2$d Vulnerabilities Found', 'turbo-guard' ),
			get_bloginfo( 'name' ),
			$results['total']
		);

		$body  = sprintf(
			/* translators: %d: number of vulnerability issues found */
			__( "Turbo Guard vulnerability scan found %d issue(s):\n\n", 'turbo-guard' ),
			$results['total']
		);

		foreach ( $results['plugins'] as $plugin ) {
			$body .= sprintf( "Plugin: %s v%s — %d vulnerability(s)\n", $plugin['name'], $plugin['version'], $plugin['count'] );
			foreach ( $plugin['vulnerabilities'] as $v ) {
				$body .= "  - {$v['title']}" . ( $v['fixed_in'] ? " (fixed in {$v['fixed_in']})" : ' (no fix yet)' ) . "\n";
			}
		}

		foreach ( $results['themes'] as $theme ) {
			$body .= sprintf( "Theme: %s v%s — %d vulnerability(s)\n", $theme['name'], $theme['version'], $theme['count'] );
		}

		$body .= "\n" . sprintf(
			/* translators: %s: URL to view vulnerability details */
			__( 'View details: %s', 'turbo-guard' ),
			admin_url( 'admin.php?page=turbo-guard-vulnerabilities' )
		);

		wp_mail( $email, $subject, $body );
	}
}
