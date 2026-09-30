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
			if ( 'ok' === $validation ) {
				$use_wpscan = true;
			} elseif ( 'invalid' === $validation ) {
				$results['status']  = 'api_error';
				$results['source']  = 'wordpress_org';
				$results['message'] = __( 'The configured WPScan API key is invalid or expired. Showing limited WordPress.org status instead of detailed CVE data.', 'turbo-guard' );
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
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== (int) $code ) {
			return new WP_Error( 'wpscan_api_error', 'WPScan API returned HTTP ' . $code );
		}

		return json_decode( wp_remote_retrieve_body( $response ), true );
	}

	/**
	 * Validate a WPScan API key with a lightweight request.
	 *
	 * @since 1.1.3
	 * @param string $api_key WPScan API token.
	 * @return string 'ok' | 'invalid' | 'unknown'.
	 */
	private static function validate_api_key( $api_key ) {
		$response = wp_remote_get(
			self::WPSCAN_API . '/plugins/akismet',
			array(
				'timeout' => 10,
				'headers' => array(
					'Accept'        => 'application/json',
					'Authorization' => 'Token token=' . $api_key,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return 'unknown';
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 200 === $code ) {
			return 'ok';
		}
		if ( 401 === $code || 403 === $code ) {
			return 'invalid';
		}
		return 'unknown';
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
