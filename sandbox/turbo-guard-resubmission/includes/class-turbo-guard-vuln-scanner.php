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
	 * WPScan API endpoint (free tier, no key required for basic lookups).
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
		$results = array(
			'plugins'    => array(),
			'themes'     => array(),
			'wordpress'  => array(),
			'total'      => 0,
			'scanned_at' => current_time( 'mysql' ),
		);

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

			$vuln = self::check_plugin( $slug, $plugin_data['Version'] );
			if ( ! empty( $vuln['vulnerabilities'] ) ) {
				$results['plugins'][] = array(
					'slug'            => $slug,
					'name'            => $plugin_data['Name'],
					'version'         => $plugin_data['Version'],
					'vulnerabilities' => $vuln['vulnerabilities'],
					'count'           => count( $vuln['vulnerabilities'] ),
				);
				$results['total'] += count( $vuln['vulnerabilities'] );
			}
		}

		// Scan themes.
		$themes = wp_get_themes();
		foreach ( $themes as $theme_slug => $theme ) {
			$vuln = self::check_theme( $theme_slug, $theme->get( 'Version' ) );
			if ( ! empty( $vuln['vulnerabilities'] ) ) {
				$results['themes'][] = array(
					'slug'            => $theme_slug,
					'name'            => $theme->get( 'Name' ),
					'version'         => $theme->get( 'Version' ),
					'vulnerabilities' => $vuln['vulnerabilities'],
					'count'           => count( $vuln['vulnerabilities'] ),
				);
				$results['total'] += count( $vuln['vulnerabilities'] );
			}
		}

		// Check WordPress core.
		$wp_vulns = self::check_wordpress_core( get_bloginfo( 'version' ) );
		if ( ! empty( $wp_vulns['vulnerabilities'] ) ) {
			$results['wordpress'] = $wp_vulns['vulnerabilities'];
			$results['total']    += count( $wp_vulns['vulnerabilities'] );
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

		// Send alert email if vulnerabilities found.
		if ( $results['total'] > 0 && 'yes' === get_option( 'turbo_guard_notify_on_threats', 'yes' ) ) {
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
	public static function check_plugin( $slug, $version ) {
		$cache_key = 'turbo_guard_vuln_plugin_' . md5( $slug . $version );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return $cached;
		}

		$api_key = get_option( 'turbo_guard_wpscan_api_key', '' );
		$result  = self::api_request( '/plugins/' . rawurlencode( $slug ), $api_key );

		$vulns = array();
		if ( ! is_wp_error( $result ) && isset( $result[ $slug ]['vulnerabilities'] ) ) {
			foreach ( $result[ $slug ]['vulnerabilities'] as $v ) {
				if ( self::affects_version( $v, $version ) ) {
					$vulns[] = self::normalise_vuln( $v );
				}
			}
		}

		$data = array( 'vulnerabilities' => $vulns );
		set_transient( $cache_key, $data, self::CACHE_TTL );
		return $data;
	}

	/**
	 * Check a single theme against WPScan API.
	 *
	 * @since 1.1.0
	 * @param string $slug    Theme slug.
	 * @param string $version Installed version.
	 * @return array
	 */
	public static function check_theme( $slug, $version ) {
		$cache_key = 'turbo_guard_vuln_theme_' . md5( $slug . $version );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return $cached;
		}

		$api_key = get_option( 'turbo_guard_wpscan_api_key', '' );
		$result  = self::api_request( '/themes/' . rawurlencode( $slug ), $api_key );

		$vulns = array();
		if ( ! is_wp_error( $result ) && isset( $result[ $slug ]['vulnerabilities'] ) ) {
			foreach ( $result[ $slug ]['vulnerabilities'] as $v ) {
				if ( self::affects_version( $v, $version ) ) {
					$vulns[] = self::normalise_vuln( $v );
				}
			}
		}

		$data = array( 'vulnerabilities' => $vulns );
		set_transient( $cache_key, $data, self::CACHE_TTL );
		return $data;
	}

	/**
	 * Check WordPress core version against WPScan API.
	 *
	 * @since 1.1.0
	 * @param string $version Installed WP version.
	 * @return array
	 */
	public static function check_wordpress_core( $version ) {
		$cache_key = 'turbo_guard_vuln_wp_' . md5( $version );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return $cached;
		}

		$api_key = get_option( 'turbo_guard_wpscan_api_key', '' );
		$slug    = str_replace( '.', '', $version );
		$result  = self::api_request( '/wordpresses/' . rawurlencode( $slug ), $api_key );

		$vulns = array();
		if ( ! is_wp_error( $result ) && isset( $result[ $slug ]['vulnerabilities'] ) ) {
			foreach ( $result[ $slug ]['vulnerabilities'] as $v ) {
				$vulns[] = self::normalise_vuln( $v );
			}
		}

		$data = array( 'vulnerabilities' => $vulns );
		set_transient( $cache_key, $data, self::CACHE_TTL );
		return $data;
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
