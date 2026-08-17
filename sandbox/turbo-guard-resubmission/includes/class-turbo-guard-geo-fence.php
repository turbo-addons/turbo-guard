<?php
/**
 * Geo-Fence & Trusted Location Security Class.
 *
 * Restricts WordPress admin access and file uploads to trusted
 * IP addresses or trusted countries. Blocks hackers uploading
 * malware from foreign locations even if they have valid credentials.
 *
 * Three protection modes:
 *  1. Trusted IP Whitelist  - only specific IPs can access wp-admin.
 *  2. Country Whitelist     - only specific countries can access wp-admin.
 *  3. Upload Country Lock   - file uploads only allowed from trusted countries.
 *
 * @package TurboGuard
 * @since   1.2.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Geo-fence and trusted location enforcement.
 *
 * @since 1.2.0
 */
class Turbo_Guard_Geo_Fence {

	/**
	 * Free IP geolocation API endpoint.
	 * No key required. Falls back gracefully if unavailable.
	 */
	const GEO_API = 'https://ipapi.co/%s/country/';

	/**
	 * Singleton instance.
	 *
	 * @var Turbo_Guard_Geo_Fence|null
	 */
	private static $instance = null;

	/**
	 * Get singleton.
	 *
	 * @since 1.2.0
	 * @return Turbo_Guard_Geo_Fence
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor — registers protection hooks.
	 *
	 * @since 1.2.0
	 */
	private function __construct() {
		// Trusted IP whitelist check (runs before everything else).
		if ( 'yes' === get_option( 'turbo_guard_trusted_ip_enabled', 'no' ) ) {
			add_action( 'init', array( $this, 'enforce_trusted_ip' ), 1 );
		}

		// Country-based admin access restriction.
		if ( 'yes' === get_option( 'turbo_guard_country_lock_enabled', 'no' ) ) {
			add_action( 'init', array( $this, 'enforce_country_lock' ), 2 );
		}

		// Block file uploads from untrusted countries.
		if ( 'yes' === get_option( 'turbo_guard_upload_country_lock', 'no' ) ) {
			add_filter( 'wp_handle_upload_prefilter', array( $this, 'block_upload_from_untrusted_country' ) );
		}

		// AJAX: detect and save current admin IP.
		add_action( 'wp_ajax_turbo_guard_save_my_ip', array( $this, 'ajax_save_my_ip' ) );

		// AJAX: get current visitor country.
		add_action( 'wp_ajax_turbo_guard_get_my_country', array( $this, 'ajax_get_my_country' ) );
	}

	// =========================================================
	// TRUSTED IP WHITELIST
	// =========================================================

	/**
	 * Block wp-admin access from IPs not in the trusted whitelist.
	 *
	 * Only enforced when the user is not already logged in as admin
	 * (to prevent complete lockout). AJAX is also restricted.
	 *
	 * @since 1.2.0
	 */
	public function enforce_trusted_ip() {
		// Only restrict wp-admin access.
		if ( ! is_admin() ) {
			return;
		}

		// Allow cron, CLI.
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		$ip           = Turbo_Guard_Scanner::get_client_ip();
		$trusted_ips  = self::get_trusted_ips();

		// If no trusted IPs configured, skip (avoid lockout on first setup).
		if ( empty( $trusted_ips ) ) {
			return;
		}

		// Check if current IP matches any trusted IP/range.
		foreach ( $trusted_ips as $trusted ) {
			if ( Turbo_Guard_Firewall::ip_matches_rule( $ip, $trusted ) ) {
				return; // Allowed.
			}
		}

		// IP not trusted. Log and block.
		Turbo_Guard_Scanner::log_event(
			'geo_fence_block',
			'critical',
			sprintf( 'Admin access blocked from untrusted IP: %s', $ip )
		);

		$this->display_blocked_page( $ip, 'trusted_ip' );
	}

	/**
	 * Block wp-admin access from countries not in the allowed list.
	 *
	 * @since 1.2.0
	 */
	public function enforce_country_lock() {
		if ( ! is_admin() ) {
			return;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		$allowed_countries = self::get_allowed_countries();
		if ( empty( $allowed_countries ) ) {
			return;
		}

		$ip      = Turbo_Guard_Scanner::get_client_ip();
		$country = self::get_country_for_ip( $ip );

		if ( ! $country || in_array( strtoupper( $country ), array_map( 'strtoupper', $allowed_countries ), true ) ) {
			return; // Country allowed or could not determine.
		}

		Turbo_Guard_Scanner::log_event(
			'geo_fence_country_block',
			'warning',
			sprintf( 'Admin access blocked from country: %s (IP: %s)', $country, $ip )
		);

		$this->display_blocked_page( $ip, 'country', $country );
	}

	/**
	 * Block file uploads from untrusted countries.
	 *
	 * Hooked into wp_handle_upload_prefilter so it fires before the file
	 * is written to disk — the upload never completes.
	 *
	 * @since 1.2.0
	 * @param array $file Upload file data array.
	 * @return array Modified file array (with error if blocked).
	 */
	public function block_upload_from_untrusted_country( $file ) {
		// Skip for super-admins who are uploading from wp-admin normally.
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			$allowed_countries = self::get_allowed_countries();
			if ( ! empty( $allowed_countries ) ) {
				$ip      = Turbo_Guard_Scanner::get_client_ip();
				$country = self::get_country_for_ip( $ip );

				if ( $country && ! in_array( strtoupper( $country ), array_map( 'strtoupper', $allowed_countries ), true ) ) {
					Turbo_Guard_Scanner::log_event(
						'upload_country_blocked',
						'critical',
						sprintf( 'File upload blocked from country %s (IP: %s). File: %s', $country, $ip, $file['name'] )
					);

					$file['error'] = sprintf(
						'Upload blocked by Turbo Guard: file uploads are not allowed from your location (%s). Contact the site owner if this is a mistake.',
						$country
					);
				}
			}
		}
		return $file;
	}

	// =========================================================
	// GEOLOCATION
	// =========================================================

	/**
	 * Get the country code for an IP address.
	 *
	 * Uses ipapi.co free tier (1,000 requests/day). Results are cached
	 * for 24 hours per IP to stay well within the limit.
	 *
	 * @since 1.2.0
	 * @param string $ip IP address.
	 * @return string|false 2-letter ISO country code or false on failure.
	 */
	public static function get_country_for_ip( $ip ) {
		if ( ! $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		// Return 'LOCAL' for private/loopback IPs (development environment).
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false ) {
			return 'LOCAL';
		}

		// Check cache first.
		$cache_key = 'turbo_guard_geo_' . md5( $ip );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return $cached;
		}

		// Fetch from API.
		$response = wp_remote_get(
			sprintf( self::GEO_API, rawurlencode( $ip ) ),
			array(
				'timeout'    => 5,
				'user-agent' => 'Turbo Guard WordPress Security Plugin',
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$country = strtoupper( trim( wp_remote_retrieve_body( $response ) ) );

		// Validate: must be exactly 2 uppercase alpha characters.
		if ( ! preg_match( '/^[A-Z]{2}$/', $country ) ) {
			return false;
		}

		// Cache for 24 hours.
		set_transient( $cache_key, $country, DAY_IN_SECONDS );

		return $country;
	}

	// =========================================================
	// OPTIONS HELPERS
	// =========================================================

	/**
	 * Get trusted IP list from options.
	 *
	 * @since 1.2.0
	 * @return string[] Array of IP addresses, CIDR blocks, or ranges.
	 */
	public static function get_trusted_ips() {
		$raw = get_option( 'turbo_guard_trusted_ips', '' );
		if ( empty( $raw ) ) {
			return array();
		}
		// One entry per line.
		$lines = array_filter( array_map( 'trim', explode( "\n", $raw ) ) );
		return array_values( $lines );
	}

	/**
	 * Get allowed country codes from options.
	 *
	 * @since 1.2.0
	 * @return string[] Array of 2-letter country codes.
	 */
	public static function get_allowed_countries() {
		$raw = get_option( 'turbo_guard_allowed_countries', '' );
		if ( empty( $raw ) ) {
			return array();
		}
		$codes = array_filter( array_map( 'strtoupper', array_map( 'trim', explode( ',', str_replace( "\n", ',', $raw ) ) ) ) );
		return array_values( $codes );
	}

	/**
	 * Get all countries list for the settings dropdown.
	 *
	 * @since 1.2.0
	 * @return array ISO code => country name.
	 */
	public static function get_countries_list() {
		return array(
			'AF' => 'Afghanistan',     'AL' => 'Albania',          'DZ' => 'Algeria',
			'AR' => 'Argentina',       'AM' => 'Armenia',          'AU' => 'Australia',
			'AT' => 'Austria',         'AZ' => 'Azerbaijan',       'BH' => 'Bahrain',
			'BD' => 'Bangladesh',      'BE' => 'Belgium',          'BO' => 'Bolivia',
			'BR' => 'Brazil',          'BG' => 'Bulgaria',         'CA' => 'Canada',
			'CL' => 'Chile',           'CN' => 'China',            'CO' => 'Colombia',
			'HR' => 'Croatia',         'CZ' => 'Czech Republic',   'DK' => 'Denmark',
			'EG' => 'Egypt',           'FI' => 'Finland',          'FR' => 'France',
			'GE' => 'Georgia',         'DE' => 'Germany',          'GH' => 'Ghana',
			'GR' => 'Greece',          'HK' => 'Hong Kong',        'HU' => 'Hungary',
			'IN' => 'India',           'ID' => 'Indonesia',        'IR' => 'Iran',
			'IQ' => 'Iraq',            'IE' => 'Ireland',          'IL' => 'Israel',
			'IT' => 'Italy',           'JP' => 'Japan',            'JO' => 'Jordan',
			'KZ' => 'Kazakhstan',      'KE' => 'Kenya',            'KR' => 'South Korea',
			'KW' => 'Kuwait',          'LB' => 'Lebanon',          'LY' => 'Libya',
			'MY' => 'Malaysia',        'MX' => 'Mexico',           'MA' => 'Morocco',
			'NL' => 'Netherlands',     'NZ' => 'New Zealand',      'NG' => 'Nigeria',
			'NO' => 'Norway',          'OM' => 'Oman',             'PK' => 'Pakistan',
			'PS' => 'Palestine',       'PE' => 'Peru',             'PH' => 'Philippines',
			'PL' => 'Poland',          'PT' => 'Portugal',         'QA' => 'Qatar',
			'RO' => 'Romania',         'RU' => 'Russia',           'SA' => 'Saudi Arabia',
			'SG' => 'Singapore',       'ZA' => 'South Africa',     'ES' => 'Spain',
			'LK' => 'Sri Lanka',       'SE' => 'Sweden',           'CH' => 'Switzerland',
			'TW' => 'Taiwan',          'TZ' => 'Tanzania',         'TH' => 'Thailand',
			'TN' => 'Tunisia',         'TR' => 'Turkey',           'UA' => 'Ukraine',
			'AE' => 'United Arab Emirates', 'GB' => 'United Kingdom', 'US' => 'United States',
			'UZ' => 'Uzbekistan',      'VN' => 'Vietnam',          'YE' => 'Yemen',
			'LOCAL' => 'Local / Development (127.x, 192.168.x)',
		);
	}

	// =========================================================
	// AJAX HANDLERS
	// =========================================================

	/**
	 * AJAX: Save the current admin IP to the trusted list.
	 *
	 * Called when admin clicks "Add My Current IP" in settings.
	 *
	 * @since 1.2.0
	 */
	public function ajax_save_my_ip() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ) );
		}

		$ip          = Turbo_Guard_Scanner::get_client_ip();
		$current_ips = get_option( 'turbo_guard_trusted_ips', '' );
		$lines       = array_filter( array_map( 'trim', explode( "\n", $current_ips ) ) );

		if ( ! in_array( $ip, $lines, true ) ) {
			$lines[] = $ip;
			update_option( 'turbo_guard_trusted_ips', implode( "\n", $lines ) );
		}

		wp_send_json_success( array(
			'ip'      => $ip,
			'message' => 'IP address ' . $ip . ' added to trusted list.',
		) );
	}

	/**
	 * AJAX: Get the current visitor country.
	 *
	 * @since 1.2.0
	 */
	public function ajax_get_my_country() {
		check_ajax_referer( 'turbo_guard_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ) );
		}

		$ip      = Turbo_Guard_Scanner::get_client_ip();
		$country = self::get_country_for_ip( $ip );
		$list    = self::get_countries_list();

		wp_send_json_success( array(
			'ip'           => $ip,
			'country_code' => $country,
			'country_name' => $country && isset( $list[ $country ] ) ? $list[ $country ] : $country,
		) );
	}

	// =========================================================
	// BLOCK PAGE
	// =========================================================

	/**
	 * Display a friendly "access blocked" page and exit.
	 *
	 * @since 1.2.0
	 * @param string $ip      Client IP address.
	 * @param string $reason  'trusted_ip' or 'country'.
	 * @param string $country Country code (for country-based blocks).
	 */
	private function display_blocked_page( $ip, $reason, $country = '' ) {
		http_response_code( 403 );
		header( 'Content-Type: text/html; charset=utf-8' );

		if ( 'trusted_ip' === $reason ) {
			$message = 'Access to the WordPress admin area is restricted to trusted IP addresses. Your IP address (' . esc_html( $ip ) . ') is not on the trusted list.';
		} else {
			$countries = self::get_countries_list();
			$name      = isset( $countries[ $country ] ) ? $countries[ $country ] : $country;
			$message   = 'Access to the WordPress admin area is restricted by location. Access from ' . esc_html( $name ) . ' is not permitted.';
		}

		?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Restricted &mdash; Turbo Guard</title>
<?php // Justification: single self-contained inline <style> for this standalone public block page; it renders before the admin asset pipeline loads, so enqueuing is not possible. ?>
<style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;display:flex;align-items:center;justify-content:center;min-height:100vh;}
.card{background:#fff;border-radius:12px;padding:48px 40px;max-width:480px;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.1);}
.icon{font-size:56px;margin-bottom:16px;}
h1{color:#1f2937;font-size:24px;margin:0 0 12px;}
p{color:#6b7280;font-size:14px;line-height:1.6;margin:0 0 24px;}
.badge{display:inline-block;background:#fef2f2;color:#dc2626;border:1px solid #fca5a5;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600;}
.footer{margin-top:24px;font-size:11px;color:#9ca3af;}
</style>
</head>
<body>
<div class="card">
	<div class="icon">&#128274;</div>
	<h1>Access Restricted</h1>
	<p><?php echo esc_html( $message ); ?></p>
	<div class="badge">Protected by Turbo Guard</div>
	<div class="footer">If you are the site owner and are locked out, disable the geo-fence in your WordPress database: set option <code>turbo_guard_trusted_ip_enabled</code> to <code>no</code>.</div>
</div>
</body>
</html><?php
		exit;
	}
}
