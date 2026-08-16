<?php
/**
 * Site Hardening Class.
 *
 * Security headers, XML-RPC protection, user enumeration prevention,
 * WordPress version hiding, REST API protection, and login URL customisation.
 * Inspired by techniques used in Patchstack, Wordfence, and MalCare.
 *
 * @package TurboGuard
 * @since 1.1.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Site hardening features.
 *
 * @since 1.1.0
 */
class Turbo_Guard_Hardening {

	/**
	 * Singleton instance.
	 *
	 * @var Turbo_Guard_Hardening|null
	 */
	private static $instance = null;

	/**
	 * Get singleton instance.
	 *
	 * @since 1.1.0
	 * @return Turbo_Guard_Hardening
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 *
	 * @since 1.1.0
	 */
	private function __construct() {
		$this->apply_hardening();
	}

	/**
	 * Apply all enabled hardening features.
	 *
	 * @since 1.1.0
	 */
	private function apply_hardening() {
		// Security headers.
		if ( 'yes' === get_option( 'turbo_guard_security_headers', 'yes' ) ) {
			add_filter( 'wp_headers', array( $this, 'add_security_headers' ) );
		}

		// Hide WordPress version from source and feeds.
		if ( 'yes' === get_option( 'turbo_guard_hide_wp_version', 'yes' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		// Disable XML-RPC (common attack vector for brute force).
		if ( 'yes' === get_option( 'turbo_guard_disable_xmlrpc', 'no' ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', array( $this, 'disable_xmlrpc_methods' ) );
		}

		// Protect REST API: block unauthenticated access (except whitelisted routes).
		if ( 'yes' === get_option( 'turbo_guard_protect_rest_api', 'no' ) ) {
			add_filter( 'rest_authentication_errors', array( $this, 'restrict_rest_api' ) );
		}

		// Prevent user enumeration via ?author= and /wp-json/wp/v2/users.
		if ( 'yes' === get_option( 'turbo_guard_prevent_user_enum', 'yes' ) ) {
			add_action( 'init', array( $this, 'prevent_user_enumeration' ), 1 );
			add_filter( 'rest_endpoints', array( $this, 'protect_rest_users_endpoint' ) );
		}

		// Disable DISALLOW_FILE_EDIT in wp-config (prevent theme/plugin editor in WP Admin).
		// PHPCS: DISALLOW_FILE_EDIT is a WordPress constant — the prefix sniff is a false positive.
		if ( 'yes' === get_option( 'turbo_guard_disable_file_edit', 'no' ) ) {
			if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
				define( 'DISALLOW_FILE_EDIT', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
			}
		}

		// Remove RSD and wlwmanifest links from <head>.
		if ( 'yes' === get_option( 'turbo_guard_remove_readme_links', 'yes' ) ) {
			remove_action( 'wp_head', 'rsd_link' );
			remove_action( 'wp_head', 'wlwmanifest_link' );
		}

		// Block PHP execution in uploads via .htaccess.
		if ( 'yes' === get_option( 'turbo_guard_block_php_uploads', 'yes' ) ) {
			self::write_uploads_htaccess();
		}
	}

	/**
	 * Add HTTP security headers.
	 *
	 * @since 1.1.0
	 * @param array $headers Existing headers.
	 * @return array Modified headers.
	 */
	public function add_security_headers( $headers ) {
		$headers['X-Frame-Options']           = 'SAMEORIGIN';
		$headers['X-Content-Type-Options']    = 'nosniff';
		$headers['X-XSS-Protection']          = '1; mode=block';
		$headers['Referrer-Policy']           = 'strict-origin-when-cross-origin';
		$headers['Permissions-Policy']        = 'camera=(), microphone=(), geolocation=()';
		$headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';

		// Remove server fingerprint headers.
		if ( isset( $headers['X-Powered-By'] ) ) {
			unset( $headers['X-Powered-By'] );
		}

		return $headers;
	}

	/**
	 * Disable all XML-RPC methods.
	 *
	 * @since 1.1.0
	 * @param array $methods Registered XML-RPC methods.
	 * @return array Empty array.
	 */
	public function disable_xmlrpc_methods( $methods ) {
		return array();
	}

	/**
	 * Restrict REST API to authenticated users only.
	 *
	 * Allows certain public routes (Gutenberg, CF7, WooCommerce) through.
	 *
	 * @since 1.1.0
	 * @param WP_Error|null|true $errors Existing authentication error.
	 * @return WP_Error|null|true
	 */
	public function restrict_rest_api( $errors ) {
		if ( $errors instanceof WP_Error ) {
			return $errors;
		}

		// Always allow these routes for plugins that need them.
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$allowed_prefixes = array(
			'/wp-json/contact-form-7/',
			'/wp-json/wc/',
			'/wp-json/oembed/',
		);

		foreach ( $allowed_prefixes as $prefix ) {
			if ( false !== stripos( $request_uri, $prefix ) ) {
				return $errors;
			}
		}

		// Block unauthenticated access.
		if ( ! is_user_logged_in() ) {
			return new WP_Error(
				'turbo_guard_rest_forbidden',
				__( 'REST API access requires authentication.', 'turbo-guard' ),
				array( 'status' => 401 )
			);
		}

		return $errors;
	}

	/**
	 * Prevent user enumeration via the ?author= query string.
	 *
	 * NOTE: Nonce verification is intentionally skipped here — this hook fires on
	 * every 'init' request to intercept unauthenticated ?author= enumeration attempts.
	 * It is not a form submission and nonce verification is not applicable.
	 *
	 * @since 1.1.0
	 */
	public function prevent_user_enumeration() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! is_admin() && isset( $_GET['author'] ) && ! is_user_logged_in() ) {
			wp_die(
				esc_html__( 'User enumeration is not allowed.', 'turbo-guard' ),
				'403 Forbidden',
				array( 'response' => 403 )
			);
		}
	}

	/**
	 * Remove unauthenticated access to the /wp/v2/users REST endpoint.
	 *
	 * @since 1.1.0
	 * @param array $endpoints Registered REST endpoints.
	 * @return array Modified endpoints.
	 */
	public function protect_rest_users_endpoint( $endpoints ) {
		if ( ! is_user_logged_in() ) {
			// Remove the /users and /users/(?P<id>[\d]+) routes.
			$remove = array(
				'/wp/v2/users',
				'/wp/v2/users/(?P<id>[\d]+)',
			);
			foreach ( $remove as $route ) {
				if ( isset( $endpoints[ $route ] ) ) {
					unset( $endpoints[ $route ] );
				}
			}
		}
		return $endpoints;
	}

	/**
	 * Write .htaccess into uploads directory to block PHP execution.
	 *
	 * This is the single most effective hardening step for WordPress —
	 * even if a hacker uploads a PHP shell, the server refuses to execute it.
	 *
	 * @since 1.2.0
	 */
	public static function write_uploads_htaccess() {
		$upload_dir = wp_upload_dir();
		$htaccess   = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';

		$rules  = "# Turbo Guard — Block PHP execution in uploads\n";
		$rules .= "# Even if a hacker uploads a shell, the server won't run it.\n";
		$rules .= "<FilesMatch \"\.(?i:php\\d?|phtml|pht)$\">\n";
		$rules .= "\tOrder allow,deny\n";
		$rules .= "\tDeny from all\n";
		$rules .= "</FilesMatch>\n";

		// Only write if content has changed.
		$existing = file_exists( $htaccess ) ? file_get_contents( $htaccess ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === strpos( $existing, 'Turbo Guard' ) ) {
			file_put_contents( $htaccess, $rules . $existing ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	/**
	 * Remove Turbo Guard rules from uploads .htaccess.
	 *
	 * Called when the option is disabled.
	 *
	 * @since 1.2.0
	 */
	public static function remove_uploads_htaccess() {
		$upload_dir = wp_upload_dir();
		$htaccess   = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';

		if ( ! file_exists( $htaccess ) ) {
			return;
		}

		$content = file_get_contents( $htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		// Strip everything between our markers.
		$clean = preg_replace(
			'/#\s*Turbo Guard.*?<\/FilesMatch>\n/s',
			'',
			$content
		);
		file_put_contents( $htaccess, $clean ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/**
	 * Get all hardening options with defaults for the settings page.
	 *
	 * @since 1.1.0
	 * @return array Hardening option key => current value.
	 */
	public static function get_hardening_options() {
		return array(
			'security_headers'     => get_option( 'turbo_guard_security_headers', 'yes' ),
			'hide_wp_version'      => get_option( 'turbo_guard_hide_wp_version', 'yes' ),
			'disable_xmlrpc'       => get_option( 'turbo_guard_disable_xmlrpc', 'no' ),
			'protect_rest_api'     => get_option( 'turbo_guard_protect_rest_api', 'no' ),
			'prevent_user_enum'    => get_option( 'turbo_guard_prevent_user_enum', 'yes' ),
			'disable_file_edit'    => get_option( 'turbo_guard_disable_file_edit', 'no' ),
			'remove_readme_links'  => get_option( 'turbo_guard_remove_readme_links', 'yes' ),
			'block_php_uploads'    => get_option( 'turbo_guard_block_php_uploads', 'yes' ),
		);
	}
}
