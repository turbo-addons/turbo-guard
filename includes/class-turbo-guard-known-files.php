<?php
/**
 * Known-Good File Verification.
 *
 * The market-standard way to eliminate malware-scan false positives (the same
 * technique Wordfence and MalCare use): a file that is part of the official,
 * unmodified wordpress.org version of a plugin or theme is TRUSTED and is never
 * flagged as malware — no matter what code patterns it contains.
 *
	 * This class builds a local index of known-good files (path => official MD5)
	 * by fetching the official WordPress.org checksums for every installed
	 * plugin/theme, then lets the scanner:
	 *   - SKIP a file whose path AND hash match the official version (trusted),
	 *   - FLAG a file whose path matches but hash differs (modified).
 *
 * @package TurboGuard
 * @since   1.3.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Known-good file index (Wordfence-style repository verification).
 *
 * @since 1.3.0
 */
class Turbo_Guard_Known_Files {

	/**
	 * Transient key for the cached index.
	 */
	const CACHE_KEY = 'turbo_guard_known_files';

	/**
	 * How long the index is cached (24 hours).
	 */
	const CACHE_TTL = DAY_IN_SECONDS;

	/**
	 * In-memory index cache (avoids repeated transient reads within a request).
	 *
	 * @var array|null
	 */
	private static $index = null;

	/**
	 * Normalised wp-content directory (cached).
	 *
	 * @var string|null
	 */
	private static $content_dir = null;

	/**
	 * Build or fetch the known-good file index.
	 *
	 * @since 1.3.0
	 * @return array Map of "plugins/{slug}/{file}" / "themes/{slug}/{file}" => md5.
	 */
	public static function get_index() {
		if ( null !== self::$index ) {
			return self::$index;
		}

		$cached = get_transient( self::CACHE_KEY );
		if ( is_array( $cached ) ) {
			self::$index = $cached;
			return self::$index;
		}

		self::$index = self::build_index();
		set_transient( self::CACHE_KEY, self::$index, self::CACHE_TTL );

		return self::$index;
	}

	/**
	 * Get the set of plugin/theme slugs that were successfully verified
	 * against the official wordpress.org checksums.
	 *
	 * Used to decide which uploads subdirectories can be trusted. A plugin
	 * injected by an attacker is not on wordpress.org, so it is never
	 * included — its uploads data stays scannable.
	 *
	 * @since 1.1.3
	 * @return array Unique list of verified slugs.
	 */
	public static function get_known_slugs() {
		$index = self::get_index();
		$slugs = array();
		foreach ( array_keys( $index ) as $key ) {
			if ( preg_match( '#^(plugins|themes)/([^/]+)/#', $key, $m ) ) {
				$slugs[] = $m[2];
			}
		}
		return array_values( array_unique( $slugs ) );
	}

	/**
	 * Clear the cached index (e.g. after plugin updates).
	 *
	 * @since 1.3.0
	 */
	public static function clear_cache() {
		self::$index = null;
		delete_transient( self::CACHE_KEY );
	}

	/**
	 * Check a file against the known-good index.
	 *
	 * @since 1.3.0
	 * @param string $file_path Absolute file path.
	 * @param string $norm_real Normalised (forward-slash) realpath of the file.
	 * @return string|false 'known_good' | 'modified' | false (not in index).
	 */
	public static function check_file( $file_path, $norm_real ) {
		$index = self::get_index();
		if ( empty( $index ) ) {
			return false;
		}

		$content_dir = self::content_dir();
		if ( ! $content_dir || 0 !== strpos( $norm_real, $content_dir . '/' ) ) {
			return false;
		}

		$rel = substr( $norm_real, strlen( $content_dir ) + 1 );
		if ( ! isset( $index[ $rel ] ) ) {
			return false;
		}

		// Skip very large files — hashing them is wasteful and slow.
		$size = @filesize( $file_path );
		if ( $size && $size > 5 * 1024 * 1024 ) {
			return false;
		}

		$actual = md5_file( $file_path );
		if ( $actual && isset( $index[ $rel ] ) ) {
			$known_md5 = $index[ $rel ];

			// A path can map to multiple known hashes (an array) when the
			// official checksums list several variants of the same file.
			// Trust the file only if its MD5 matches ANY of them.
			$known_hashes = is_array( $known_md5 ) ? $known_md5 : array( $known_md5 );
			foreach ( $known_hashes as $md5 ) {
				if ( is_string( $md5 ) && '' !== $md5 && hash_equals( $md5, $actual ) ) {
					return 'known_good';
				}
			}
		}

		return 'modified';
	}

	/**
	 * Build the known-good index from wordpress.org checksums.
	 *
	 * @since 1.3.0
	 * @return array
	 */
	private static function build_index() {
		$index = array();
		$jobs  = array(); // index prefix => array( type, slug, version )

		// ---- Plugins -------------------------------------------------
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		foreach ( get_plugins() as $plugin_file => $data ) {
			$slug = self::plugin_slug( $plugin_file );
			if ( $slug && ! empty( $data['Version'] ) ) {
				$jobs[ 'plugins/' . $slug . '/' ] = array( 'plugin', $slug, $data['Version'] );
			}
		}

		// ---- Themes --------------------------------------------------
		foreach ( wp_get_themes() as $slug => $theme ) {
			$version = $theme->get( 'Version' );
			if ( $version ) {
				$jobs[ 'themes/' . $slug . '/' ] = array( 'theme', $slug, $version );
			}
		}

		foreach ( self::fetch_all_checksums( $jobs ) as $prefix => $files ) {
			foreach ( $files as $rel => $md5 ) {
				$index[ $prefix . $rel ] = $md5;
			}
		}

		return $index;
	}

	/**
	 * Fetch the checksum lists for many plugins/themes at once.
	 *
	 * Requests run in parallel (WordPress' bundled Requests library), so a site
	 * with 20 plugins waits for roughly one round-trip instead of 20 in a row.
	 * Building the index sequentially took 20+ seconds on such sites and pushed
	 * the SEO spam scan past the host's request time limit (HTTP 500).
	 *
	 * @since 1.1.8
	 * @param array $jobs prefix => array( type, slug, version ).
	 * @return array prefix => array( relative path => md5 ).
	 */
	private static function fetch_all_checksums( $jobs ) {
		$out = array();
		if ( empty( $jobs ) ) {
			return $out;
		}

		$requests_class = class_exists( '\WpOrg\Requests\Requests' ) ? '\WpOrg\Requests\Requests' : ( class_exists( 'Requests' ) ? 'Requests' : '' );
		if ( '' === $requests_class || ! method_exists( $requests_class, 'request_multiple' ) ) {
			foreach ( $jobs as $prefix => $job ) {
				$out[ $prefix ] = self::fetch_checksums( $job[0], $job[1], $job[2] );
			}
			return $out;
		}

		$requests = array();
		foreach ( $jobs as $prefix => $job ) {
			$requests[ $prefix ] = array(
				'url'     => self::checksums_url( $job[0], $job[1], $job[2] ),
				'type'    => 'GET',
				'headers' => array(),
				'options' => array(
					'timeout'   => 8,
					'useragent' => 'Turbo Guard WordPress Security Plugin',
				),
			);
		}

		try {
			$responses = call_user_func( array( $requests_class, 'request_multiple' ), $requests );
		} catch ( \Exception $e ) {
			$responses = array();
		}

		foreach ( $jobs as $prefix => $job ) {
			$r = isset( $responses[ $prefix ] ) ? $responses[ $prefix ] : null;
			if ( is_object( $r ) && ! ( $r instanceof \Exception ) && isset( $r->status_code ) && 200 === (int) $r->status_code ) {
				$out[ $prefix ] = self::parse_checksums( $r->body );
			} else {
				$out[ $prefix ] = array(); // Premium/unknown plugin, or network error - not verifiable.
			}
		}

		return $out;
	}

	/**
	 * Derive a wordpress.org slug from a plugin file path.
	 *
	 * For "akismet/akismet.php" the slug is "akismet". For a single-file
	 * plugin "hello.php" the slug is "hello".
	 *
	 * @since 1.3.0
	 * @param string $plugin_file Plugin file path relative to wp-content/plugins.
	 * @return string Slug or empty string.
	 */
	private static function plugin_slug( $plugin_file ) {
		$slug = dirname( $plugin_file );
		if ( '.' === $slug ) {
			$slug = basename( $plugin_file, '.php' );
		}
		return sanitize_key( $slug );
	}

	/**
	 * Fetch the file list for a plugin/theme version from wordpress.org.
	 *
	 * @since 1.3.0
	 * @param string $type    'plugin' or 'theme'.
	 * @param string $slug    Repository slug.
	 * @param string $version Installed version.
	 * @return array List of file paths relative to the plugin/theme root.
	 */
	private static function fetch_checksums( $type, $slug, $version ) {
		if ( ! $slug || ! $version ) {
			return array();
		}

		$response = wp_remote_get(
			self::checksums_url( $type, $slug, $version ),
			array(
				'timeout'    => 8,
				'user-agent' => 'Turbo Guard WordPress Security Plugin',
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return array(); // Premium/unknown plugin, or network error - not verifiable.
		}

		return self::parse_checksums( wp_remote_retrieve_body( $response ) );
	}

	/**
	 * wordpress.org checksum URL for a plugin/theme version.
	 *
	 * @since 1.1.8
	 * @param string $type    'plugin' or 'theme'.
	 * @param string $slug    Repository slug.
	 * @param string $version Installed version.
	 * @return string
	 */
	private static function checksums_url( $type, $slug, $version ) {
		return sprintf(
			'https://downloads.wordpress.org/%s-checksums/%s/%s.json',
			$type,
			rawurlencode( $slug ),
			rawurlencode( $version )
		);
	}

	/**
	 * Parse a wordpress.org checksum JSON body into relative path => md5.
	 *
	 * "files" is a map of relative_path => hashes. Two known formats:
	 *   - plugin checksums: { "md5": "...", "sha256": "..." }
	 *   - theme checksums:  a plain md5 string
	 * Some paths map to an ARRAY of hashes (a file that differs across release
	 * branches). Keep the value as-is so check_file() can compare against every
	 * known hash instead of crashing.
	 *
	 * @since 1.1.8
	 * @param string $body JSON body.
	 * @return array
	 */
	private static function parse_checksums( $body ) {
		$json = json_decode( (string) $body, true );
		if ( ! is_array( $json ) || empty( $json['files'] ) || ! is_array( $json['files'] ) ) {
			return array();
		}

		$files = array();
		foreach ( $json['files'] as $rel => $hashes ) {
			if ( is_array( $hashes ) ) {
				if ( isset( $hashes['md5'] ) ) {
					$files[ $rel ] = $hashes['md5'];
				}
			} elseif ( is_string( $hashes ) && '' !== $hashes ) {
				$files[ $rel ] = $hashes;
			}
		}
		return $files;
	}

	/**
	 * Normalised wp-content directory (cached).
	 *
	 * @since 1.3.0
	 * @return string
	 */
	private static function content_dir() {
		if ( null === self::$content_dir ) {
			self::$content_dir = str_replace( '\\', '/', (string) realpath( WP_CONTENT_DIR ) );
		}
		return self::$content_dir;
	}
}
