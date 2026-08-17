<?php
/**
 * Malware Scanner Class.
 *
 * Scans WordPress files for malware, backdoors, and suspicious code.
 *
 * @package TurboGuard
 * @since 1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles malware scanning logic.
 *
 * @since 1.0.0
 */
class Turbo_Guard_Scanner {

	/**
	 * Scan ID for current scan.
	 *
	 * @var int
	 */
	private $scan_id = 0;

	/**
	 * Cached WordPress core file manifest (relative paths => md5 checksums).
	 *
	 * @var array|null
	 */
	private static $core_manifest = null;

	/**
	 * Malware signature patterns.
	 *
	 * @var array
	 */
	private static $malware_patterns = array(
		// Critical: Web shells & backdoors.
		'eval_base64'       => array(
			'pattern'  => '/eval\s*\(\s*base64_decode\s*\(/i',
			'severity' => 'critical',
			'name'     => 'Obfuscated Backdoor (eval+base64)',
		),
		'eval_gzinflate'    => array(
			'pattern'  => '/eval\s*\(\s*gzinflate\s*\(/i',
			'severity' => 'critical',
			'name'     => 'Obfuscated Backdoor (eval+gzinflate)',
		),
		'eval_gzuncompress' => array(
			'pattern'  => '/eval\s*\(\s*gzuncompress\s*\(/i',
			'severity' => 'critical',
			'name'     => 'Obfuscated Backdoor (eval+gzuncompress)',
		),
		'eval_str_rot13'    => array(
			'pattern'  => '/eval\s*\(\s*str_rot13\s*\(/i',
			'severity' => 'critical',
			'name'     => 'Obfuscated Code (eval+rot13)',
		),
		'preg_replace_e'    => array(
			'pattern'  => '/preg_replace\s*\(\s*["\'].*\/e["\']/',
			'severity' => 'critical',
			'name'     => 'Code Execution via preg_replace /e',
		),
		'assert_post'       => array(
			'pattern'  => '/assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',
			'severity' => 'critical',
			'name'     => 'Remote Code Execution (assert)',
		),
		'system_post'       => array(
			'pattern'  => '/system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',
			'severity' => 'critical',
			'name'     => 'Remote Code Execution (system)',
		),
		'exec_post'         => array(
			'pattern'  => '/exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',
			'severity' => 'critical',
			'name'     => 'Remote Code Execution (exec)',
		),
		'exec_var'          => array(
			// Catches nobodycrew-style shells: checks function_exists('exec') then uses exec($cmd).
			// Requires BOTH the function_exists check AND exec call to avoid false positives.
			'pattern'  => '/function_exists\s*\(\s*["\']exec["\']\s*\).*exec\s*\(\s*\$/is',
			'severity' => 'critical',
			'name'     => 'Backdoor:PHP/nobodycrew — Command Execution Shell',
		),
		'shell_exec_post'   => array(
			'pattern'  => '/shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',
			'severity' => 'critical',
			'name'     => 'Remote Code Execution (shell_exec)',
		),
		'passthru_post'     => array(
			'pattern'  => '/passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',
			'severity' => 'critical',
			'name'     => 'Remote Code Execution (passthru)',
		),

		// Critical: Known shell signatures.
		'c99shell'          => array(
			'pattern'  => '/c99sh|c99shell|c99_shell/i',
			'severity' => 'critical',
			'name'     => 'C99 Shell Backdoor',
		),
		'r57shell'          => array(
			'pattern'  => '/r57shell|r57_shell/i',
			'severity' => 'critical',
			'name'     => 'R57 Shell Backdoor',
		),
		'phpspy'            => array(
			'pattern'  => '/PhpSpy|php_spy/i',
			'severity' => 'critical',
			'name'     => 'PhpSpy Shell Backdoor',
		),
		'webshell'          => array(
			// Match "Web Shell by" (shell self-identification) OR the WSO shell header.
			// Requires a space then digit to avoid matching JS variable names like
			// "WSO2" in legitimate vendor bundles (e.g. Google Site Kit dist JS).
			// Only applied to PHP files — JS files never contain actual WSO shells.
			'pattern'      => '/Web\s*Shell\s*by|WSO\s+[0-9]/i',
			'severity'     => 'critical',
			'name'         => 'WebShell (WSO)',
			'php_only'     => true,  // Never flag JS/CSS files for this pattern.
		),
		'polyglot_image'    => array(
			// Fake JFIF/PNG/GIF magic bytes stitched onto a PHP payload — the
			// GIF/exec.img backdoor family. Real image files never contain "<?php".
			'pattern'  => '/^(\xff\xd8\xff|\x89PNG\r\n\x1a\n|GIF8[79]a).{0,4096}<\?php/is',
			'severity' => 'critical',
			'name'     => 'Polyglot Image Backdoor (fake JFIF/PNG/GIF header + PHP)',
		),

		// Critical: Polyglot variable-based image header backdoor.
		// Hackers store fake PNG/GIF/JFIF magic bytes in PHP variables to
		// evade scanners that only check file headers. The akijlogistics
		// malware uses: $假PNG头 = "\x89PNG\r\n\x1a\n" (Chinese var name).
		// Any PHP variable containing raw image magic byte sequences is malicious.
		'polyglot_var_header' => array(
			'pattern'  => '/\$\w*\s*=\s*["\']\\\\x89PNG|\\\\xFFD8\\\\xFF|\$\w*\s*=\s*["\']GIF8[79]a/i',
			'severity' => 'critical',
			'name'     => 'Backdoor:PHP/polyglot.var — Fake Image Header in Variable',
			'php_only' => true,
		),

		// Critical: Chinese/Unicode variable names in PHP code.
		// Legitimate PHP code NEVER uses Chinese characters as variable names.
		// This is exclusively used by Chinese/Japanese SEO spam backdoors to
		// evade English-focused scanners. E.g.: $假PNG头, $加密数据, $注入代码
		'chinese_var_names' => array(
			'pattern'  => '/\$[\x{4E00}-\x{9FFF}\x{3400}-\x{4DBF}]{2,}/u',
			'severity' => 'critical',
			'name'     => 'Backdoor:PHP/cjk-obfuscated — Chinese Variable Name Obfuscation',
			'php_only' => true,
		),

		// Critical: HTML + PHP polyglot file (DOCTYPE/html mixed with PHP code).
		// Normal PHP files don't start with fake PNG headers then switch to HTML
		// then back to PHP. This pattern detects files that use HTML as a wrapper
		// around embedded PHP backdoors — the exact pattern from akijlogistics.
		'html_php_polyglot' => array(
			'pattern'  => '/<!DOCTYPE[^>]*>.*<\?php.*class\s+\w*(Manager|Shell|Upload|Admin|File)/is',
			'severity' => 'critical',
			'name'     => 'Backdoor:PHP/polyglot.html — HTML-Wrapped PHP Backdoor',
			'php_only' => true,
		),

		// Critical: PHP File Manager class outside of legitimate plugin dirs.
		// The FileManager class pattern is the actual backdoor payload in the
		// akijlogistics attack. Detects: class FileManager, class FileBrowser,
		// class WebShell, class Uploader, etc.
		'file_manager_class' => array(
			'pattern'  => '/class\s+(FileManager|FileBrowser|FileAdmin|WebFileManager|Uploader)\s*\{/i',
			'severity' => 'critical',
			'name'     => 'Backdoor:PHP/phpfm — PHP File Manager Shell',
			'php_only' => true,
		),

		// Critical: Multiple image format magic bytes in same PHP file.
		// Normal PHP files never reference GIF89a AND PNG headers together.
		// Backdoors combine multiple fake headers for maximum evasion.
		'multi_magic_bytes' => array(
			'pattern'  => '/(GIF89a|GIF87a).*\\\\x89PNG|\\\\x89PNG.*(GIF89a|GIF87a)/is',
			'severity' => 'critical',
			'name'     => 'Backdoor:PHP/multi-polyglot — Multiple Fake Image Headers',
			'php_only' => true,
		),

		// High: SEO spam injections.
		// NOTE: hidden_links is uploads_only because minified plugin JS files
		// legitimately contain CSS strings like "display:none" near href attributes
		// (tooltips, dropdowns, etc.) which would cause massive false positives.
		// This pattern is accurate ONLY for files in uploads/ or non-plugin dirs.
		'hidden_links'      => array(
			'pattern'      => '/display\s*:\s*none.*href/i',
			'severity'     => 'high',
			'name'         => 'Hidden SEO Spam Links',
			'uploads_only' => true,
		),
		'spam_pharma'       => array(
			'pattern'  => '/(viagra|cialis|levitra|phentermine|casino|poker)\s*<\/a>/i',
			'severity' => 'high',
			'name'     => 'Pharma/Casino SEO Spam',
		),
		'spam_redirect'     => array(
			'pattern'  => '/header\s*\(\s*["\']Location:.*\$_(GET|POST|REQUEST)/i',
			'severity' => 'high',
			'name'     => 'Malicious Redirect via Header',
		),
		'iframe_hidden'     => array(
			'pattern'  => '/<iframe[^>]*(width\s*=\s*["\']?\s*0|height\s*=\s*["\']?\s*0|visibility\s*:\s*hidden)/i',
			'severity' => 'high',
			'name'     => 'Hidden iFrame Injection',
		),

		// High: Code obfuscation.
		// chr_obfuscation is uploads_only — large minified JS bundles can contain
		// legitimate chr() calls (e.g. Elementor's editor-controls.js has thousands).
		'chr_obfuscation'   => array(
			'pattern'      => '/(\bchr\s*\(\s*\d{1,3}\s*\)\s*\.){5,}/i',
			'severity'     => 'high',
			'name'         => 'String Obfuscation (chr concatenation)',
			'uploads_only' => true,
		),
		'hex_obfuscation'   => array(
			'pattern'  => '/\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){10,}/',
			'severity' => 'high',
			'name'     => 'Hex-Encoded Obfuscated Code',
			'uploads_only' => true,  // Plugin vendor libs (phpseclib, polyfill) contain hex legitimately.
		),

		// Medium: Suspicious functions.
		'file_write_post'   => array(
			'pattern'  => '/file_put_contents\s*\(.*\$_(POST|GET|REQUEST|COOKIE)/i',
			'severity' => 'medium',
			'name'     => 'File Write from User Input',
		),
		'create_function'   => array(
			'pattern'  => '/create_function\s*\([^)]*\$_(POST|GET|REQUEST)/i',
			'severity' => 'medium',
			'name'     => 'Dynamic Code Creation (create_function)',
		),

		// HIGH: Japanese/Chinese/Korean SEO spam text inside PHP/JS files.
		// IMPORTANT: These patterns are ONLY applied to files in uploads/ and
		// non-plugin/theme directories. Legitimate plugins (Elementor, Yoast, etc.)
		// contain Japanese/Chinese translation strings that would cause false positives.
		// These patterns are applied selectively — see scan_file() method.
		'cjk_spam_japanese' => array(
			'pattern'  => '/[\x{3040}-\x{30FF}\x{31F0}-\x{31FF}]{3,}/u',
			'severity' => 'high',
			'name'     => 'Japanese SEO Spam Injection (e.g. GUCCI バッグ)',
			'uploads_only' => true,
		),
		'cjk_spam_chinese'  => array(
			'pattern'  => '/[\x{4E00}-\x{9FFF}\x{3400}-\x{4DBF}]{3,}/u',
			'severity' => 'high',
			'name'     => 'Chinese SEO Spam Injection',
			'uploads_only' => true,
		),
		'cjk_spam_korean'   => array(
			'pattern'  => '/[\x{AC00}-\x{D7A3}]{3,}/u',
			'severity' => 'high',
			'name'     => 'Korean SEO Spam Injection',
			'uploads_only' => true,
		),

		// HIGH: Luxury/pharma brand spam keywords injected into PHP files.
		// ONLY applied to uploads/ and non-plugin/theme dirs.
		// Pattern requires the keyword to appear as a standalone word (word-boundary)
		// to avoid false matches like "channel" matching "chanel", etc.
		'luxury_spam_keywords' => array(
			'pattern'      => '/\b(gucci|louis[_\s-]vuitton|chanel|prada|rolex|hermes|burberry|viagra|cialis|levitra|ブレスレット|バッグ|財布|コピー品|ブランドコピー)\b/i',
			'severity'     => 'high',
			'name'         => 'Luxury Brand / Pharma SEO Spam Keywords',
			'uploads_only' => true,
		),
	);

	/**
	 * File extensions to scan (text-based: full pattern matching).
	 *
	 * @var array
	 */
	private static $scan_extensions = array(
		'php',
		'php3',
		'php4',
		'php5',
		'php7',
		'phtml',
		'pht',
		'js',
		'html',
		'htm',
		'svg',
		'htaccess',
	);

	/**
	 * Image/binary extensions to scan for embedded PHP (polyglot backdoors).
	 *
	 * These are NOT scanned for text patterns — only for PHP code injection.
	 * Wordfence calls this "Scan images, binary, and other files as if they
	 * were executable" — catches Backdoor:GIF/exec.img.10061 and similar.
	 *
	 * @var array
	 */
	private static $image_extensions = array(
		'jpg',
		'jpeg',
		'png',
		'gif',
		'webp',
		'bmp',
		'ico',
		'tiff',
		'tif',
	);

	/**
	 * Other suspicious extensions that should be collected.
	 *
	 * @var array
	 */
	private static $suspicious_extensions = array(
		'suspected', // Files renamed by hosting providers after hack detection.
		'phar',      // PHP archives — can contain backdoors.
	);

	/**
	 * Directories to skip during scan.
	 *
	 * @var array
	 */
	private static $skip_dirs = array(
		'node_modules',
		'.git',
		'.svn',
		'cache',
		'turbo-guard-quarantine',
	);

	/**
	 * Start a new scan.
	 *
	 * @since 1.0.0
	 * @return int Scan ID.
	 */
	public function start_scan() {
		global $wpdb;

		// Create scan record.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scans table; single row per scan, plugin-specific data.
		$wpdb->insert(
			$wpdb->prefix . 'turbo_guard_scans',
			array(
				'status'     => 'running',
				'started_at' => current_time( 'mysql' ),
			),
			array( '%s', '%s' )
		);

		$this->scan_id = $wpdb->insert_id;

		// Set transient to track running scan.
		set_transient( 'turbo_guard_running_scan_id', $this->scan_id, HOUR_IN_SECONDS );

		// Log event.
		self::log_event( 'scan_started', 'info', __( 'Malware scan started.', 'turbo-guard' ) );

		return $this->scan_id;
	}

	/**
	 * Scan a directory chunk (for AJAX progressive scanning).
	 *
	 * @since 1.0.0
	 * @param int $scan_id   Scan ID to continue.
	 * @param int $offset    File offset to start from.
	 * @param int $chunk_size Number of files to scan per chunk.
	 * @return array Scan progress data.
	 */
	public function scan_chunk( $scan_id, $offset = 0, $chunk_size = 100 ) {
		global $wpdb;

		$this->scan_id = absint( $scan_id );

		// Get all files — include parent directory if "scan outside WP" is enabled.
		// Justification: scanning site core paths (wp-admin/wp-includes), legitimate for a security plugin.
		$all_files = $this->get_all_files( ABSPATH );

		// Scan outside WordPress root (like Wordfence's "Scan files outside your
		// WordPress installation" option). Catches cPanel-level injected files
		// that are above the public_html/WordPress directory.
		if ( get_option( 'turbo_guard_scan_outside_wp', false ) ) {
			$parent = dirname( ABSPATH );
			if ( $parent && $parent !== ABSPATH && is_readable( $parent ) ) {
				// Only scan PHP/image files in the parent dir (not recursive
				// into sibling sites) — just the immediate parent level.
				$parent_files = $this->get_parent_dir_files( $parent );
				$all_files    = array_merge( $all_files, $parent_files );
			}
		}

		$total     = count( $all_files );
		$chunk     = array_slice( $all_files, $offset, $chunk_size );

		$threats_in_chunk = 0;

		foreach ( $chunk as $file_path ) {
			$result = $this->scan_file( $file_path );
			if ( $result ) {
				++$threats_in_chunk;
			}
		}

		$scanned = min( $offset + $chunk_size, $total );

		// Update scan progress.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Custom turbo_guard_scans table; per-chunk progress update, plugin-specific data.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->prefix}turbo_guard_scans
				 SET scanned_files = %d, total_files = %d,
				     threats_found = threats_found + %d
				 WHERE id = %d",
				$scanned,
				$total,
				$threats_in_chunk,
				$this->scan_id
			)
		);

		$done = ( $scanned >= $total );

		if ( $done ) {
			// Run database scan when file scan completes.
			$db_threats = self::scan_database( $this->scan_id );

			// Get current accumulated file threats count from DB.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scans table; single row per scan, plugin-specific data.
			$current_file_threats = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT threats_found FROM {$wpdb->prefix}turbo_guard_scans WHERE id = %d",
					$this->scan_id
				)
			);

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scans table; single row per scan, plugin-specific data.
			$wpdb->update(
				$wpdb->prefix . 'turbo_guard_scans',
				array(
					'status'       => 'completed',
					'completed_at' => current_time( 'mysql' ),
					'threats_found'=> $current_file_threats + $db_threats,
				),
				array( 'id' => $this->scan_id ),
				array( '%s', '%s', '%d' ),
				array( '%d' )
			);

			delete_transient( 'turbo_guard_running_scan_id' );
			self::log_event( 'scan_completed', 'info', __( 'Malware scan completed (files + database).', 'turbo-guard' ) );
		}

		return array(
			'scan_id'     => $this->scan_id,
			'total'       => $total,
			'scanned'     => $scanned,
			'percent'     => $total > 0 ? round( ( $scanned / $total ) * 100 ) : 0,
			'done'        => $done,
			'next_offset' => $offset + $chunk_size,
			'new_threats' => $threats_in_chunk,
		);
	}

	/**
	 * Get the official WordPress core file manifest (checksums) for the installed version.
	 *
	 * Uses the WordPress.org checksums API to get the list of all files that ship
	 * with the currently installed WordPress version. Results are cached as a transient
	 * for 24 hours to avoid hitting the API on every scan.
	 *
	 * This is the same approach Wordfence uses to detect "Unknown file in WordPress core".
	 *
	 * @since 1.2.2
	 * @return array Associative array of relative_path => md5_checksum. Empty on failure.
	 */
	private static function get_core_manifest() {
		// Return cached copy if already loaded this request.
		if ( null !== self::$core_manifest ) {
			return self::$core_manifest;
		}

		// Check transient cache first (avoids API call on every scan chunk).
		$cached = get_transient( 'turbo_guard_core_manifest' );
		if ( is_array( $cached ) && ! empty( $cached ) ) {
			self::$core_manifest = $cached;
			return self::$core_manifest;
		}

		// Fetch from WordPress.org checksums API.
		global $wp_version;
		$locale = get_locale();

		$url = sprintf(
			'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
			urlencode( $wp_version ),
			urlencode( $locale )
		);

		$response = wp_remote_get( $url, array(
			'timeout'   => 15,
			'sslverify' => true,
		) );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			// Try again with en_US locale as fallback.
			if ( 'en_US' !== $locale ) {
				$url = sprintf(
					'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=en_US',
					urlencode( $wp_version )
				);
				$response = wp_remote_get( $url, array(
					'timeout'   => 15,
					'sslverify' => true,
				) );
			}

			if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
				// API unavailable — fall back to local wp-includes/version.php file list.
				self::$core_manifest = self::build_local_core_manifest();
				if ( ! empty( self::$core_manifest ) ) {
					set_transient( 'turbo_guard_core_manifest', self::$core_manifest, 12 * HOUR_IN_SECONDS );
				}
				return self::$core_manifest;
			}
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) || empty( $body['checksums'] ) ) {
			self::$core_manifest = self::build_local_core_manifest();
			if ( ! empty( self::$core_manifest ) ) {
				set_transient( 'turbo_guard_core_manifest', self::$core_manifest, 12 * HOUR_IN_SECONDS );
			}
			return self::$core_manifest;
		}

		self::$core_manifest = $body['checksums'];

		// Cache for 24 hours.
		set_transient( 'turbo_guard_core_manifest', self::$core_manifest, DAY_IN_SECONDS );

		return self::$core_manifest;
	}

	/**
	 * Build a local core file manifest when the API is unavailable.
	 *
	 * When offline, we cannot get the official checksums. Instead, we build a
	 * manifest of known-legitimate WordPress core file paths by reading the
	 * existing filesystem. This is less precise than the API approach but still
	 * catches obvious injections (PHP files in css/, images/, fonts/ dirs).
	 *
	 * Strategy: Trust existing PHP files in wp-admin/ and wp-includes/ root and
	 * their expected subdirectories, but NOT in asset subdirectories that are
	 * already handled by the "CRITICAL EARLY CHECK A/B" logic above.
	 *
	 * @since 1.2.2
	 * @return array Associative array of relative_path => '' (empty checksums for local).
	 */
	private static function build_local_core_manifest() {
		// When the API is unreachable, return empty so the manifest check is
		// effectively skipped. The earlier positional checks (no-php-dirs,
		// asset-dir checks, images checks) still provide primary protection.
		// This prevents false positives when running offline/localhost without
		// internet access (common development scenario).
		return array();
	}

	/**
	 * Classify a backdoor based on its content — returns Wordfence-style threat name.
	 *
	 * Reads up to 4KB of file content and matches against known backdoor signatures
	 * to produce a meaningful threat name (not just "suspicious file").
	 *
	 * @since 1.2.1
	 * @param string $content First 4096 bytes of the file.
	 * @return array { type: string, name: string, description: string }
	 */
	private static function classify_backdoor( $content ) {

		// Polyglot image backdoor: fake JFIF/PNG/GIF header + PHP payload.
		// Wordfence calls this: Backdoor:GIF/exec.img.10061
		if ( preg_match( '/^(\xff\xd8\xff|.{0,4}\x89PNG|\x47\x49\x46\x38)/s', $content )
			|| strpos( $content, 'JFIF' ) !== false
			|| strpos( $content, "\x89PNG" ) !== false
			|| strpos( $content, 'GIF89a' ) !== false
		) {
			return array(
				'type'        => 'backdoor_polyglot_image',
				'name'        => 'Backdoor:GIF/exec.img — Polyglot Image Shell',
				'description' => 'File disguised as a JFIF/PNG/GIF image containing a PHP backdoor payload. Used to bypass upload filters.',
			);
		}

		// Remote eval dropper: fetches remote PHP and evals it.
		// Re-infection mechanism — reinstalls malware after cleanup.
		if ( preg_match( '/eval\s*\(\s*["\']?\?>/i', $content )
			|| ( strpos( $content, 'file_get_contents' ) !== false && strpos( $content, 'eval' ) !== false )
			|| ( strpos( $content, 'curl_exec' ) !== false && strpos( $content, 'eval' ) !== false )
		) {
			return array(
				'type'        => 'backdoor_remote_eval',
				'name'        => 'Backdoor:PHP/dropper.eval — Remote Code Dropper',
				'description' => 'Fetches PHP code from a remote server and executes it via eval(). This is a re-infection dropper — it reinstalls malware after cleanup.',
			);
		}

		// PHP File Manager shell (FileMaster, WSO, c99, r57, etc.).
		// Wordfence calls this: Backdoor:PHP/phpfm.file_touch.13690
		if ( preg_match( '/class\s+FileManager/i', $content )
			|| strpos( $content, 'FileMaster' ) !== false
			|| strpos( $content, 'move_uploaded_file' ) !== false
			|| preg_match( '/c99shell|r57shell|WSO\s+[0-9]/i', $content )
		) {
			return array(
				'type'        => 'backdoor_file_manager',
				'name'        => 'Backdoor:PHP/phpfm — PHP File Manager Shell',
				'description' => 'Full-featured web-based file manager backdoor. Allows attacker to browse, edit, upload, delete, and execute files on your server.',
			);
		}

		// nobodycrew / exec() shell.
		// Wordfence calls this: Backdoor:PHP/nobodycrew.3414
		if ( preg_match( '/function_exists\s*\(\s*["\']exec["\']\s*\)/i', $content )
			|| preg_match( '/\$cmd.*exec\s*\(\s*\$cmd/is', $content )
			|| preg_match( '/passthru\s*\(\s*\$_(GET|POST|REQUEST)/i', $content )
		) {
			return array(
				'type'        => 'backdoor_exec_shell',
				'name'        => 'Backdoor:PHP/nobodycrew — Command Execution Shell',
				'description' => 'PHP shell that executes system commands (exec, passthru, system) from attacker-supplied input. Full server control.',
			);
		}

		// Generic obfuscated backdoor (eval+base64, gzinflate, etc.).
		if ( preg_match( '/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i', $content ) ) {
			return array(
				'type'        => 'backdoor_obfuscated',
				'name'        => 'Backdoor:PHP/obfuscated — Obfuscated PHP Backdoor',
				'description' => 'PHP code obfuscated using base64/gzip encoding to hide its purpose. Typically a remote access shell or spam injector.',
			);
		}

		// Default: unknown malicious PHP in unexpected location.
		return array(
			'type'        => 'injected_php_unknown',
			'name'        => 'Malware:PHP/injected — Injected PHP File',
			'description' => 'PHP file found in a location where PHP should never exist. Planted by an attacker — investigate and delete.',
		);
	}

	/**
	 * Determine whether a file lives inside a known-trusted location.
	 *
	 * Trusted locations are wp-content/plugins/*, wp-content/themes/*,
	 * wp-content/languages/*, and any caching-plugin JS cache directory.
	 * Files in these locations are distributed by their developers and have
	 * legitimate reasons to contain CJK characters or luxury-brand keywords
	 * (translation files, minified bundles that include dictionaries, etc.).
	 *
	 * ONLY patterns flagged with 'uploads_only' => true are affected by this
	 * check. Dangerous execution patterns (eval+base64, web shells, etc.) are
	 * ALWAYS applied regardless of location.
	 *
	 * @since 1.2.1
	 * @param string $real_path realpath()-resolved absolute file path.
	 * @return bool True if the file is in a trusted plugin/theme/language dir.
	 */
	private static function is_trusted_plugin_path( $real_path ) {
		if ( ! $real_path ) {
			return false;
		}

		// Accept already-normalised path (forward slashes).
		$norm = str_replace( '\\', '/', $real_path );

		// wp-content/plugins/*  — any installed plugin.
		// Justification: scanning site core paths (wp-content/plugins), legitimate for a security plugin.
		$plugins_dir = str_replace( '\\', '/', realpath( WP_PLUGIN_DIR ) );
		if ( $plugins_dir && strpos( $norm, $plugins_dir . '/' ) === 0 ) {
			return true;
		}

		// wp-content/themes/*  — any installed theme.
		$themes_dir = str_replace( '\\', '/', realpath( get_theme_root() ) );
		if ( $themes_dir && strpos( $norm, $themes_dir . '/' ) === 0 ) {
			return true;
		}

		// wp-content/languages/*  — core + plugin translation files.
		$lang_dir = str_replace( '\\', '/', realpath( WP_LANG_DIR ) );
		if ( $lang_dir && strpos( $norm, $lang_dir . '/' ) === 0 ) {
			return true;
		}

		// wp-content/uploads/al_opt_content/*  — Autoptimize JS/CSS cache.
		$al_opt = str_replace( '\\', '/', realpath( wp_upload_dir()['basedir'] . '/al_opt_content' ) );
		if ( $al_opt && strpos( $norm, $al_opt . '/' ) === 0 ) {
			return true;
		}

		// wp-content/uploads/cache/*  — W3 Total Cache, WP Super Cache, etc.
		$cache_dir = str_replace( '\\', '/', realpath( wp_upload_dir()['basedir'] . '/cache' ) );
		if ( $cache_dir && strpos( $norm, $cache_dir . '/' ) === 0 ) {
			return true;
		}

		// wp-content/cache/*  — WP-Rocket, LiteSpeed Cache, etc.
		// Justification: scanning site core paths (wp-content/cache), legitimate for a security plugin.
		$wpcache_dir = str_replace( '\\', '/', realpath( WP_CONTENT_DIR . '/cache' ) );
		if ( $wpcache_dir && strpos( $norm, $wpcache_dir . '/' ) === 0 ) {
			return true;
		}

		return false;
	}

	/**
	 * Scan a single file for malware.
	 *
	 * @since 1.0.0
	 * @param string $file_path Full path to the file.
	 * @return bool True if threat found.
	 */
	private function scan_file( $file_path ) {
		global $wpdb;

		$real_file_path = realpath( $file_path );
		$norm_real      = str_replace( '\\', '/', (string) $real_file_path );

		// ------------------------------------------------------------------
		// Determine file extension and type early — used throughout.
		// ------------------------------------------------------------------
		$ext    = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
		$is_php = in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'pht', 'phar' ), true );
		$is_image = in_array( $ext, self::$image_extensions, true );
		$is_suspected = ( 'suspected' === $ext );

		// ------------------------------------------------------------------
		// SKIP: our own plugin (avoid self-scan false positives).
		// ------------------------------------------------------------------
		$own_plugin_real = str_replace( '\\', '/', (string) realpath( TURBO_GUARD_PLUGIN_DIR ) );
		if ( $own_plugin_real && strpos( $norm_real, $own_plugin_real ) === 0 ) {
			return false;
		}

		// ------------------------------------------------------------------
		// SKIP: known security plugins that legitimately use crypto/hex.
		// ------------------------------------------------------------------
		$whitelist_plugins = array(
			'wordfence', 'malcare-security', 'sucuri-scanner',
			'better-wp-security', 'all-in-one-wp-security-and-firewall',
			'patchstack', 'bitfire', 'shield-security', 'wp-cerber',
			'solid-security', 'ithemes-security', 'ninjafirewall',
			'bulletproof-security', 'anti-malware', 'wp-simple-firewall',
			'security-malware-firewall',
			'wp-file-manager', // Legitimate file manager — has class FileManager.
		);
		foreach ( $whitelist_plugins as $slug ) {
			// Justification: scanning installed plugins (wp-content/plugins), legitimate for a security plugin.
			$dir = WP_PLUGIN_DIR . '/' . $slug;
			if ( is_dir( $dir ) ) {
				$real_dir = str_replace( '\\', '/', (string) realpath( $dir ) );
				if ( $real_dir && strpos( $norm_real, $real_dir . '/' ) === 0 ) {
					return false;
				}
			}
		}

		// Wordfence WAF logs.
		// Justification: scanning site core paths (wp-content/wflogs), legitimate for a security plugin.
		$wflogs = WP_CONTENT_DIR . '/wflogs';
		if ( is_dir( $wflogs ) ) {
			$real_wflogs = str_replace( '\\', '/', (string) realpath( $wflogs ) );
			if ( $real_wflogs && strpos( $norm_real, $real_wflogs . '/' ) === 0 ) {
				return false;
			}
		}

		// ------------------------------------------------------------------
		// SKIP: user-ignored files (Ignore button).
		// ------------------------------------------------------------------
		$ignored = get_option( 'turbo_guard_ignored_files', array() );
		if ( is_array( $ignored ) && $real_file_path ) {
			foreach ( $ignored as $entry ) {
				$norm_entry = str_replace( '\\', '/', $entry );
				if ( $norm_real === $norm_entry || substr( $norm_real, -strlen( $norm_entry ) ) === $norm_entry ) {
					return false;
				}
			}
		}

		// ------------------------------------------------------------------
		// CRITICAL EARLY CHECK A: PHP files in core asset directories.
		//
		// Strategy: flag PHP files in any /images/ subdirectory inside
		// wp-admin or wp-includes. WordPress never ships PHP inside an
		// images directory regardless of nesting depth.
		// Also flag wp-includes/css/ which never contains PHP.
		// ------------------------------------------------------------------
		// Justification: scanning site core paths (wp-admin/wp-includes), legitimate for a security plugin.
		$core_no_php_dirs = array_map( 'wp_normalize_path', array(
			ABSPATH . 'wp-admin/images',
			ABSPATH . 'wp-admin/css',
			ABSPATH . 'wp-admin/js',
			ABSPATH . 'wp-includes/images',
			ABSPATH . 'wp-includes/css',
		) );

		// Also catch PHP in any nested /images/ dir inside wp-admin
		// e.g. wp-admin/js/widgets/images/index.php
		// Justification: scanning site core paths (wp-admin), legitimate for a security plugin.
		$wp_admin_real_check = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-admin' ) );
		if ( $is_php && $wp_admin_real_check && strpos( $norm_real, $wp_admin_real_check . '/' ) === 0 ) {
			if ( preg_match( '~/images/~', $norm_real ) ) {
				$snippet      = @file_get_contents( $file_path, false, null, 0, 4096 ); // phpcs:ignore
				$threat_class = self::classify_backdoor( $snippet ? $snippet : '' );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
				$wpdb->insert(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array(
						'scan_id'        => $this->scan_id,
						'file_path'      => $file_path,
						'threat_type'    => $threat_class['type'],
						'severity'       => 'critical',
						'threat_name'    => $threat_class['name'],
						'threat_details' => sprintf(
							/* translators: 1: directory path, 2: threat description */
							__( 'PHP files must never exist in %1$s. %2$s DELETE IMMEDIATELY.', 'turbo-guard' ),
							str_replace( ABSPATH, '', dirname( $file_path ) ) . '/', // Display-only relative path.
							$threat_class['description']
						),
						'status'         => 'pending',
						'file_size'      => (int) @filesize( $file_path ),
						'file_hash'      => md5( $snippet ? $snippet : '' ),
					),
					array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
				);
				return true;
			}
		}

		if ( $is_php && $real_file_path ) {
			foreach ( $core_no_php_dirs as $no_php_dir ) {
				$real_no_php = str_replace( '\\', '/', (string) realpath( $no_php_dir ) );
				if ( $real_no_php && strpos( $norm_real, $real_no_php . '/' ) === 0 ) {
					$snippet      = @file_get_contents( $file_path, false, null, 0, 4096 ); // phpcs:ignore
					$threat_class = self::classify_backdoor( $snippet ? $snippet : '' );
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
					$wpdb->insert(
						$wpdb->prefix . 'turbo_guard_scan_results',
						array(
							'scan_id'        => $this->scan_id,
							'file_path'      => $file_path,
							'threat_type'    => $threat_class['type'],
							'severity'       => 'critical',
							'threat_name'    => $threat_class['name'],
							'threat_details' => sprintf(
								/* translators: 1: directory path, 2: threat description */
								__( 'PHP files must never exist in %1$s. %2$s DELETE IMMEDIATELY.', 'turbo-guard' ),
								str_replace( ABSPATH, '', dirname( $file_path ) ) . '/', // Display-only relative path.
								$threat_class['description']
							),
							'status'         => 'pending',
							'file_size'      => (int) @filesize( $file_path ),
							'file_hash'      => md5( $snippet ? $snippet : '' ),
						),
						array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
					);
					return true;
				}
			}
		}

		// ------------------------------------------------------------------
		// CRITICAL EARLY CHECK B: PHP files injected into non-core locations
		// that should never contain PHP (theme style subdirs, maintenance dirs,
		// etc.). Pattern: a PHP file exists in a path that contains a directory
		// named "images", "fonts", "styles", "assets", "dist", "css", "js"
		// AND the file is NOT in a known plugin/theme root.
		//
		// This catches: wp-content/themes/TT4/styles/ValueObjects/index.php
		// and:          wp-content/maintenance/assets/fonts/dist/index.php
		// ------------------------------------------------------------------
		if ( $is_php && $real_file_path ) {
			// Only apply to wp-content (not uploads — that's handled separately below).
			// Justification: scanning site core paths (wp-content), legitimate for a security plugin.
			$wc_real = str_replace( '\\', '/', (string) realpath( WP_CONTENT_DIR ) );
			$upload_real = str_replace( '\\', '/', (string) realpath( wp_upload_dir()['basedir'] ) );

			if ( $wc_real && strpos( $norm_real, $wc_real . '/' ) === 0
				&& ! ( $upload_real && strpos( $norm_real, $upload_real . '/' ) === 0 )
			) {
				// Check if any path segment is a pure-asset directory name.
				$asset_dirs = array(
					'/images/', '/fonts/', '/dist/', '/css/', '/less/', '/sass/',
					'/img/', '/icons/', '/svg/', '/media/', '/styles/',
				);
				// Normalised relative path from wp-content root.
				$rel = substr( $norm_real, strlen( $wc_real ) );

				foreach ( $asset_dirs as $asset_seg ) {
					if ( strpos( $rel, $asset_seg ) !== false ) {
						// Only skip files that are inside a registered WordPress.org plugin.
						// Themes and languages dirs CAN contain injected PHP in asset subdirs.
						// We use is_trusted_plugin_path() BUT only for the plugins/ directory —
						// themes/languages are NOT excluded here.
						// Justification: scanning installed plugins (wp-content/plugins), legitimate for a security plugin.
						$plugins_real = str_replace( '\\', '/', (string) realpath( WP_PLUGIN_DIR ) );
						$is_in_plugin = $plugins_real && strpos( $norm_real, $plugins_real . '/' ) === 0;

						// EXCEPTION: WordPress 6.x+ .asset.php files.
						// Themes/plugins built with wp-scripts generate .asset.php files
						// in /assets/css/, /assets/js/, /dist/ directories. These are
						// dependency manifests containing: <?php return array('dependencies'=>...);
						// They are always small (<500 bytes) and NOT malware.
						// Examples: hello-elementor/assets/css/header-footer.asset.php
						$basename = basename( $file_path );
						$is_asset_php = (
							substr( $basename, -10 ) === '.asset.php'
							&& filesize( $file_path ) < 500
						);

						if ( ! $is_in_plugin && ! $is_asset_php ) {
							$snippet      = @file_get_contents( $file_path, false, null, 0, 4096 ); // phpcs:ignore
							$threat_class = self::classify_backdoor( $snippet ? $snippet : '' );
							// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
							$wpdb->insert(
								$wpdb->prefix . 'turbo_guard_scan_results',
								array(
									'scan_id'        => $this->scan_id,
									'file_path'      => $file_path,
									'threat_type'    => $threat_class['type'],
									'severity'       => 'critical',
									'threat_name'    => $threat_class['name'],
									'threat_details' => sprintf(
										/* translators: 1: relative path, 2: threat description */
										__( 'PHP file found in asset directory %1$s — this should never contain PHP. %2$s', 'turbo-guard' ),
										str_replace( WP_CONTENT_DIR, 'wp-content', dirname( $file_path ) ) . '/', // Display-only relative path.
										$threat_class['description']
									),
									'status'         => 'pending',
									'file_size'      => (int) @filesize( $file_path ),
									'file_hash'      => md5( $snippet ? $snippet : '' ),
								),
								array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
							);
							return true;
						}
						break;
					}
				}
			}
		}

		// ------------------------------------------------------------------
		// SKIP: legitimate core PHP files (wp-admin root, wp-includes root
		// and their expected PHP subdirectories).
		// We already scanned the no-php subdirs above. Now skip the rest of
		// wp-admin and wp-includes — those PHP files ship with WordPress and
		// are verified by the File Integrity checker (separate feature).
		// ------------------------------------------------------------------
		// ------------------------------------------------------------------
		// SKIP: legitimate core PHP files — but FIRST check extensionless files.
		// Extensionless files (like wp-includes/css/license) should not exist
		// in core dirs — flag them as unknown planted files.
		// ------------------------------------------------------------------
		if ( '' === $ext && $real_file_path ) {
			// Justification: scanning site core paths (wp-admin/wp-includes), legitimate for a security plugin.
			$wp_admin_real2    = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-admin' ) );
			$wp_includes_real2 = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-includes' ) );
			if (
				( $wp_admin_real2    && strpos( $norm_real, $wp_admin_real2    . '/' ) === 0 ) ||
				( $wp_includes_real2 && strpos( $norm_real, $wp_includes_real2 . '/' ) === 0 )
			) {
				// WHITELIST: Common extensionless files that are NOT malware.
				// error_log / php_errorlog — PHP/Apache error logging output.
				// .htaccess — security or hosting config.
				$ext_basename = basename( $file_path );
				$ext_whitelisted = in_array( $ext_basename, array(
					'error_log', 'php_errorlog', '.htaccess', '.user.ini', 'LICENSE', 'license',
				), true );
				if ( $ext_whitelisted ) {
					return false;
				}

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
				$wpdb->insert(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array(
						'scan_id'        => $this->scan_id,
						'file_path'      => $file_path,
						'threat_type'    => 'unknown_core_file',
						'severity'       => 'high',
						'threat_name'    => __( 'Unknown File in WordPress Core Directory', 'turbo-guard' ),
						'threat_details' => sprintf(
							/* translators: %s: file path relative to ABSPATH */
							__( 'This file (%s) is not distributed with WordPress and should not exist in a core directory. It may have been planted by an attacker or left by a failed update. Verify and delete if not legitimate.', 'turbo-guard' ),
							str_replace( ABSPATH, '', $file_path ) // Display-only relative path.
						),
						'status'         => 'pending',
						'file_size'      => (int) @filesize( $file_path ),
						'file_hash'      => md5( (string) @file_get_contents( $file_path, false, null, 0, 512 ) ), // phpcs:ignore
					),
					array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
				);
				return true;
			}
		}

		// Justification: scanning site core paths (wp-admin/wp-includes), legitimate for a security plugin.
		$wp_admin_real    = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-admin' ) );
		$wp_includes_real = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-includes' ) );
		if (
			( $wp_admin_real    && strpos( $norm_real, $wp_admin_real    . '/' ) === 0 ) ||
			( $wp_includes_real && strpos( $norm_real, $wp_includes_real . '/' ) === 0 )
		) {
			// ------------------------------------------------------------------
			// CORE FILE MANIFEST CHECK (like Wordfence "Unknown file in WordPress core").
			//
			// Instead of blindly skipping all core files, we check whether the file
			// exists in the official WordPress distribution for this version.
			// If it does NOT exist in the manifest, it was planted by an attacker,
			// left by a failed update, or added by a plugin/host — flag it.
			//
			// Files that ARE in the manifest are legitimate core files — skip them.
			// File integrity (modified core files) is handled by the separate
			// File Integrity Checker module, not the malware scanner.
			// ------------------------------------------------------------------
			$manifest = self::get_core_manifest();
			if ( ! empty( $manifest ) ) {
				// Build relative path from ABSPATH (e.g. "wp-includes/css/index.php").
				// Justification: display-only relative path derived from the site's root.
				$rel_path = str_replace(
					str_replace( '\\', '/', (string) realpath( ABSPATH ) ) . '/',
					'',
					$norm_real
				);

				if ( ! isset( $manifest[ $rel_path ] ) ) {
					// WHITELIST: Common legitimate files in core dirs that aren't in manifest.
					// error_log / php_errorlog — generated by PHP error logging.
					// .htaccess — can be placed by hosting or plugins for security.
					// .private dir — Hostinger hosting system directory.
					$core_basename = basename( $rel_path );
					$core_whitelisted = in_array( $core_basename, array(
						'error_log', 'php_errorlog', '.htaccess', 'php.ini', '.user.ini',
					), true );

					// Skip directories created by hosting (.private, maint, etc.)
					if ( $core_whitelisted ) {
						return false;
					}

					// This file is NOT part of the official WordPress distribution.
					// Read a snippet to classify the threat.
					$snippet      = @file_get_contents( $file_path, false, null, 0, 4096 ); // phpcs:ignore
					$threat_class = self::classify_backdoor( $snippet ? $snippet : '' );

					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
					$wpdb->insert(
						$wpdb->prefix . 'turbo_guard_scan_results',
						array(
							'scan_id'        => $this->scan_id,
							'file_path'      => $file_path,
							'threat_type'    => 'unknown_core_file',
							'severity'       => 'high',
							'threat_name'    => __( 'Unknown File in WordPress Core', 'turbo-guard' ),
							'threat_details' => sprintf(
								/* translators: 1: file path relative to ABSPATH, 2: threat classification description */
								__( 'File "%1$s" is in a WordPress core location but is not distributed with this version of WordPress. This scan often includes files left over from a previous WordPress version, but it may also find files added by another plugin, files added by your host, or malicious files added by an attacker. %2$s', 'turbo-guard' ),
								$rel_path,
								$threat_class['description']
							),
							'status'         => 'pending',
							'file_size'      => (int) @filesize( $file_path ),
							'file_hash'      => md5( $snippet ? $snippet : '' ),
						),
						array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
					);
					return true;
				}
			}

			// File is in the official manifest — it's a legitimate core file.
			// Skip further malware pattern checks (integrity is a separate module).
			return false;
		}

		// Skip files we can't read.
		if ( ! is_readable( $file_path ) ) {
			return false;
		}

		$file_size = filesize( $file_path );

		// Skip very large files (over 5MB) - performance protection.
		if ( $file_size > 5 * MB_IN_BYTES ) {
			return false;
		}

		// Get file content.
		$content = file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $content ) {
			return false;
		}

		// $ext and $is_php defined at top of scan_file().
		$threat_found = false;

		// ------------------------------------------------------------------
		// CHECK: Unknown PHP files at ABSPATH root level.
		//
		// WordPress root only has specific files (index.php, wp-login.php,
		// wp-settings.php, etc.). Any other PHP file at the root level
		// that's not in the manifest is suspicious.
		// ------------------------------------------------------------------
		if ( $is_php ) {
			// Justification: scanning site core paths (WordPress root), legitimate for a security plugin.
			$abspath_real = str_replace( '\\', '/', (string) realpath( ABSPATH ) );
			$file_dir_real = str_replace( '\\', '/', (string) realpath( dirname( $file_path ) ) );

			// Only check files directly in ABSPATH (not subdirectories — those are handled above).
			if ( $abspath_real && $file_dir_real === $abspath_real ) {
				$manifest = self::get_core_manifest();
				if ( ! empty( $manifest ) ) {
					$rel_path = basename( $file_path );

					// WHITELIST: Files legitimately in WP root but not in manifest.
					// wp-config.php — generated during install, never in manifest.
					// bv_connector_*.php — BlogVault/MalCare security backup connector.
					// monarx-analyzer.php — Hostinger/Monarx server-level malware scanner.
					// .user.ini / php.ini — PHP config files placed by hosting.
					// wordfence-waf.php — Wordfence WAF bootstrap (auto-prepend).
					$root_whitelist = array( 'wp-config.php', 'wordfence-waf.php', 'monarx-analyzer.php', '.user.ini', 'php.ini' );
					$is_whitelisted_root = in_array( $rel_path, $root_whitelist, true )
						|| strpos( $rel_path, 'bv_connector_' ) === 0;  // BlogVault connector (hash in filename).

					if ( ! isset( $manifest[ $rel_path ] ) && ! $is_whitelisted_root ) {
						$snippet      = @file_get_contents( $file_path, false, null, 0, 4096 ); // phpcs:ignore
						$threat_class = self::classify_backdoor( $snippet ? $snippet : '' );
						// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
						$wpdb->insert(
							$wpdb->prefix . 'turbo_guard_scan_results',
							array(
								'scan_id'        => $this->scan_id,
								'file_path'      => $file_path,
								'threat_type'    => 'unknown_core_file',
								'severity'       => 'high',
								'threat_name'    => __( 'Unknown File in WordPress Root', 'turbo-guard' ),
								'threat_details' => sprintf(
									/* translators: 1: file name, 2: threat classification */
									__( 'File "%1$s" is in the WordPress root directory but is not part of the official WordPress distribution. It may have been planted by an attacker. %2$s', 'turbo-guard' ),
									$rel_path,
									$threat_class['description']
								),
								'status'         => 'pending',
								'file_size'      => (int) @filesize( $file_path ),
								'file_hash'      => md5( $snippet ? $snippet : '' ),
							),
							array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
						);
						return true;
					}
				}
			}
		}

		// Check for PHP files in uploads directory (always suspicious).
		if ( $is_php ) {
			$upload_dir      = wp_upload_dir();
			$real_upload     = str_replace( '\\', '/', (string) realpath( $upload_dir['basedir'] ) );
			if ( $real_upload && strpos( $norm_real, $real_upload . '/' ) === 0 ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
				$wpdb->insert(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array(
						'scan_id'        => $this->scan_id,
						'file_path'      => $file_path,
						'threat_type'    => 'php_in_uploads',
						'severity'       => 'critical',
						'threat_name'    => __( 'PHP File in Uploads Directory', 'turbo-guard' ),
						'threat_details' => __( 'PHP files should never exist in the uploads directory. This is a strong indicator of a backdoor or malware.', 'turbo-guard' ),
						'status'         => 'pending',
						'file_size'      => $file_size,
						'file_hash'      => md5( $content ),
					),
					array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
				);
				return true;
			}
		}

		// ------------------------------------------------------------------
		// CHECK: .suspected files — hosting providers rename hacked files.
		// Any .suspected file is evidence of a prior compromise.
		// ------------------------------------------------------------------
		if ( $is_suspected ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
			$wpdb->insert(
				$wpdb->prefix . 'turbo_guard_scan_results',
				array(
					'scan_id'        => $this->scan_id,
					'file_path'      => $file_path,
					'threat_type'    => 'suspected_file',
					'severity'       => 'high',
					'threat_name'    => __( 'Previously Infected File (.suspected)', 'turbo-guard' ),
					'threat_details' => sprintf(
						/* translators: %s: file path */
						__( 'File "%s" was renamed to .suspected by your hosting provider after detecting malware. This file should be reviewed and deleted — it is evidence of a prior compromise. The original file may still be active under its original name.', 'turbo-guard' ),
						str_replace( ABSPATH, '', $file_path ) // Display-only relative path.
					),
					'status'         => 'pending',
					'file_size'      => $file_size,
					'file_hash'      => md5( substr( $content, 0, 1024 ) ),
				),
				array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
			);
			return true;
		}

		// ------------------------------------------------------------------
		// CHECK: Image files for embedded PHP code (polyglot backdoors).
		//
		// This is what Wordfence calls "Scan images, binary, and other files
		// as if they were executable". It detects Backdoor:GIF/exec.img.10061
		// — fake JFIF/PNG/GIF files with PHP code stitched in.
		//
		// Real images NEVER contain "<?php" or "<?" followed by PHP keywords.
		// We only scan image content for PHP injection — NOT for text patterns
		// like CJK spam or hidden links (those would be nonsensical in binary).
		// ------------------------------------------------------------------
		if ( $is_image ) {
			// Check if this image contains ACTUAL PHP code injection.
			// IMPORTANT: We only check for the full "<?php" tag, NOT short tags
			// like "<?" because compressed JPEG/PNG binary data randomly contains
			// the bytes 0x3C 0x3F which would cause massive false positives
			// (RevSlider images, WooCommerce product images, etc.).
			//
			// Additionally, we require a PHP keyword within 200 bytes of the tag
			// to confirm it's real PHP, not just random binary noise that happens
			// to spell "<?php" (extremely rare but possible in large images).
			$has_php = false;
			$php_pos = strpos( $content, '<?php' );
			if ( false !== $php_pos ) {
				// Verify actual PHP code follows within 200 bytes.
				$after_tag = substr( $content, $php_pos, 200 );
				if ( preg_match( '/\$\w|\bfunction\b|\becho\b|\beval\b|\binclude\b|\brequire\b|\bclass\b|\breturn\b|\bif\s*\(|\bwhile\b/i', $after_tag ) ) {
					$has_php = true;
				}
			}
			// Also check <?= (short echo tag) — less common in binary noise.
			if ( ! $has_php && strpos( $content, '<?=' ) !== false ) {
				// <?= followed by a $ or quote is real PHP.
				$echo_pos = strpos( $content, '<?=' );
				$after_echo = substr( $content, $echo_pos, 50 );
				if ( preg_match( '/\<\?=\s*[\$"\']/', $after_echo ) ) {
					$has_php = true;
				}
			}

			if ( $has_php ) {
				$snippet      = substr( $content, 0, 1024 );
				$threat_class = self::classify_backdoor( $snippet );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
				$wpdb->insert(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array(
						'scan_id'        => $this->scan_id,
						'file_path'      => $file_path,
						'threat_type'    => $threat_class['type'],
						'severity'       => 'critical',
						'threat_name'    => $threat_class['name'],
						'threat_details' => sprintf(
							/* translators: 1: file extension, 2: threat description */
							__( 'Image file (.%1$s) contains embedded PHP code. Real images never contain PHP. %2$s', 'turbo-guard' ),
							$ext,
							$threat_class['description']
						),
						'status'         => 'pending',
						'file_size'      => $file_size,
						'file_hash'      => md5( $content ),
					),
					array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
				);
				return true;
			}

			// Also check for JavaScript injection in images (less common but exists).
			// IMPORTANT: Only flag if actual JS code follows the <script> tag.
			// Compressed JPEG/PNG binary data can randomly contain the bytes
			// 0x3C 0x73 0x63 0x72 0x69 0x70 0x74 which spells "<script".
			// Require JS keywords within 200 bytes to confirm real injection.
			$script_pos = strpos( strtolower( $content ), '<script' );
			if ( false !== $script_pos ) {
				$after_script = substr( $content, $script_pos, 300 );
				// Real script injection has: function, var, document, window, eval, alert, etc.
				if ( preg_match( '/\b(function|var|let|const|document|window|eval|alert|fetch|XMLHttpRequest|addEventListener)\b/i', $after_script ) ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
					$wpdb->insert(
						$wpdb->prefix . 'turbo_guard_scan_results',
						array(
							'scan_id'        => $this->scan_id,
							'file_path'      => $file_path,
							'threat_type'    => 'image_script_injection',
							'severity'       => 'high',
							'threat_name'    => __( 'Script Injection in Image File', 'turbo-guard' ),
							'threat_details' => sprintf(
								/* translators: %s: file path */
								__( 'Image file "%s" contains <script> tags with JavaScript code. Real images never contain JavaScript. This file may be used for XSS attacks via SVG/image polyglots.', 'turbo-guard' ),
								str_replace( ABSPATH, '', $file_path ) // Display-only relative path.
							),
							'status'         => 'pending',
							'file_size'      => $file_size,
							'file_hash'      => md5( $content ),
						),
						array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
					);
					return true;
				}
			}

			// Image file is clean — no further text pattern checks needed.
			return false;
		}

		// ------------------------------------------------------------------
		// Determine path context for selective pattern application.
		//
		// Patterns marked 'uploads_only' => true (CJK text, luxury keywords,
		// hex obfuscation) MUST NOT fire on plugin/theme/language files because
		// those legitimately contain Japanese translations, Unicode data tables,
		// and minified bundles that look like spam to naive regex.
		//
		// Rule:
		//   - trusted_path = file is inside plugins/, themes/, languages/, or
		//     a known caching-plugin JS cache directory.
		//   - For trusted paths: ONLY run patterns WITHOUT 'uploads_only'.
		//   - For non-trusted paths (uploads/, maintenance/, random dirs): run ALL patterns.
		// ------------------------------------------------------------------
		$is_trusted_path = self::is_trusted_plugin_path( $norm_real );

		// Run pattern matching for PHP and JS files.
		if ( in_array( $ext, self::$scan_extensions, true ) ) {
			foreach ( self::$malware_patterns as $pattern_key => $pattern_data ) {

				// Skip uploads_only patterns for files in trusted plugin/theme/language directories.
				// This is the CORE fix for the false positives that crashed akijlogistics.com:
				// Elementor JS files contain Japanese translations → should NOT be flagged.
				// Yoast ja.js is a Japanese language file → should NOT be flagged.
				// Google Site Kit vendor libs contain Unicode data → should NOT be flagged.
				// WP Mail SMTP polyfill → contains mapped.php with Japanese chars → should NOT be flagged.
				if ( ! empty( $pattern_data['uploads_only'] ) && $is_trusted_path ) {
					continue;
				}

				// Skip php_only patterns for non-PHP files.
				if ( ! empty( $pattern_data['php_only'] ) && ! $is_php ) {
					continue;
				}

				if ( preg_match( $pattern_data['pattern'], $content ) ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
					$wpdb->insert(
						$wpdb->prefix . 'turbo_guard_scan_results',
						array(
							'scan_id'        => $this->scan_id,
							'file_path'      => $file_path,
							'threat_type'    => $pattern_key,
							'severity'       => $pattern_data['severity'],
							'threat_name'    => $pattern_data['name'],
							'threat_details' => sprintf(
								/* translators: %s is the file path */
								__( 'Suspicious pattern detected in file: %s', 'turbo-guard' ),
								$file_path
							),
							'status'         => 'pending',
							'file_size'      => $file_size,
							'file_hash'      => md5( $content ),
						),
						array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
					);
					$threat_found = true;
					break; // One report per file is enough.
				}
			}
		}

		return $threat_found;
	}

	/**
	 * Get all files to scan recursively.
	 *
	 * @since 1.0.0
	 * @param string $dir Root directory path.
	 * @return array List of file paths.
	 */
	private function get_all_files( $dir ) {
		$files = array();

		if ( ! is_dir( $dir ) ) {
			return $files;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveCallbackFilterIterator(
					new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
					function ( $current ) {
						// Skip directories we don't want to scan.
						if ( $current->isDir() ) {
							foreach ( self::$skip_dirs as $skip ) {
								if ( $current->getFilename() === $skip ) {
									return false;
								}
							}
						}
						return true;
					}
				),
				RecursiveIteratorIterator::SELF_FIRST
			);

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}

				$ext = strtolower( $file->getExtension() );

				// Standard scannable extensions (PHP, JS, HTML, etc.).
				if ( in_array( $ext, self::$scan_extensions, true ) ) {
					$files[] = $file->getPathname();
					continue;
				}

				// Image/binary extensions — scan for polyglot PHP backdoors.
				// This is equivalent to Wordfence's "Scan images as executable".
				if ( in_array( $ext, self::$image_extensions, true ) ) {
					// Only collect images outside trusted plugin/theme dirs
					// (images in plugins/themes are almost always legitimate).
					// Exception: uploads/ where hackers plant fake images.
					$img_norm = str_replace( '\\', '/', $file->getPathname() );
					$upload_base = str_replace( '\\', '/', (string) realpath( wp_upload_dir()['basedir'] ) );
					// Justification: scanning site core paths (wp-content/maintenance), legitimate for a security plugin.
					$maintenance_base = str_replace( '\\', '/', (string) realpath( WP_CONTENT_DIR . '/maintenance' ) );

					$in_uploads     = $upload_base && strpos( $img_norm, $upload_base . '/' ) === 0;
					$in_maintenance = $maintenance_base && strpos( $img_norm, $maintenance_base . '/' ) === 0;

					// SKIP: Known plugin upload directories that contain legitimate images.
					// RevSlider, LayerSlider, Smart Slider, etc. store template previews
					// and slider assets as regular JPG/PNG files — not malware.
					// Scanning these causes hundreds of false positives due to JPEG
					// compression artifacts that randomly match PHP byte sequences.
					$trusted_upload_dirs = array(
						'/revslider/',       // Slider Revolution template images.
						'/layerslider/',     // LayerSlider assets.
						'/smartslider3/',    // Smart Slider 3 assets.
						'/elementor/css/',   // Elementor generated CSS (not images but cached).
						'/wc-product-images/', // WooCommerce optimized images.
					);
					$skip_image = false;
					if ( $in_uploads ) {
						$rel_upload_path = substr( $img_norm, strlen( $upload_base ) );
						foreach ( $trusted_upload_dirs as $trusted_dir ) {
							if ( strpos( $rel_upload_path, $trusted_dir ) !== false ) {
								$skip_image = true;
								break;
							}
						}
					}

					// Also check images in core directories (wp-admin, wp-includes)
					// where attackers plant fake .ico/.jpg backdoors.
					// Justification: scanning site core paths (wp-admin/wp-includes), legitimate for a security plugin.
					$wp_adm_real = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-admin' ) );
					$wp_inc_real = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-includes' ) );
					$in_core = ( $wp_adm_real && strpos( $img_norm, $wp_adm_real . '/' ) === 0 )
					         || ( $wp_inc_real && strpos( $img_norm, $wp_inc_real . '/' ) === 0 );

					// Scan setting check: scan all images if option enabled.
					$scan_all_images = get_option( 'turbo_guard_scan_images', false );

					if ( ! $skip_image && ( $in_uploads || $in_maintenance || $in_core || $scan_all_images ) ) {
						$files[] = $file->getPathname();
					}
					continue;
				}

				// Suspicious extensions (.suspected, .phar).
				if ( in_array( $ext, self::$suspicious_extensions, true ) ) {
					$files[] = $file->getPathname();
					continue;
				}

				// Also include extensionless files found inside core directories
				// that never legitimately contain files without extensions.
				// e.g. wp-includes/css/license — flagged by Wordfence as unknown core file.
				if ( '' === $ext ) {
					$norm_path = str_replace( '\\', '/', $file->getPathname() );
					// Justification: scanning site core paths (wp-includes/wp-admin), legitimate for a security plugin.
					$wp_inc    = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-includes' ) );
					$wp_adm    = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-admin' ) );
					if ( ( $wp_inc && strpos( $norm_path, $wp_inc . '/' ) === 0 )
						|| ( $wp_adm && strpos( $norm_path, $wp_adm . '/' ) === 0 )
					) {
						$files[] = $file->getPathname();
					}
				}
			}
		} catch ( Exception $e ) {
			// Log error and continue.
			error_log( 'Turbo Guard scanner error: ' . $e->getMessage() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}

		return $files;
	}

	/**
	 * Get files from the parent directory (above ABSPATH) for scanning.
	 *
	 * This mimics Wordfence's "Scan files outside your WordPress installation"
	 * feature. It scans only the immediate parent directory (not recursively into
	 * sibling sites) for suspicious PHP files and scripts that attackers plant
	 * outside the WP root to avoid detection.
	 *
	 * @since 1.2.2
	 * @param string $parent_dir Parent directory path.
	 * @return array List of file paths.
	 */
	private function get_parent_dir_files( $parent_dir ) {
		$files = array();

		if ( ! is_dir( $parent_dir ) || ! is_readable( $parent_dir ) ) {
			return $files;
		}

		try {
			// Non-recursive — only scan the immediate parent level.
			$dir_iterator = new DirectoryIterator( $parent_dir );

			foreach ( $dir_iterator as $file ) {
				if ( $file->isDot() || $file->isDir() ) {
					continue;
				}

				// Skip if file is inside ABSPATH (already scanned).
				$file_norm = str_replace( '\\', '/', $file->getPathname() );
				// Justification: comparing against the site root (ABSPATH) to avoid re-scanning; legitimate for a security plugin.
				$abspath_norm = str_replace( '\\', '/', ABSPATH );
				if ( strpos( $file_norm, $abspath_norm ) === 0 ) {
					continue;
				}

				$ext = strtolower( $file->getExtension() );

				// Collect PHP, image, and suspicious extension files.
				if ( in_array( $ext, self::$scan_extensions, true )
					|| in_array( $ext, self::$image_extensions, true )
					|| in_array( $ext, self::$suspicious_extensions, true )
				) {
					$files[] = $file->getPathname();
				}
			}
		} catch ( Exception $e ) {
			error_log( 'Turbo Guard parent dir scan error: ' . $e->getMessage() ); // phpcs:ignore
		}

		return $files;
	}

	/**
	 * Get scan results for a given scan ID.
	 *
	 * @since 1.0.0
	 * @param int    $scan_id  Scan ID.
	 * @param string $severity Filter by severity (optional).
	 * @return array Scan result rows.
	 */
	public static function get_scan_results( $scan_id, $severity = '' ) {
		global $wpdb;

		$scan_id = absint( $scan_id );

		// Build a list of ignored paths to exclude from results.
		$ignored = get_option( 'turbo_guard_ignored_files', array() );
		if ( ! is_array( $ignored ) ) {
			$ignored = array();
		}

		if ( $severity ) {
			$severity_sql = ' AND severity = %s';
			$base_args    = array( $scan_id, sanitize_key( $severity ) );
			$order_sql    = ' ORDER BY severity DESC, id ASC';
		} else {
			$severity_sql = '';
			$base_args    = array( $scan_id );
			$order_sql    = " ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'info') ASC, id ASC";
		}

		// Dynamic IN-list: placeholders generated from array_fill, every value
		// bound via %s in the prepare() args below — no raw user input in SQL.
		$in_clause = '';
		if ( ! empty( $ignored ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- IN-list built from array_fill placeholders; values bound via prepare() args.
			$in_clause = ' AND file_path NOT IN (' . implode( ', ', array_fill( 0, count( $ignored ), '%s' ) ) . ')';
			$base_args = array_merge( $base_args, $ignored );
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Query built from allowlisted literals and generated placeholders; every value is bound via the prepare() args below.
		$query = $wpdb->prepare(
			"SELECT * FROM {$wpdb->prefix}turbo_guard_scan_results" .
			" WHERE scan_id = %d AND status = 'pending'" .
			$severity_sql .
			$in_clause .
			$order_sql,
			$base_args
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- Custom turbo_guard_scan_results table; $query is prepared above.
		$results = $wpdb->get_results( $query );

		return $results ? $results : array();
	}

	/**
	 * Add a file path to the permanent ignore list.
	 *
	 * Ignored files are skipped during future scans AND hidden from results
	 * of previous scans. Mirrors the Wordfence "ignore file" workflow.
	 *
	 * @since 1.2.1
	 * @param string $file_path Absolute path to the file to ignore.
	 * @return bool True on success.
	 */
	public static function ignore_file( $file_path ) {
		$file_path = sanitize_text_field( wp_unslash( $file_path ) );
		if ( ! $file_path ) {
			return false;
		}

		$ignored = get_option( 'turbo_guard_ignored_files', array() );
		if ( ! is_array( $ignored ) ) {
			$ignored = array();
		}

		// Normalise slashes so the same path always matches.
		$norm = str_replace( '\\', '/', $file_path );

		if ( ! in_array( $norm, $ignored, true ) ) {
			$ignored[] = $norm;
			update_option( 'turbo_guard_ignored_files', $ignored, false );
		}

		return true;
	}

	/**
	 * Remove a file path from the permanent ignore list.
	 *
	 * @since 1.2.1
	 * @param string $file_path Absolute path to remove from ignore list.
	 * @return bool True on success.
	 */
	public static function unignore_file( $file_path ) {
		$file_path = sanitize_text_field( wp_unslash( $file_path ) );
		if ( ! $file_path ) {
			return false;
		}

		$ignored = get_option( 'turbo_guard_ignored_files', array() );
		if ( ! is_array( $ignored ) ) {
			return true;
		}

		$norm    = str_replace( '\\', '/', $file_path );
		$ignored = array_filter( $ignored, static function( $entry ) use ( $norm ) {
			return $entry !== $norm;
		} );
		update_option( 'turbo_guard_ignored_files', array_values( $ignored ), false );

		return true;
	}

	/**
	 * Get the full list of ignored file paths.
	 *
	 * @since 1.2.1
	 * @return array
	 */
	public static function get_ignored_files() {
		$ignored = get_option( 'turbo_guard_ignored_files', array() );
		return is_array( $ignored ) ? $ignored : array();
	}

	/**
	 * Get the most recent scan.
	 *
	 * @since 1.0.0
	 * @return object|null Scan row or null.
	 */
	public static function get_latest_scan() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom turbo_guard_scans table; single most-recent row, plugin-specific data.
		return $wpdb->get_row(
			"SELECT * FROM {$wpdb->prefix}turbo_guard_scans
			 WHERE status = 'completed'
			 ORDER BY id DESC
			 LIMIT 1"
		);
	}

	/**
	 * Scan the WordPress database for injected content.
	 *
	 * Checks wp_posts (content, excerpts), wp_postmeta, wp_options, and wp_comments
	 * for Japanese/Chinese SEO spam, hidden links, eval injections, and malicious redirects.
	 * This is the technique MalCare uses to find DB-level infections that file scanners miss.
	 *
	 * @since 1.1.0
	 * @param int $scan_id Current scan ID to log results under.
	 * @return int Number of database threats found.
	 */
	public static function scan_database( $scan_id ) {
		global $wpdb;

		$threats_found = 0;

		// Patterns to search for in database content.
		$db_patterns = array(
			array(
				'pattern' => 'eval(base64_decode',
				'name'    => 'eval+base64 Injection in Database',
				'severity'=> 'critical',
				'type'    => 'db_eval_injection',
			),
			array(
				'pattern' => '<script>eval(',
				'name'    => 'JavaScript eval Injection in Database',
				'severity'=> 'critical',
				'type'    => 'db_js_eval',
			),
			array(
				'pattern' => 'document.write(unescape',
				'name'    => 'Obfuscated Script Injection in Database',
				'severity'=> 'critical',
				'type'    => 'db_obfuscated_script',
			),
			array(
				'pattern' => 'viagra',
				'name'    => 'Pharma Spam in Database',
				'severity'=> 'high',
				'type'    => 'db_pharma_spam',
			),
			array(
				'pattern' => 'cialis',
				'name'    => 'Pharma Spam in Database',
				'severity'=> 'high',
				'type'    => 'db_pharma_spam',
			),
			array(
				'pattern' => 'casino',
				'name'    => 'Casino Spam in Database',
				'severity'=> 'high',
				'type'    => 'db_casino_spam',
			),
			array(
				'pattern' => 'display:none',
				'name'    => 'Hidden Content Injection in Database',
				'severity'=> 'medium',
				'type'    => 'db_hidden_content',
			),
		);

		// -----------------------------------------------------------
		// 1. Scan wp_posts (post_content, post_excerpt) for injections.
		//    Deduplication: track already-reported post IDs so the same post
		//    is never added more than once even if it matches multiple patterns.
		//    Priority: critical patterns are checked first so the most severe
		//    threat name wins.
		// -----------------------------------------------------------
		$reported_post_ids = array(); // dedup tracker.

		foreach ( $db_patterns as $pattern_data ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Malware scan over core posts tables; results are scan-scoped, not cacheable.
			$results = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT ID, post_title, post_type, post_status
					 FROM {$wpdb->posts}
					 WHERE (post_content LIKE %s OR post_excerpt LIKE %s)
					 AND post_status NOT IN ('auto-draft','trash')
					 LIMIT 50",
					'%' . $wpdb->esc_like( $pattern_data['pattern'] ) . '%',
					'%' . $wpdb->esc_like( $pattern_data['pattern'] ) . '%'
				)
			);

			foreach ( $results as $post ) {
				// Skip if we already reported this post for a higher-priority pattern.
				if ( isset( $reported_post_ids[ $post->ID ] ) ) {
					continue;
				}
				$reported_post_ids[ $post->ID ] = true;

				$path = 'database://wp_posts#' . $post->ID . ' (' . $post->post_type . ': ' . wp_trim_words( $post->post_title, 8, '...' ) . ')';
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
				$wpdb->insert(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array(
						'scan_id'        => $scan_id,
						'file_path'      => $path,
						'threat_type'    => $pattern_data['type'],
						'severity'       => $pattern_data['severity'],
						'threat_name'    => $pattern_data['name'],
						'threat_details' => sprintf(
							/* translators: 1: pattern text, 2: post ID */
							__( 'Pattern "%1$s" found in post ID %2$d. This post may contain injected spam content. Review and delete if not legitimate.', 'turbo-guard' ),
							$pattern_data['pattern'],
							$post->ID
						),
						'status'         => 'pending',
						'file_size'      => 0,
						'file_hash'      => '',
					),
					array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
				);
				++$threats_found;
			}
		}

		// -----------------------------------------------------------
		// 2. Scan wp_options for malicious values (siteurl redirect, injected scripts).
		// -----------------------------------------------------------
		$suspicious_options = array(
			'siteurl'   => 'WordPress siteurl option',
			'home'      => 'WordPress home option',
			'blogdescription' => 'WordPress tagline',
		);

		foreach ( $suspicious_options as $option_name => $label ) {
			$value = get_option( $option_name, '' );
			foreach ( $db_patterns as $pattern_data ) {
				if ( false !== stripos( $value, $pattern_data['pattern'] ) ) {
					$path = 'database://wp_options#' . $option_name;
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
					$wpdb->insert(
						$wpdb->prefix . 'turbo_guard_scan_results',
						array(
							'scan_id'        => $scan_id,
							'file_path'      => $path,
							'threat_type'    => 'db_option_injection',
							'severity'       => 'critical',
							'threat_name'    => 'Malicious Injection in ' . $label,
							'threat_details' => 'The ' . $option_name . ' WordPress option contains suspicious content. This could indicate a redirect hack.',
							'status'         => 'pending',
							'file_size'      => 0,
							'file_hash'      => '',
						),
						array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
					);
					++$threats_found;
				}
			}
		}

		// -----------------------------------------------------------
		// 3. CronSafe — detect malicious WP-Cron jobs.
		// Hackers register cron jobs to re-infect the site after cleanup.
		// -----------------------------------------------------------
		$cron_jobs = _get_cron_array();
		$suspicious_cron_hooks = array(
			'eval', 'base64', 'shell', 'exec', 'system', 'passthru',
			'backdoor', 'malware', 'spam', 'inject', 'payload',
		);
		if ( is_array( $cron_jobs ) ) {
			foreach ( $cron_jobs as $timestamp => $hooks ) {
				foreach ( $hooks as $hook => $events ) {
					$hook_lower = strtolower( $hook );
					foreach ( $suspicious_cron_hooks as $keyword ) {
						if ( false !== strpos( $hook_lower, $keyword ) ) {
							// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
							$wpdb->insert(
								$wpdb->prefix . 'turbo_guard_scan_results',
								array(
									'scan_id'        => $scan_id,
									'file_path'      => 'cron://' . $hook,
									'threat_type'    => 'malicious_cron',
									'severity'       => 'critical',
									'threat_name'    => 'Suspicious WP-Cron Job: ' . $hook,
									'threat_details' => 'Cron hook "' . $hook . '" contains a suspicious keyword. Hackers use cron jobs to re-infect sites after cleanup. Scheduled at: ' . gmdate( 'Y-m-d H:i:s', $timestamp ),
									'status'         => 'pending',
									'file_size'      => 0,
									'file_hash'      => '',
								),
								array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
							);
							++$threats_found;
							break;
						}
					}
				}
			}
		}

		// -----------------------------------------------------------
		// 4. Redirection Checks — detect .htaccess redirect hacks.
		// SEO spam campaigns inject redirect rules into .htaccess.
		// -----------------------------------------------------------
		// Justification: scanning site core paths (root and wp-content .htaccess), legitimate for a security plugin.
		$htaccess_files = array_map( 'wp_normalize_path', array(
			ABSPATH . '.htaccess',
			WP_CONTENT_DIR . '/.htaccess',
			wp_upload_dir()['basedir'] . '/.htaccess',
		) );
		$redirect_patterns = array(
			'/RewriteRule.*\$_(GET|POST|REQUEST)/i',
			'/RewriteRule.*\.(ru|cn|tk|pw|cc|xyz|top)\//i',
			'/RewriteCond.*HTTP_USER_AGENT.*Googlebot/i',
			'/php_value\s+auto_prepend_file/i',
			'/php_value\s+auto_append_file/i',
			'/SetHandler\s+application\/x-httpd-php/i',
		);
		foreach ( $htaccess_files as $htaccess ) {
			if ( ! file_exists( $htaccess ) || ! is_readable( $htaccess ) ) {
				continue;
			}
			$content = file_get_contents( $htaccess ); // phpcs:ignore
			foreach ( $redirect_patterns as $pattern ) {
				if ( preg_match( $pattern, $content ) ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
					$wpdb->insert(
						$wpdb->prefix . 'turbo_guard_scan_results',
						array(
							'scan_id'        => $scan_id,
							'file_path'      => $htaccess,
							'threat_type'    => 'htaccess_redirect_hack',
							'severity'       => 'critical',
							'threat_name'    => 'Malicious .htaccess Redirect Rule',
							'threat_details' => 'Suspicious redirect rule detected in ' . str_replace( ABSPATH, '', $htaccess ) . '. This is a common SEO spam / cloaking technique that redirects Googlebot to spam sites while showing normal content to visitors.',
							'status'         => 'pending',
							'file_size'      => filesize( $htaccess ),
							'file_hash'      => md5( $content ),
						),
						array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
					);
					++$threats_found;
					break; // One report per .htaccess file.
				}
			}
		}

		// -----------------------------------------------------------
		// 5. Hidden Folders — detect numbered/hash spam folders.
		// Your exact hack: /wp-admin/images/581824/ type folders.
		// -----------------------------------------------------------
		// Justification: scanning site core paths (wp-admin subdirs + uploads), legitimate for a security plugin.
		$suspicious_dirs = array_map( 'wp_normalize_path', array(
			ABSPATH . 'wp-admin/images',
			ABSPATH . 'wp-admin/css',
			ABSPATH . 'wp-admin/js',
			wp_upload_dir()['basedir'],
		) );
		foreach ( $suspicious_dirs as $check_dir ) {
			if ( ! is_dir( $check_dir ) ) {
				continue;
			}
			$subdirs = glob( $check_dir . '/*', GLOB_ONLYDIR );
			if ( ! $subdirs ) {
				continue;
			}
			foreach ( $subdirs as $subdir ) {
				$dirname = basename( $subdir );
				// Numbered folders (5+ digits) or hex hash folders (32+ hex chars).
				if ( preg_match( '/^\d{5,}$/', $dirname ) || preg_match( '/^[a-f0-9]{32,}$/i', $dirname ) ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
					$wpdb->insert(
						$wpdb->prefix . 'turbo_guard_scan_results',
						array(
							'scan_id'        => $scan_id,
							'file_path'      => $subdir,
							'threat_type'    => 'hidden_spam_folder',
							'severity'       => 'critical',
							'threat_name'    => 'Hidden SEO Spam Folder: /' . $dirname . '/',
							'threat_details' => 'Numbered or hash-named folder found in ' . str_replace( ABSPATH, '', $check_dir ) . '. This is the exact pattern used by Japanese/Chinese SEO spam campaigns (e.g. /wp-admin/images/581824/). DELETE the entire folder.',
							'status'         => 'pending',
							'file_size'      => 0,
							'file_hash'      => '',
						),
						array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
					);
					++$threats_found;
				}
			}
		}

		// -----------------------------------------------------------
		// 6. Check for unexpected admin users (common after a hack).
		// -----------------------------------------------------------
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Malware scan over core users tables; only $wpdb->prefix is interpolated.
		$recent_admins = $wpdb->get_results(
			"SELECT u.ID, u.user_login, u.user_registered
			 FROM {$wpdb->users} u
			 INNER JOIN {$wpdb->usermeta} um ON u.ID = um.user_id
			 WHERE um.meta_key = '{$wpdb->prefix}capabilities'
			 AND um.meta_value LIKE '%administrator%'
			 AND u.user_registered > DATE_SUB(NOW(), INTERVAL 30 DAY)
			 ORDER BY u.user_registered DESC"
		);

		if ( count( $recent_admins ) > 0 ) {
			foreach ( $recent_admins as $admin ) {
				$path = 'database://wp_users#' . $admin->ID . ' (' . $admin->user_login . ')';
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_scan_results table; per-scan data, not cacheable.
				$wpdb->insert(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array(
						'scan_id'        => $scan_id,
						'file_path'      => $path,
						'threat_type'    => 'suspicious_admin_user',
						'severity'       => 'high',
						'threat_name'    => 'New Administrator Account Created Recently',
						'threat_details' => sprintf(
							'Admin user "%s" (ID: %d) was created on %s. If you did not create this account, it may have been created by an attacker. Verify immediately.',
							$admin->user_login,
							$admin->ID,
							$admin->user_registered
						),
						'status'         => 'pending',
						'file_size'      => 0,
						'file_hash'      => '',
					),
					array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
				);
				++$threats_found;
			}
		}

		return $threats_found;
	}

	/**
	 * Log a security event.
	 *
	 * @since 1.0.0
	 * @param string $event_type Event type identifier.
	 * @param string $severity   Event severity: info|warning|critical.
	 * @param string $message    Human-readable message.
	 */
	public static function log_event( $event_type, $severity, $message ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom turbo_guard_events table; event logging, plugin-specific data.
		$wpdb->insert(
			$wpdb->prefix . 'turbo_guard_events',
			array(
				'event_type' => sanitize_key( $event_type ),
				'severity'   => sanitize_key( $severity ),
				'message'    => sanitize_text_field( $message ),
				'user_id'    => get_current_user_id(),
				'ip_address' => self::get_client_ip(),
			),
			array( '%s', '%s', '%s', '%d', '%s' )
		);
	}

	/**
	 * Get client IP address (sanitized).
	 *
	 * @since 1.0.0
	 * @return string IP address.
	 */
	public static function get_client_ip() {
		$ip = '';

		if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			$ip = $_SERVER['HTTP_CLIENT_IP']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			// Could be comma-separated list.
			$ips = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$ip  = trim( $ips[0] );
		} elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = $_SERVER['REMOTE_ADDR']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		}

		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}
}
