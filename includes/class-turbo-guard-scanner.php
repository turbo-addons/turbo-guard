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

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Security scanner requires direct database access.

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
			'pattern'      => '/eval\s*\(\s*base64_decode\s*\(/i',
			'severity'     => 'critical',
			'name'         => 'Obfuscated Backdoor (eval+base64)',
			'trusted_skip' => true, // Legit plugins (license/encryption) use eval+base64.
		),
		'eval_gzinflate'    => array(
			'pattern'      => '/eval\s*\(\s*gzinflate\s*\(/i',
			'severity'     => 'critical',
			'name'         => 'Obfuscated Backdoor (eval+gzinflate)',
			'trusted_skip' => true,
		),
		'eval_gzuncompress' => array(
			'pattern'      => '/eval\s*\(\s*gzuncompress\s*\(/i',
			'severity'     => 'critical',
			'name'         => 'Obfuscated Backdoor (eval+gzuncompress)',
			'trusted_skip' => true,
		),
		'eval_str_rot13'    => array(
			'pattern'      => '/eval\s*\(\s*str_rot13\s*\(/i',
			'severity'     => 'critical',
			'name'         => 'Obfuscated Code (eval+rot13)',
			'trusted_skip' => true,
		),
		'preg_replace_e'    => array(
			'pattern'      => '/preg_replace\s*\(\s*["\'].*\/e["\']/',
			'severity'     => 'critical',
			'name'         => 'Code Execution via preg_replace /e',
			'trusted_skip' => true, // Deprecated /e modifier may exist in old plugins.
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
			// Still, legitimate plugins (e.g. Rank Math) use this exact safe-exec pattern,
			// so it is skipped inside trusted plugin/theme directories.
			'pattern'      => '/function_exists\s*\(\s*["\']exec["\']\s*\).*exec\s*\(\s*\$/is',
			'severity'     => 'critical',
			'name'         => 'Backdoor:PHP/nobodycrew — Command Execution Shell',
			'trusted_skip' => true,
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

		// =========================================================
		// Known malware families & web-shell identifiers (v1.3.0).
		// These are UNIQUE strings that never appear in legitimate code,
		// so they are safe to flag in ANY location (no trusted_skip).
		// =========================================================
		'b374k_shell'        => array(
			'pattern'  => '/b374k/i',
			'severity' => 'critical',
			'name'     => 'b374k Web Shell Backdoor',
			'php_only' => true,
		),
		'wso_filesman'       => array(
			'pattern'  => '/filesman/i',
			'severity' => 'critical',
			'name'     => 'WSO FilesMan Backdoor',
			'php_only' => true,
		),
		'indoxploit_shell'   => array(
			'pattern'  => '/indoxploit/i',
			'severity' => 'critical',
			'name'     => 'Indoxploit Web Shell',
			'php_only' => true,
		),
		'alfa_shell'         => array(
			'pattern'  => '/alfashell|alfa\s*(shell|team)/i',
			'severity' => 'critical',
			'name'     => 'ALFA Web Shell',
			'php_only' => true,
		),
		'n3t_shell'          => array(
			'pattern'  => '/n3tshell/i',
			'severity' => 'critical',
			'name'     => 'N3tShell Backdoor',
			'php_only' => true,
		),
		'madspot_shell'      => array(
			'pattern'  => '/madspot/i',
			'severity' => 'critical',
			'name'     => 'Madspot Web Shell',
			'php_only' => true,
		),
		'simatek_shell'      => array(
			'pattern'  => '/sima[-_ ]?tek/i',
			'severity' => 'critical',
			'name'     => 'Sima-Tek Web Shell',
			'php_only' => true,
		),
		'antichat_shell'     => array(
			'pattern'  => '/antichat/i',
			'severity' => 'critical',
			'name'     => 'Antichat Web Shell',
			'php_only' => true,
		),
		'weevely_backdoor'   => array(
			'pattern'  => '/weevely/i',
			'severity' => 'critical',
			'name'     => 'Weevely Backdoor',
			'php_only' => true,
		),
		'obytemini_shell'    => array(
			'pattern'  => '/0byt3m1n1|obytemini/i',
			'severity' => 'critical',
			'name'     => 'ObyteMini Web Shell',
			'php_only' => true,
		),
		'known_shell_author' => array(
			'pattern'  => '/By\s*VaLKa|indoushka/i',
			'severity' => 'critical',
			'name'     => 'Known Shell Author Signature',
			'php_only' => true,
		),

		// ---- Direct code execution / inclusion from user input (never legit). ----
		'eval_request'       => array(
			'pattern'  => '/eval\s*\(\s*\$_(POST|REQUEST|GET|COOKIE)/i',
			'severity' => 'critical',
			'name'     => 'Direct Code Execution (eval of request input)',
			'php_only' => true,
		),
		'include_request'    => array(
			'pattern'  => '/\b(include|require)(_once)?\s*\(\s*\$_(POST|REQUEST|GET|COOKIE)/i',
			'severity' => 'high',
			'name'     => 'Local File Inclusion (include/require of request)',
			'php_only' => true,
		),
		'globals_backdoor'   => array(
			'pattern'  => '/\$GLOBALS\s*\[\s*["\']GLOBALS["\']\s*\]/',
			'severity' => 'critical',
			'name'     => 'Backdoor:PHP/GLOBALS — Variable Manipulation',
			'php_only' => true,
		),

		// ---- Obfuscation patterns that may also exist in premium plugins, so
		// they are skipped inside trusted plugin/theme directories. ----
		'base64_request'     => array(
			'pattern'      => '/base64_decode\s*\(\s*\$_(POST|REQUEST|GET|COOKIE)/i',
			'severity'     => 'high',
			'name'         => 'Decoding Request Input (base64_decode)',
			'php_only'     => true,
			'trusted_skip' => true,
		),
		'gzinflate_base64'   => array(
			'pattern'      => '/eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/i',
			'severity'     => 'critical',
			'name'         => 'Multi-Layer Obfuscated Backdoor (eval+gzinflate+base64)',
			'trusted_skip' => true,
		),
		'rot13_base64'       => array(
			'pattern'      => '/str_rot13\s*\(\s*base64_decode\s*\(/i',
			'severity'     => 'critical',
			'name'         => 'Obfuscated Backdoor (rot13+base64)',
			'trusted_skip' => true,
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
		// Clear the site cache before scanning so results are fresh.
		turbo_guard_clear_site_cache();

		global $wpdb;

		// Create scan record.
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
			$current_file_threats = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT threats_found FROM {$wpdb->prefix}turbo_guard_scans WHERE id = %d",
					$this->scan_id
				)
			);

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

		global $wp_version;
		$locale = get_locale();

		// Cache key is version + locale specific so a WordPress core update
		// never reuses a stale manifest (which would flag the update's new
		// core files as "unknown").
		$cache_key = 'turbo_guard_core_manifest_' . md5( $wp_version . '|' . $locale );

		// Check transient cache first (avoids API call on every scan chunk).
		$cached = get_transient( $cache_key );
		if ( is_array( $cached ) && ! empty( $cached ) ) {
			self::$core_manifest = $cached;
			return self::$core_manifest;
		}

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
					set_transient( $cache_key, self::$core_manifest, 12 * HOUR_IN_SECONDS );
				}
				return self::$core_manifest;
			}
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) || empty( $body['checksums'] ) ) {
			self::$core_manifest = self::build_local_core_manifest();
			if ( ! empty( self::$core_manifest ) ) {
				set_transient( $cache_key, self::$core_manifest, 12 * HOUR_IN_SECONDS );
			}
			return self::$core_manifest;
		}

		self::$core_manifest = $body['checksums'];

		// Cache for 24 hours.
		set_transient( $cache_key, self::$core_manifest, DAY_IN_SECONDS );

		return self::$core_manifest;
	}

	/**
	 * Whether a file (by its normalised realpath) is part of the official
	 * WordPress core distribution, according to the core checksums manifest.
	 *
	 * Used to avoid flagging legitimate core files (e.g. the auto-generated
	 * wp-includes/css/dist/registry.php that ships with modern WordPress).
	 *
	 * @since 1.1.3
	 * @param string $norm_real Normalised (forward-slash) realpath of the file.
	 * @return bool True if the file is in the official core manifest.
	 */
	private static function is_core_file( $norm_real ) {
		$manifest = self::get_core_manifest();
		if ( empty( $manifest ) ) {
			return false;
		}

		$abspath = str_replace( '\\', '/', (string) realpath( ABSPATH ) );
		if ( ! $abspath ) {
			return false;
		}

		$rel = str_replace( $abspath . '/', '', $norm_real );
		return isset( $manifest[ $rel ] );
	}

	/**
	 * Whether an uploads-relative path belongs to a known legitimate plugin
	 * data directory.
	 *
	 * Trust is granted only for plugins/themes that were VERIFIED against the
	 * official wordpress.org checksums. An attacker-injected plugin is not on
	 * wordpress.org, so its slug is never trusted and its uploads files stay
	 * scannable. A few well-known data dirs that don't match their plugin slug
	 * are included as explicit exceptions.
	 *
	 * @since 1.1.3
	 * @param string $rel_upload_path Path relative to the uploads basedir.
	 * @return bool True if the path is under a trusted plugin data directory.
	 */
	public static function is_trusted_upload_path( $rel_upload_path ) {
		static $trusted_prefixes = null;

		if ( null === $trusted_prefixes ) {
			$trusted_prefixes = array();

			foreach ( Turbo_Guard_Known_Files::get_known_slugs() as $slug ) {
				$trusted_prefixes[] = $slug . '/';
			}

			// Known data dirs that don't match their plugin slug.
			$trusted_prefixes = array_merge( $trusted_prefixes, array(
				'redux/',
				'woocommerce_uploads/',
				'wc-logs/',
			) );

			$trusted_prefixes = array_unique( $trusted_prefixes );
		}

		$rel = ltrim( str_replace( '\\', '/', (string) $rel_upload_path ), '/' );
		foreach ( $trusted_prefixes as $prefix ) {
			if ( 0 === strpos( $rel, $prefix ) ) {
				return true;
			}
		}
		return false;
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

		// Command-execution shell with variable indirection: attacker input is
		// read into a variable, then passed to a command-execution function
		// (e.g. $c = $_GET['cmd']; shell_exec($c);). The direct $_GET->exec
		// signature above is trivially dodged with one assignment, so detect
		// the general shape: command-exec function + superglobal read.
		if ( preg_match( '/\b(?:shell_exec|passthru|system|proc_open|popen|exec)\s*\(\s*\$/i', $content )
			&& preg_match( '/\$(?:_GET|_POST|_REQUEST|_COOKIE|_FILES)\b/', $content )
		) {
			return array(
				'type'        => 'backdoor_exec_shell',
				'name'        => 'Backdoor:PHP/nobodycrew — Command Execution Shell',
				'description' => 'PHP shell that executes system commands (shell_exec, exec, system, passthru) from attacker-supplied input. Full server control.',
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

		// Obfuscated include/require backdoor: the included path is assembled
		// from concatenated string fragments (and/or a PHP stream wrapper such
		// as compress.zlib://). Legitimate code never splits a single string
		// into fragments this way — it's a signature-evasion technique used to
		// hide the included payload from signature scanners.
		if ( preg_match( '/(?:include|require)(?:_once)?\b/i', $content )
			&& (
				preg_match( '/["\'][^"\']{0,64}["\']\s*\.\s*["\'][^"\']{0,64}["\']/', $content )
				|| preg_match( '/(?:compress\.zlib|php|data|phar|zip|rar|ogg|expect):\/\//i', $content )
			)
		) {
			return array(
				'type'        => 'backdoor_obfuscated_include',
				'name'        => 'Backdoor:PHP/obfuscated-include — Obfuscated Include',
				'description' => 'Includes a file whose path is assembled from concatenated string fragments or a PHP stream wrapper — a common evasion technique used by backdoors to hide their payload from signature scanners.',
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
	 * Patterns flagged with 'uploads_only' => true OR 'trusted_skip' => true are
	 * skipped for files in trusted locations. Clear web-shell signatures (c99,
	 * r57, WSO, polyglot, $_POST command injection, etc.) are ALWAYS applied
	 * regardless of location.
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
			$dir = WP_PLUGIN_DIR . '/' . $slug;
			if ( is_dir( $dir ) ) {
				$real_dir = str_replace( '\\', '/', (string) realpath( $dir ) );
				if ( $real_dir && strpos( $norm_real, $real_dir . '/' ) === 0 ) {
					return false;
				}
			}
		}

		// Wordfence WAF logs.
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
		// KNOWN-GOOD VERIFICATION (Wordfence-style repository check).
		// A file that matches the official wordpress.org plugin/theme checksums
		// (path + MD5) is trusted and skipped. A file whose path matches but
		// hash DIFFERS has been modified — likely injected — so it is flagged.
		// ------------------------------------------------------------------
		$known_state = Turbo_Guard_Known_Files::check_file( $real_file_path, $norm_real );
		if ( 'known_good' === $known_state ) {
			return false;
		}
		if ( 'modified' === $known_state ) {
			$wpdb->insert(
				$wpdb->prefix . 'turbo_guard_scan_results',
				array(
					'scan_id'        => $this->scan_id,
					'file_path'      => $file_path,
					'threat_type'    => 'modified_plugin_file',
					'severity'       => 'high',
					'threat_name'    => __( 'Modified Plugin/Theme File', 'turbo-guard' ),
					'threat_details' => __( 'This file is part of an official wordpress.org plugin or theme, but its content has been modified. This is a strong indicator of an injected backdoor.', 'turbo-guard' ),
					'status'         => 'pending',
					'file_size'      => (int) @filesize( $file_path ),
					'file_hash'      => md5_file( $real_file_path ),
				),
				array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
			);
			return true;
		}

		// ------------------------------------------------------------------
		// CRITICAL EARLY CHECK A: PHP files in core asset directories.
		//
		// Strategy: flag PHP files in any /images/ subdirectory inside
		// wp-admin or wp-includes. WordPress never ships PHP inside an
		// images directory regardless of nesting depth.
		// Also flag PHP in wp-includes/css/ — BUT modern WordPress DOES ship
		// a few legitimate PHP files there (e.g. css/dist/registry.php), so
		// any file that exists in the official core manifest is skipped first.
		// ------------------------------------------------------------------

		// A PHP file in a core asset directory is only suspicious when it is
		// NOT part of the official WordPress distribution. Consult the core
		// checksums manifest and skip any genuine core file.
		if ( $is_php && self::is_core_file( $norm_real ) ) {
			return false;
		}

		$core_no_php_dirs = array(
			ABSPATH . 'wp-admin/images',
			ABSPATH . 'wp-admin/css',
			ABSPATH . 'wp-admin/js',
			ABSPATH . 'wp-includes/images',
			ABSPATH . 'wp-includes/css',
		);

		// Also catch PHP in any nested /images/ dir inside wp-admin
		// e.g. wp-admin/js/widgets/images/index.php
		$wp_admin_real_check = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-admin' ) );
		if ( $is_php && $wp_admin_real_check && strpos( $norm_real, $wp_admin_real_check . '/' ) === 0 ) {
			if ( preg_match( '~/images/~', $norm_real ) ) {
				$snippet      = @file_get_contents( $file_path, false, null, 0, 4096 ); // phpcs:ignore
				$threat_class = self::classify_backdoor( $snippet ? $snippet : '' );
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
							str_replace( ABSPATH, '', dirname( $file_path ) ) . '/',
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
								str_replace( ABSPATH, '', dirname( $file_path ) ) . '/',
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
										str_replace( WP_CONTENT_DIR, 'wp-content', dirname( $file_path ) ) . '/',
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
							str_replace( ABSPATH, '', $file_path )
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

		$wp_admin_real    = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-admin' ) );
		$wp_includes_real = str_replace( '\\', '/', (string) realpath( ABSPATH . 'wp-includes' ) );
		if (
			( $wp_admin_real    && strpos( $norm_real, $wp_admin_real    . '/' ) === 0 ) ||
			( $wp_includes_real && strpos( $norm_real, $wp_includes_real . '/' ) === 0 )
		) {
			// ------------------------------------------------------------------
			// CORE LOCATION FILE CHECK.
			//
			// WordPress ships a known set of files. When the official checksums
			// manifest is available, ANY PHP file in wp-admin/ or wp-includes/
			// that is not in the manifest is suspicious on its own — this is
			// Wordfence's "Unknown file in WordPress core" detection and does
			// NOT rely on signature matching (a hacker can trivially obfuscate
			// a shell to dodge any fixed signature).
			//
			// When the manifest is UNAVAILABLE (offline), fall back to concrete
			// signature checks only, to avoid flagging clean files we cannot
			// verify against the official distribution.
			// ------------------------------------------------------------------

			$manifest = self::get_core_manifest();
			$rel_path = str_replace(
				str_replace( '\\', '/', (string) realpath( ABSPATH ) ) . '/',
				'',
				$norm_real
			);

			if ( ! empty( $manifest ) ) {
				if ( isset( $manifest[ $rel_path ] ) ) {
					// Legitimate core file — skip (handled by File Integrity).
					return false;
				}

				// WHITELIST: Common legitimate files in core dirs that aren't in manifest.
				$core_basename    = basename( $rel_path );
				$core_whitelisted = in_array( $core_basename, array(
					'error_log', 'php_errorlog', '.htaccess', 'php.ini', '.user.ini',
				), true );

				if ( $core_whitelisted ) {
					return false;
				}

				// Unknown file in a core directory. Use a concrete backdoor name
				// when a signature matches, otherwise flag as an unknown file.
				$snippet      = @file_get_contents( $file_path, false, null, 0, 4096 ); // phpcs:ignore
				$threat_class = self::classify_backdoor( $snippet ? $snippet : '' );
				$has_signature = ( 'injected_php_unknown' !== $threat_class['type'] );

				$wpdb->insert(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array(
						'scan_id'        => $this->scan_id,
						'file_path'      => $file_path,
						'threat_type'    => $has_signature ? $threat_class['type'] : 'unknown_core_file',
						'severity'       => $has_signature ? 'critical' : 'high',
						'threat_name'    => $has_signature ? $threat_class['name'] : __( 'Unknown File in WordPress Core Directory', 'turbo-guard' ),
						'threat_details' => $has_signature
							? sprintf(
								/* translators: 1: file path relative to ABSPATH, 2: threat classification description */
								__( 'File "%1$s" is in a WordPress core location and matches a known backdoor signature. %2$s', 'turbo-guard' ),
								$rel_path,
								$threat_class['description']
							)
							: sprintf(
								/* translators: %s: file path relative to ABSPATH */
								__( 'File "%s" is not distributed with WordPress and should not exist in a core directory. It may have been planted by an attacker. Verify and delete if not legitimate.', 'turbo-guard' ),
								$rel_path
							),
						'status'         => 'pending',
						'file_size'      => (int) @filesize( $file_path ),
						'file_hash'      => md5( $snippet ? $snippet : '' ),
					),
					array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
				);
				return true;
			}

			// Manifest unavailable (offline) — only flag concrete signatures to
			// avoid false positives on files we cannot verify.
			$snippet      = @file_get_contents( $file_path, false, null, 0, 4096 ); // phpcs:ignore
			$threat_class = self::classify_backdoor( $snippet ? $snippet : '' );
			if ( 'injected_php_unknown' !== $threat_class['type'] ) {
				$wpdb->insert(
					$wpdb->prefix . 'turbo_guard_scan_results',
					array(
						'scan_id'        => $this->scan_id,
						'file_path'      => $file_path,
						'threat_type'    => $threat_class['type'],
						'severity'       => 'critical',
						'threat_name'    => $threat_class['name'],
						'threat_details' => sprintf(
							/* translators: 1: file path relative to ABSPATH, 2: threat classification description */
							__( 'File "%1$s" is in a WordPress core location and matches a known backdoor signature. %2$s', 'turbo-guard' ),
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

			// Legitimate core file — skip further pattern checks.
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

		// SKIP: copies of this plugin's own source (e.g. a backup/duplicate
		// folder). The scanner's pattern definitions contain the literal
		// signature strings it searches for (c99shell, r57shell, WSO, ...),
		// so a copy of the plugin would otherwise match its own signatures
		// and be flagged as malware. We identify self by the package marker
		// rather than by directory name — a folder named "backup" must NOT
		// be blindly trusted, an attacker can place malware there.
		if ( false !== strpos( $content, '@package TurboGuard' ) ) {
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
						// Unknown file in the WordPress root. Use a concrete backdoor
						// name when a signature matches, otherwise flag as unknown.
						$snippet      = @file_get_contents( $file_path, false, null, 0, 4096 ); // phpcs:ignore
						$threat_class = self::classify_backdoor( $snippet ? $snippet : '' );
						$has_signature = ( 'injected_php_unknown' !== $threat_class['type'] );

						$wpdb->insert(
							$wpdb->prefix . 'turbo_guard_scan_results',
							array(
								'scan_id'        => $this->scan_id,
								'file_path'      => $file_path,
								'threat_type'    => $has_signature ? $threat_class['type'] : 'unknown_root_file',
								'severity'       => $has_signature ? 'critical' : 'high',
								'threat_name'    => $has_signature ? $threat_class['name'] : __( 'Unknown File in WordPress Root Directory', 'turbo-guard' ),
								'threat_details' => $has_signature
									? sprintf(
										/* translators: 1: file name, 2: threat classification */
										__( 'File "%1$s" is in the WordPress root directory and matches a known backdoor signature. %2$s', 'turbo-guard' ),
										$rel_path,
										$threat_class['description']
									)
									: sprintf(
										/* translators: %s: file name */
										__( 'File "%s" is not part of the WordPress distribution and should not exist in the root directory. It may have been planted by an attacker. Verify and delete if not legitimate.', 'turbo-guard' ),
										$rel_path
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

				// WHITELIST: known plugin directories that legitimately store PHP
				// files inside uploads (e.g. Redux Framework writes ace_editor.php,
				// color.php, etc.). Flagging these produces false positives on
				// healthy sites. Wordfence applies the same repository-aware logic.
				$rel_upload_path = substr( $norm_real, strlen( $real_upload ) + 1 );

				// Trusted plugin data directories in uploads — derived dynamically
				// from installed plugin slugs (see is_trusted_upload_path()).
				$is_allowed_upload = self::is_trusted_upload_path( $rel_upload_path );

				// WHITELIST: WordPress placeholder files ("Silence is golden") that
				// plugins legitimately drop in their own uploads folders (e.g. Simple
				// Custom CSS & JS, WP File Manager). These are not malware.
				$is_silence_placeholder = ( false !== stripos( $content, 'Silence is golden' ) );

				if ( ! $is_allowed_upload && ! $is_silence_placeholder ) {
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
		}

		// ------------------------------------------------------------------
		// CHECK: .suspected files — hosting providers rename hacked files.
		// Any .suspected file is evidence of a prior compromise.
		// ------------------------------------------------------------------
		if ( $is_suspected ) {
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
						str_replace( ABSPATH, '', $file_path )
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
								str_replace( ABSPATH, '', $file_path )
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

				// Skip generic obfuscation patterns (eval+base64, nobodycrew, etc.) for
				// files inside trusted plugin/theme directories. Legitimate plugins use
				// these code patterns (Wordfence-style false-positive prevention).
				if ( ! empty( $pattern_data['trusted_skip'] ) && $is_trusted_path ) {
					continue;
				}

				// Skip php_only patterns for non-PHP files.
				if ( ! empty( $pattern_data['php_only'] ) && ! $is_php ) {
					continue;
				}

				if ( preg_match( $pattern_data['pattern'], $content ) ) {
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

		if ( $severity ) {
			if ( ! empty( $ignored ) && is_array( $ignored ) ) {
				$placeholders = implode( ', ', array_fill( 0, count( $ignored ), '%s' ) );
				// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
				$results = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT * FROM {$wpdb->prefix}turbo_guard_scan_results
						 WHERE scan_id = %d AND severity = %s AND status = 'pending'
						 AND file_path NOT IN ($placeholders)
						 ORDER BY severity DESC, id ASC",
						array_merge( array( $scan_id, sanitize_key( $severity ) ), $ignored )
					)
				);
				// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
			} else {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$results = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT * FROM {$wpdb->prefix}turbo_guard_scan_results
						 WHERE scan_id = %d AND severity = %s AND status = 'pending'
						 ORDER BY severity DESC, id ASC",
						$scan_id,
						sanitize_key( $severity )
					)
				);
			}
		} else {
			if ( ! empty( $ignored ) && is_array( $ignored ) ) {
				$placeholders = implode( ', ', array_fill( 0, count( $ignored ), '%s' ) );
				// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
				$results = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT * FROM {$wpdb->prefix}turbo_guard_scan_results
						 WHERE scan_id = %d AND status = 'pending'
						 AND file_path NOT IN ($placeholders)
						 ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'info') ASC, id ASC",
						array_merge( array( $scan_id ), $ignored )
					)
				);
				// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
			} else {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$results = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT * FROM {$wpdb->prefix}turbo_guard_scan_results
						 WHERE scan_id = %d AND status = 'pending'
						 ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'info') ASC, id ASC",
						$scan_id
					)
				);
			}
		}

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
	 * Classify a file path by its origin — mirrors Wordfence's file provenance
	 * check ("Not a core, theme, or plugin file from wordpress.org").
	 *
	 * @since 1.3.0
	 * @param string $file_path Absolute file path.
	 * @return array { key: string, label: string, known: bool }
	 */
	public static function get_file_provenance( $file_path ) {
		$norm = str_replace( '\\', '/', $file_path );

		if ( false !== strpos( $norm, '/wp-admin/' ) || false !== strpos( $norm, '/wp-includes/' ) ) {
			return array(
				'key'   => 'core',
				'label' => __( 'WordPress core file', 'turbo-guard' ),
				'known' => true,
			);
		}
		if ( false !== strpos( $norm, '/wp-content/plugins/' ) ) {
			return array(
				'key'   => 'plugin',
				'label' => __( 'Plugin file', 'turbo-guard' ),
				'known' => true,
			);
		}
		if ( false !== strpos( $norm, '/wp-content/themes/' ) ) {
			return array(
				'key'   => 'theme',
				'label' => __( 'Theme file', 'turbo-guard' ),
				'known' => true,
			);
		}
		if ( false !== strpos( $norm, '/wp-content/uploads/' ) ) {
			return array(
				'key'   => 'upload',
				'label' => __( 'File in uploads directory', 'turbo-guard' ),
				'known' => false,
			);
		}

		return array(
			'key'   => 'unknown',
			'label' => __( 'Not a core, theme, or plugin file from wordpress.org', 'turbo-guard' ),
			'known' => false,
		);
	}

	/**
	 * Get the most recent scan.
	 *
	 * @since 1.0.0
	 * @return object|null Scan row or null.
	 */
	public static function get_latest_scan() {
		global $wpdb;

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
	 * Checks wp_posts (content/excerpts), wp_options (siteurl/home/tagline),
	 * WP-Cron jobs, .htaccess redirects, hidden folders, recent admin users,
	 * and — via baseline comparison — unknown tables and unknown options.
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
				'pattern'       => 'viagra',
				'name'          => 'Pharma Spam in Database',
				'severity'      => 'high',
				'type'          => 'db_pharma_spam',
				'word_boundary' => true,
			),
			array(
				'pattern'       => 'cialis',
				'name'          => 'Pharma Spam in Database',
				'severity'      => 'high',
				'type'          => 'db_pharma_spam',
				'word_boundary' => true, // Avoid matching "cialis" inside "specialist".
			),
			array(
				'pattern'       => 'casino',
				'name'          => 'Casino Spam in Database',
				'severity'      => 'high',
				'type'          => 'db_casino_spam',
				'word_boundary' => true,
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
			$needs_content = ! empty( $pattern_data['word_boundary'] );
			$select        = $needs_content
				? 'ID, post_title, post_type, post_status, post_content, post_excerpt'
				: 'ID, post_title, post_type, post_status';

			// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $select is a fixed allowlist (column list), never user input.
			$results = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT {$select}
					 FROM {$wpdb->posts}
					 WHERE (post_content LIKE %s OR post_excerpt LIKE %s)
					 AND post_status NOT IN ('auto-draft','trash')
					 LIMIT 50",
					'%' . $wpdb->esc_like( $pattern_data['pattern'] ) . '%',
					'%' . $wpdb->esc_like( $pattern_data['pattern'] ) . '%'
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

			foreach ( $results as $post ) {
				// Skip if we already reported this post for a higher-priority pattern.
				if ( isset( $reported_post_ids[ $post->ID ] ) ) {
					continue;
				}

				// Word-boundary validation: confirm the keyword is a standalone word,
				// not a substring of a longer word (e.g. "cialis" inside "specialist").
				if ( $needs_content ) {
					$haystack = ( isset( $post->post_content ) ? $post->post_content : '' )
						. ' '
						. ( isset( $post->post_excerpt ) ? $post->post_excerpt : '' );
					$regex    = '/\b' . preg_quote( $pattern_data['pattern'], '/' ) . '\b/i';
					if ( ! preg_match( $regex, $haystack ) ) {
						continue; // Substring match only — false positive.
					}
				}

				$reported_post_ids[ $post->ID ] = true;

				$path = 'database://wp_posts#' . $post->ID . ' (' . $post->post_type . ': ' . wp_trim_words( $post->post_title, 8, '...' ) . ')';
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
				if ( ! empty( $pattern_data['word_boundary'] ) ) {
					$is_match = (bool) preg_match( '/\b' . preg_quote( $pattern_data['pattern'], '/' ) . '\b/i', $value );
				} else {
					$is_match = ( false !== stripos( $value, $pattern_data['pattern'] ) );
				}

				if ( $is_match ) {
					$path = 'database://wp_options#' . $option_name;
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
		$htaccess_files = array(
			ABSPATH . '.htaccess',
			WP_CONTENT_DIR . '/.htaccess',
			wp_upload_dir()['basedir'] . '/.htaccess',
		);
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
		$suspicious_dirs = array(
			ABSPATH . 'wp-admin/images',
			ABSPATH . 'wp-admin/css',
			ABSPATH . 'wp-admin/js',
			wp_upload_dir()['basedir'],
		);
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

		// -----------------------------------------------------------
		// 7. Unknown database tables (hacker-created tables).
		// -----------------------------------------------------------
		$threats_found += self::detect_unknown_tables( $scan_id );

		// -----------------------------------------------------------
		// 8. Unknown wp_options rows (hacker-created options).
		// -----------------------------------------------------------
		$threats_found += self::detect_unknown_options( $scan_id );

		return $threats_found;
	}

	/**
	 * Detect database tables that were not present when the baseline was
	 * recorded. Hackers often create helper tables (e.g. wp_xyz_payload) to
	 * store injected content that file and pattern scans would never see.
	 *
	 * Baseline-based on purpose: only NEW tables are flagged, so pre-existing
	 * tables from legitimate plugins never trigger false positives.
	 *
	 * @since 1.1.3
	 * @param int $scan_id Current scan ID.
	 * @return int Number of unknown tables flagged.
	 */
	private static function detect_unknown_tables( $scan_id ) {
		global $wpdb;

		$baseline_option = 'turbo_guard_db_tables_baseline';
		$baseline        = get_option( $baseline_option, array() );
		if ( ! is_array( $baseline ) ) {
			$baseline = array();
		}

		$tables = $wpdb->get_col( 'SHOW TABLES' );
		if ( empty( $tables ) ) {
			return 0;
		}

		// First run: record the current schema as the trusted baseline.
		if ( empty( $baseline ) ) {
			update_option( $baseline_option, $tables, false );
			return 0;
		}

		$baseline_map = array_fill_keys( $baseline, true );
		$found        = 0;

		foreach ( $tables as $table ) {
			if ( isset( $baseline_map[ $table ] ) ) {
				continue;
			}

			$wpdb->insert(
				$wpdb->prefix . 'turbo_guard_scan_results',
				array(
					'scan_id'        => $scan_id,
					'file_path'      => 'database://table:' . $table,
					'threat_type'    => 'unknown_table',
					'severity'       => 'high',
					'threat_name'    => 'Unknown Database Table Detected',
					'threat_details' => sprintf(
						/* translators: %s: database table name */
						__( 'Table "%s" was not present when the database baseline was recorded. It may have been created by an attacker, or by a recently installed/updated plugin. Verify before deleting.', 'turbo-guard' ),
						$table
					),
					'status'         => 'pending',
					'file_size'      => 0,
					'file_hash'      => '',
				),
				array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
			);
			++$found;
		}

		// Refresh the baseline so each new table is reported once, not every scan.
		update_option( $baseline_option, $tables, false );

		return $found;
	}

	/**
	 * Detect wp_options rows (option names) that were not present when the
	 * baseline was recorded. Hackers often add hidden options (redirects,
	 * payloads) that a pattern-based scan would miss.
	 *
	 * Transients are ignored — they are created/expired constantly and are
	 * never a meaningful "unknown row" signal.
	 *
	 * @since 1.1.3
	 * @param int $scan_id Current scan ID.
	 * @return int Number of unknown options flagged.
	 */
	private static function detect_unknown_options( $scan_id ) {
		global $wpdb;

		$baseline_option = 'turbo_guard_db_options_baseline';
		$baseline        = get_option( $baseline_option, array() );
		if ( ! is_array( $baseline ) ) {
			$baseline = array();
		}

		$options = $wpdb->get_col( "SELECT option_name FROM {$wpdb->options}" );
		if ( empty( $options ) ) {
			return 0;
		}

		// First run: record the current option names as the trusted baseline.
		if ( empty( $baseline ) ) {
			update_option( $baseline_option, $options, false );
			return 0;
		}

		$baseline_map = array_fill_keys( $baseline, true );
		$found        = 0;

		foreach ( $options as $option ) {
			// Skip the plugin's own baseline keys (they are added during scans
			// and must never be flagged as "new options").
			if ( 'turbo_guard_db_tables_baseline' === $option || 'turbo_guard_db_options_baseline' === $option ) {
				continue;
			}

			// Skip all transients (regular + network) — high churn, not a signal.
			if ( 0 === strpos( $option, '_transient' ) || 0 === strpos( $option, '_site_transient' ) ) {
				continue;
			}

			if ( isset( $baseline_map[ $option ] ) ) {
				continue;
			}

			$wpdb->insert(
				$wpdb->prefix . 'turbo_guard_scan_results',
				array(
					'scan_id'        => $scan_id,
					'file_path'      => 'database://wp_options#' . $option,
					'threat_type'    => 'unknown_option',
					'severity'       => 'medium',
					'threat_name'    => 'New WordPress Option Detected',
					'threat_details' => sprintf(
						/* translators: %s: option name */
						__( 'Option "%s" was not present when the database baseline was recorded. It may have been added by an attacker, or by a recently installed/updated plugin. Review its value before removing.', 'turbo-guard' ),
						$option
					),
					'status'         => 'pending',
					'file_size'      => 0,
					'file_hash'      => '',
				),
				array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
			);
			++$found;
		}

		// Refresh the baseline so each new option is reported once.
		update_option( $baseline_option, $options, false );

		return $found;
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
		// ---------------------------------------------------------------------
		// SECURITY: never trust client-supplied IP headers unconditionally.
		// `X-Forwarded-For` and `HTTP_CLIENT_IP` are set by the client and can be
		// spoofed to bypass rate limiting, brute-force lockout and the IP
		// blocklist. By default only `REMOTE_ADDR` (set by the web server) is
		// trusted. When WordPress sits behind a known proxy/CDN (Cloudflare,
		// Sucuri, a reverse proxy, ...) the admin registers that proxy's IP/CIDR
		// via the `turbo_guard_trusted_proxies` filter; only then are forwarded
		// headers parsed.
		// ---------------------------------------------------------------------

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
		$remote_addr = filter_var( $remote_addr, FILTER_VALIDATE_IP ) ? $remote_addr : '';

		// Direct connection (or an untrusted peer): REMOTE_ADDR is authoritative.
		if ( $remote_addr && ! self::is_trusted_proxy( $remote_addr ) ) {
			return $remote_addr;
		}

		// Behind a trusted proxy: walk the X-Forwarded-For chain right-to-left
		// and return the first address that is NOT itself a trusted proxy (the
		// real client). The rightmost entry is the one appended by the proxy
		// closest to us; the leftmost is the original, spoofable client value.
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$chain = explode( ',', wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			for ( $i = count( $chain ) - 1; $i >= 0; $i-- ) {
				$candidate = filter_var( trim( $chain[ $i ] ), FILTER_VALIDATE_IP );
				if ( $candidate && ! self::is_trusted_proxy( $candidate ) ) {
					return $candidate;
				}
			}
		}

		// No usable forwarded address — fall back to the peer address.
		return $remote_addr;
	}

	/**
	 * Whether an IP address belongs to a configured trusted proxy/CDN.
	 *
	 * Trusted proxies are registered via the `turbo_guard_trusted_proxies` filter
	 * as an array of exact IPs or IPv4/IPv6 CIDR blocks, e.g.:
	 *
	 *     add_filter( 'turbo_guard_trusted_proxies', function () {
	 *         return array( '173.245.48.0/20', '103.21.244.0/22' ); // Cloudflare.
	 *     } );
	 *
	 * When empty (the default), only REMOTE_ADDR is trusted and no forwarded
	 * header is ever honoured.
	 *
	 * @since 1.1.4
	 * @param string $ip Client/peer IP address.
	 * @return bool True if the IP is a trusted proxy.
	 */
	private static function is_trusted_proxy( $ip ) {
		static $trusted = null;

		if ( null === $trusted ) {
			$trusted = array();
			$rules   = (array) apply_filters( 'turbo_guard_trusted_proxies', array() );
			foreach ( $rules as $rule ) {
				$rule = trim( (string) $rule );
				if ( '' !== $rule ) {
					$trusted[] = $rule;
				}
			}
		}

		foreach ( $trusted as $rule ) {
			if ( $ip === $rule ) {
				return true;
			}

			// CIDR block, e.g. "192.168.0.0/16" or "2001:db8::/32".
			if ( strpos( $rule, '/' ) !== false && self::ip_in_cidr_network( $ip, $rule ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Match an IP address against an IPv4 or IPv6 CIDR block.
	 *
	 * @since 1.1.4
	 * @param string $ip   IP address.
	 * @param string $cidr CIDR block, e.g. "10.0.0.0/8".
	 * @return bool
	 */
	private static function ip_in_cidr_network( $ip, $cidr ) {
		$parts = explode( '/', $cidr, 2 );
		if ( 2 !== count( $parts ) ) {
			return false;
		}

		list( $subnet, $bits ) = $parts;
		$bits = absint( $bits );

		// IPv4.
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			if ( $bits > 32 ) {
				return false;
			}
			$ip_long  = ip2long( $ip );
			$sub_long = ip2long( trim( $subnet ) );
			if ( false === $ip_long || false === $sub_long ) {
				return false;
			}
			$mask = $bits > 0 ? ( ~0 << ( 32 - $bits ) ) : 0;
			return ( $ip_long & $mask ) === ( $sub_long & $mask );
		}

		// IPv6.
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			if ( $bits > 128 ) {
				return false;
			}
			$ip_bin  = @inet_pton( $ip );
			$sub_bin = @inet_pton( trim( $subnet ) );
			if ( false === $ip_bin || false === $sub_bin ) {
				return false;
			}

			$full_bytes = (int) floor( $bits / 8 );
			$remain     = $bits % 8;

			if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $sub_bin, 0, $full_bytes ) ) {
				return false;
			}
			if ( $remain > 0 ) {
				$mask = 0xff << ( 8 - $remain );
				if ( ( ord( $ip_bin[ $full_bytes ] ) & $mask ) !== ( ord( $sub_bin[ $full_bytes ] ) & $mask ) ) {
					return false;
				}
			}

			return true;
		}

		return false;
	}
}
