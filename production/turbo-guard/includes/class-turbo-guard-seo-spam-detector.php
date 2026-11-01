<?php
/**
 * SEO Spam Detector — No OAuth Required.
 *
 * Detects Japanese/Chinese SEO spam that hackers have indexed in Google
 * by scanning local evidence on the site itself:
 *
 *  1. Spam posts/pages in the WordPress database (CJK titles/content)
 *  2. Spam files on disk (PHP files with CJK text)
 *  3. .htaccess redirect hacks
 *  4. wp_options contamination (siteurl, blogname, active_plugins)
 *  5. Sitemap entries that look like spam
 *  6. Google cache check via public search URL (no API key needed)
 *
 * This gives users immediate value without any Google Cloud setup.
 *
 * @package TurboGuard
 * @since   1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Security scanner requires direct database access.

/**
 * SEO Spam Detector.
 *
 * @since 1.2.0
 */
class Turbo_Guard_SEO_Spam_Detector {

	/**
	 * CJK Unicode ranges for detection.
	 * Covers Japanese (Hiragana, Katakana), Chinese (CJK Unified), Korean (Hangul).
	 */
	const CJK_REGEX = '/[\x{3040}-\x{30FF}\x{31F0}-\x{31FF}\x{4E00}-\x{9FFF}\x{3400}-\x{4DBF}\x{AC00}-\x{D7A3}]/u';

	/**
	 * A run of 3+ CJK characters — a real sentence/word, not a stray glyph.
	 *
	 * @since 1.1.7
	 */
	const CJK_RUN_REGEX = '/[\x{3040}-\x{30FF}\x{31F0}-\x{31FF}\x{4E00}-\x{9FFF}\x{3400}-\x{4DBF}\x{AC00}-\x{D7A3}]{3,}/u';

	/**
	 * Free-tier limit: number of SEO spam files a free user may delete in total.
	 *
	 * @since 1.1.7
	 */
	const FREE_FILE_DELETE_LIMIT = 2;

	/**
	 * Luxury-brand keywords — specific, high-signal brand names that are almost
	 * never legitimate on an unrelated site. Ambiguous common words ("coach",
	 * "ugg") are deliberately excluded: "coach" matches "life coach" and
	 * "ugg" is a low-value signal, both causing false positives on template
	 * marketplaces, e-commerce and content sites.
	 */
	const BRAND_KEYWORDS = array(
		'gucci', 'louis vuitton', 'chanel', 'prada', 'rolex', 'hermes', 'burberry',
		'oakley', 'ray-ban', 'tory burch', 'moncler', 'canada goose',
	);

	/**
	 * Pharma keywords — specific prescription drugs that are essentially always
	 * spam. "pharmacy" is excluded because it is a legitimate, common business
	 * (e.g. a "Pharmacy Shop" template or a real pharmacy site).
	 */
	const PHARMA_KEYWORDS = array(
		'viagra', 'cialis', 'levitra',
	);

	/**
	 * CJK spam keyword dictionary — Japanese and Chinese phrases that appear
	 * almost exclusively in SEO spam campaigns. Used both by has_spam_keyword()
	 * and looks_like_doorway_generator() to detect CJK-script spam content that
	 * has no Latin-script keyword equivalent.
	 *
	 * Japanese luxury brands, pharma, and counterfeit/discount phrases are listed
	 * first; Chinese luxury/spam equivalents follow.
	 *
	 * @since 1.5.0
	 */
	const CJK_SPAM_KEYWORDS = array(
		// Japanese luxury brand spam.
		'ブランド', 'ルイヴィトン', 'グッチ', 'シャネル', 'プラダ',
		'コーチ', 'エルメス', 'ロレックス', 'バーバリー', 'モンクレール',
		// Japanese pharma spam.
		'バイアグラ', 'シアリス', 'レビトラ',
		// Japanese counterfeit / discount spam.
		'激安', '最安値', '格安', '送料無料', 'コピー品',
		'スーパーコピー', '偽物', 'ブランドコピー',
		// Chinese luxury / spam keywords.
		'奢侈品', '名牌', '仿冒', '假货', '路易威登',
		'古驰', '特価', '低価', '山寨', '代購',
	);

	/**
	 * Run a full SEO spam detection scan.
	 *
	 * @since 1.2.0
	 * @return array Scan results.
	 */
	public static function run_scan() {
		// Clear the site cache before scanning so results are fresh.
		turbo_guard_clear_site_cache();

		// Always clear old cached results before running fresh.
		delete_transient( 'turbo_guard_seo_spam_results' );
		$results = array(
			'spam_posts'      => array(),
			'spam_options'    => array(),
			'htaccess_hacks'  => array(),
			'spam_files'      => array(),
			'spam_core_files' => array(),
			'google_link'     => '',
			'total'           => 0,
			'scanned_at'      => current_time( 'mysql' ),
		);

		$results['spam_posts']      = self::scan_posts_for_spam();
		$results['spam_options']    = self::scan_options_for_spam();
		$results['htaccess_hacks']  = self::scan_htaccess();
		$results['spam_files']      = self::scan_disk_for_spam();
		$results['spam_core_files'] = self::scan_core_for_spam();
		$results['google_link']     = self::build_google_check_url();

		$results['total'] = count( $results['spam_posts'] )
			+ count( $results['spam_options'] )
			+ count( $results['htaccess_hacks'] )
			+ count( $results['spam_files'] )
			+ count( $results['spam_core_files'] );

		// Cache for 6 hours.
		set_transient( 'turbo_guard_seo_spam_results', $results, 6 * HOUR_IN_SECONDS );

		// Log event.
		Turbo_Guard_Scanner::log_event(
			'seo_spam_scan',
			$results['total'] > 0 ? 'critical' : 'info',
			sprintf( 'SEO spam scan complete. %d spam indicators found.', $results['total'] )
		);

		// Let the Pro add-on extend results (AI analysis, auto-cleanup, etc.).
		do_action( 'turbo_guard_seo_spam_scan_complete', $results );

		// Send email alert if spam was found (Pro feature).
		if ( $results['total'] > 0 && turbo_guard_is_pro() && 'yes' === get_option( 'turbo_guard_notify_on_threats', 'yes' ) ) {
			self::send_seo_spam_alert( $results );
		}

		return $results;
	}

	/**
	 * Public post types that can hold real content (excludes internal/system
	 * types that would only add noise, e.g. revisions, attachments, menus).
	 *
	 * @since 1.1.7
	 * @return string[] Post type slugs.
	 */
	private static function get_content_post_types() {
		$exclude = array(
			'revision', 'attachment', 'nav_menu_item', 'custom_css',
			'customize_changeset', 'oembed_cache', 'user_request',
			'wp_block', 'wp_global_styles', 'wp_navigation',
			'wp_template', 'wp_template_part',
		);

		$types = array_diff( get_post_types( array( 'public' => true ), 'names' ), $exclude );

		return array_values( array_unique( $types ) );
	}

	/**
	 * Scan WordPress posts/pages for CJK spam content.
	 *
	 * @since 1.2.0
	 * @return array Spam post entries.
	 */
	private static function scan_posts_for_spam() {
		global $wpdb;
		$spam_posts = array();
		$batch_size = 200;
		$offset     = 0;

		// Paginate through all content post types so large sites are fully scanned.
		$post_types   = self::get_content_post_types();
		$type_holders = implode( ',', array_fill( 0, count( $post_types ), '%s' ) );

		do {
			$query = "SELECT ID, post_title, post_type, post_status, post_date, guid, post_name
				 FROM {$wpdb->posts}
				 WHERE post_status IN ('publish','draft','private')
				 AND post_type IN ($type_holders)
				 ORDER BY ID DESC
				 LIMIT %d OFFSET %d";

			$posts = $wpdb->get_results(
				$wpdb->prepare(
					$query,
					array_merge( $post_types, array( $batch_size, $offset ) ) // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- placeholders built from a fixed post-type list.
				)
			);

			foreach ( $posts as $post ) {
				if ( self::is_ignored( 'posts', $post->ID ) ) {
					continue;
				}

				$is_spam      = false;
				$spam_reasons = array();

				// Check for CJK in title — only suspicious when the site itself is
				// NOT a Japanese/Chinese/Korean-language site. Require either a
				// dictionary keyword hit OR high run density (≥5 distinct runs)
				// to suppress false positives from single translated words.
				if ( ! self::is_cjk_site() ) {
					$cjk_keyword_in_title = self::has_spam_keyword( $post->post_title );
					$cjk_runs_in_title    = self::count_distinct_cjk_runs( $post->post_title );
					if ( $cjk_keyword_in_title || $cjk_runs_in_title >= 5 ) {
						$is_spam        = true;
						$spam_reasons[] = $cjk_keyword_in_title
							? 'CJK spam keyword in title: ' . $cjk_keyword_in_title
							: 'CJK characters in title';
					}
				}

				// Check for spam keywords in title.
				$title_keyword = self::has_spam_keyword( $post->post_title );
				if ( $title_keyword ) {
					$is_spam        = true;
					$spam_reasons[] = 'Spam keyword in title: ' . $title_keyword;
				}

				// Check for spam keywords in the URL slug.
				$slug_keyword = self::has_spam_keyword( $post->post_name );
				if ( $slug_keyword ) {
					$is_spam        = true;
					$spam_reasons[] = 'Spam keyword in URL slug: ' . $slug_keyword;
				}

				// Numeric doorway slug: a post whose slug is a large number is a
				// doorway page injected by a Japanese SEO spam campaign
				// (e.g. /whatever/98254733 → post_name "98254733"). These have no
				// CJK text and no brand keyword, so they need their own check.
				if ( preg_match( '/^\d{4,}$/', (string) $post->post_name ) ) {
					$is_spam        = true;
					$spam_reasons[] = 'Numeric doorway slug';
				}

				if ( $is_spam ) {
					$spam_posts[] = array(
						'id'       => $post->ID,
						'title'    => $post->post_title,
						'type'     => $post->post_type,
						'status'   => $post->post_status,
						'date'     => $post->post_date,
						'url'      => get_permalink( $post->ID ),
						'reasons'  => $spam_reasons,
						'edit_url' => get_edit_post_link( $post->ID ),
					);
				}
			}

			$offset += $batch_size;
		} while ( count( $posts ) === $batch_size );

		// Also search post content for CJK — skipped entirely on CJK-language
		// sites, where Japanese/Chinese/Korean text is legitimate.
		// Note: CJK matching is done in PHP (not MySQL REGEXP) because MySQL's
		// REGEXP engine does not support PCRE \x{…} Unicode syntax, so the old
		// REGEXP query silently matched nothing.
		if ( ! self::is_cjk_site() ) {
			$existing_ids   = array_map( 'intval', array_column( $spam_posts, 'id' ) );
			$content_offset = 0;
			do {
				$cjk_posts = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT ID, post_title, post_type, post_status, post_content, post_excerpt
						 FROM {$wpdb->posts}
						 WHERE post_status = 'publish'
						 ORDER BY ID DESC
						 LIMIT %d OFFSET %d",
						$batch_size,
						$content_offset
					)
				);

				foreach ( $cjk_posts as $post ) {
					if ( self::is_ignored( 'posts', $post->ID ) ) {
						continue;
					}

					// Avoid duplicates from the title scan above.
					if ( in_array( (int) $post->ID, $existing_ids, true ) ) {
						continue;
					}

					$haystack = $post->post_content . ' ' . $post->post_excerpt;
					if ( ! preg_match( self::CJK_REGEX, $haystack ) ) {
						continue;
					}

					// Require a CJK spam keyword OR ≥5 distinct CJK runs to flag.
					// A single translated word (1 run, no keyword) must NOT be flagged.
					$cjk_keyword = self::has_spam_keyword( $haystack );
					$cjk_runs    = self::count_distinct_cjk_runs( $haystack );
					if ( ! $cjk_keyword && $cjk_runs < 5 ) {
						continue;
					}

					$spam_posts[] = array(
						'id'       => $post->ID,
						'title'    => $post->post_title,
						'type'     => $post->post_type,
						'status'   => $post->post_status,
						'date'     => '',
						'url'      => get_permalink( $post->ID ),
						'reasons'  => array( $cjk_keyword
							? 'CJK spam keyword in post content: ' . $cjk_keyword
							: 'CJK characters in post content' ),
						'edit_url' => get_edit_post_link( $post->ID ),
					);
					$existing_ids[] = (int) $post->ID;
				}

				$content_offset += $batch_size;
			} while ( count( $cjk_posts ) === $batch_size );
		}

		return $spam_posts;
	}

	/**
	 * Scan key wp_options for spam contamination.
	 *
	 * @since 1.2.0
	 * @return array Contaminated options.
	 */
	private static function scan_options_for_spam() {
		$contaminated = array();

		$check_options = array(
			'siteurl'         => 'Site URL',
			'home'            => 'Home URL',
			'blogname'        => 'Site Title',
			'blogdescription' => 'Tagline',
			'admin_email'     => 'Admin Email',
		);

		foreach ( $check_options as $key => $label ) {
			if ( self::is_ignored( 'options', $key ) ) {
				continue;
			}

			$value = get_option( $key, '' );
			if ( empty( $value ) ) {
				continue;
			}

			$reasons = array();
			if ( ! self::is_cjk_site() && preg_match( self::CJK_REGEX, $value ) ) {
				$reasons[] = 'Contains CJK (Japanese/Chinese/Korean) characters';
			}

			$value_keyword = self::has_spam_keyword( $value );
			if ( $value_keyword ) {
				$reasons[] = 'Contains spam keyword: ' . $value_keyword;
			}

			if ( ! empty( $reasons ) ) {
				$contaminated[] = array(
					'option'  => $key,
					'label'   => $label,
					'value'   => substr( $value, 0, 200 ),
					'reasons' => $reasons,
				);
			}
		}

		return $contaminated;
	}

	/**
	 * Scan .htaccess file for suspicious redirect rules.
	 *
	 * @since 1.2.0
	 * @return array Suspicious rules found.
	 */
	private static function scan_htaccess() {
		$suspicious = array();
		$htaccess   = ABSPATH . '.htaccess';

		if ( ! file_exists( $htaccess ) || ! is_readable( $htaccess ) ) {
			return $suspicious;
		}

		$content = file_get_contents( $htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $content ) {
			return $suspicious;
		}

		$lines = explode( "\n", $content );
		foreach ( $lines as $line_num => $line ) {
			$line_trimmed = trim( $line );

			// Skip WordPress standard rules and Turbo Guard rules.
			if (
				empty( $line_trimmed )
				|| strpos( $line_trimmed, '#' ) === 0
				|| strpos( $line_trimmed, '# BEGIN WordPress' ) !== false
				|| strpos( $line_trimmed, '# END WordPress' ) !== false
				|| strpos( $line_trimmed, '# Turbo Guard' ) !== false
			) {
				continue;
			}

			// Detect suspicious redirect patterns.
			$is_suspicious = false;
			$reason        = '';

			// Redirect to external domains.
			if ( preg_match( '/RewriteRule.*https?:\/\/(?!' . preg_quote( wp_parse_url( home_url(), PHP_URL_HOST ), '/' ) . ')/i', $line_trimmed ) ) {
				$is_suspicious = true;
				$reason        = 'Redirects to external domain';
			}

			// CJK in htaccess (very suspicious).
			if ( preg_match( self::CJK_REGEX, $line_trimmed ) ) {
				$is_suspicious = true;
				$reason        = 'Contains CJK characters';
			}

			// Encoded/obfuscated rules.
			if ( preg_match( '/base64_decode|eval\(|gzinflate/i', $line_trimmed ) ) {
				$is_suspicious = true;
				$reason        = 'Contains obfuscated code';
			}

			if ( $is_suspicious ) {
				$suspicious[] = array(
					'line'   => $line_num + 1,
					'rule'   => substr( $line_trimmed, 0, 200 ),
					'reason' => $reason,
				);
			}
		}

		return $suspicious;
	}

	/**
	 * Scan disk for PHP/HTML files containing CJK spam text.
	 * Scans wp-content (uploads, misc dirs, and wp-content root), skipping
	 * trusted plugin/theme/language dirs whose CJK text is legitimate.
	 *
	 * @since 1.2.0
	 * @return array Spam files found.
	 */
	private static function scan_disk_for_spam() {
		$spam_files  = array();
		$content_dir = wp_normalize_path( WP_CONTENT_DIR );

		if ( ! is_dir( $content_dir ) ) {
			return $spam_files;
		}

		// Pass 1: uploads + misc + wp-content root — spam content files
		// (CJK/brand/eval/base64). Code dirs are skipped here so the file cap is
		// not consumed before uploads are reached.
		$spam_files = self::scan_directory_for_spam(
			$content_dir,
			array( 'turbo-guard-quarantine', 'turbo-guard-backups', 'cache', 'languages', 'upgrade', 'plugins', 'themes', 'mu-plugins' ),
			false,
			1500
		);

		// Pass 2: plugins/themes/mu-plugins — doorway generator backdoors.
		foreach ( array( 'plugins', 'themes', 'mu-plugins' ) as $code_subdir ) {
			$dir = $content_dir . '/' . $code_subdir;
			if ( is_dir( $dir ) ) {
				$spam_files = array_merge(
					$spam_files,
					self::scan_directory_for_spam( $dir, array(), true, 4000 )
				);
			}
		}

		return $spam_files;
	}

	/**
	 * Scan WordPress core (wp-admin, wp-includes, and root PHP files) for
	 * injected doorway-generator backdoors and dropped PHP files.
	 *
	 * Two zero-false-positive signals:
	 * 1. A .php file inside a core ASSET directory (css/js/images/fonts) that is
	 *     NOT a genuine WordPress core file. Modern WordPress legitimately ships
	 *     PHP in wp-includes/fonts/ (class-wp-font-*.php), so every candidate is
	 *     verified against the official checksums (or, offline, against the
	 *     WordPress file docblock) before it is reported.
	 * 2. A doorway generator (numeric-ID rewrite rule + handler) inside a core
	 *     PHP file that is not pristine core code.
	 *
	 * @since 1.1.7
	 * @since 1.5.1 Genuine, unmodified core files are never reported (fixes the
	 *              false positives on wp-includes/fonts/*.php and
	 *              class-wp-post-type.php's own pagination rewrite rule).
	 * @return array Core spam entries.
	 */
	private static function scan_core_for_spam() {
		$spam = array();

		// 1. PHP files in core asset directories — injected unless the file is a
		//    genuine, unmodified WordPress core file.
		$asset_dirs = array(
			'wp-admin/images', 'wp-admin/css', 'wp-admin/js',
			'wp-includes/images', 'wp-includes/css', 'wp-includes/js',
			'wp-includes/fonts', 'wp-includes/certificates',
		);
		foreach ( $asset_dirs as $dir ) {
			$abs = wp_normalize_path( ABSPATH . $dir );
			if ( ! is_dir( $abs ) ) {
				continue;
			}
			foreach ( (array) glob( $abs . '/*.php' ) as $file ) {
				$rel = self::rel_path( $file );
				if ( self::is_suppressed_core_file( $rel ) || self::is_pristine_core_file( $file ) ) {
					continue;
				}
				$spam[] = self::core_file_entry(
					$file,
					array( __( 'PHP backdoor in WordPress core asset directory', 'turbo-guard' ) )
				);
			}
		}

		// 2. Doorway generators injected into core PHP files.
		$files = array();
		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			foreach ( (array) glob( ABSPATH . $dir . '/*.php' ) as $file ) {
				$files[] = $file;
			}
		}
		foreach ( array( 'wp-config.php', 'wp-settings.php', 'wp-load.php', 'index.php', 'wp-blog-header.php', 'wp-cron.php', 'wp-login.php', 'xmlrpc.php', 'wp-activate.php', 'wp-signup.php', 'wp-trackback.php', 'wp-comments-post.php', 'wp-mail.php', 'wp-links-opml.php' ) as $root_file ) {
			if ( is_file( ABSPATH . $root_file ) ) {
				$files[] = ABSPATH . $root_file;
			}
		}

		foreach ( array_unique( $files ) as $file ) {
			$rel = self::rel_path( $file );
			if ( self::is_suppressed_core_file( $rel ) || self::is_pristine_core_file( $file ) ) {
				continue;
			}
			$content = @file_get_contents( $file, false, null, 0, 262144 ); // phpcs:ignore
			if ( ! $content ) {
				continue;
			}
			if ( self::looks_like_doorway_generator( $content ) ) {
				$spam[] = self::core_file_entry(
					$file,
					array( __( 'Doorway spam generator injected into a WordPress core file', 'turbo-guard' ) )
				);
			}
		}

		return $spam;
	}

	/**
	 * Whether a core file is a genuine, unmodified WordPress file.
	 *
	 * Primary check: the file's MD5 matches the official wordpress.org checksum
	 * for the installed version. Offline fallback: genuine core PHP files carry
	 * the standard `@package WordPress` file docblock in their first 2 KB, which
	 * a dropped backdoor never has.
	 *
	 * @since 1.5.1
	 * @param string $abs_path Absolute file path.
	 * @return bool True if the file is pristine core code.
	 */
	private static function is_pristine_core_file( $abs_path ) {
		$abs_path = wp_normalize_path( (string) $abs_path );
		if ( '' === $abs_path || ! is_file( $abs_path ) ) {
			return false;
		}

		$norm_real = wp_normalize_path( (string) realpath( $abs_path ) );
		if ( '' !== $norm_real && class_exists( 'Turbo_Guard_Scanner' ) ) {
			$manifest = Turbo_Guard_Scanner::get_core_manifest();
			if ( ! empty( $manifest ) ) {
				return Turbo_Guard_Scanner::is_unmodified_core_file( $norm_real );
			}
		}

		$head = @file_get_contents( $abs_path, false, null, 0, 2048 ); // phpcs:ignore
		return is_string( $head ) && (bool) preg_match( '/@package\s+WordPress\b/i', $head );
	}

	/**
	 * Whether a core-file finding was ignored or marked as fixed by the admin.
	 *
	 * @since 1.5.1
	 * @param string $rel_path Path relative to ABSPATH.
	 * @return bool
	 */
	private static function is_suppressed_core_file( $rel_path ) {
		$rel_path = ltrim( str_replace( '\\', '/', (string) $rel_path ), '/' );
		if ( '' === $rel_path ) {
			return false;
		}
		return self::is_ignored( 'core_files', $rel_path ) || self::is_core_fixed( $rel_path );
	}

	/**
	 * Build a core-file scan entry (path relative to ABSPATH + size + mtime).
	 *
	 * @since 1.1.7
	 * @param string $abs_path Absolute file path.
	 * @param array  $reasons  Reasons to flag.
	 * @return array
	 */
	private static function core_file_entry( $abs_path, $reasons ) {
		$abs_path = wp_normalize_path( (string) $abs_path );
		return array(
			'path'     => self::rel_path( $abs_path ),
			'size'     => size_format( (int) @filesize( $abs_path ) ),
			'modified' => gmdate( 'Y-m-d H:i', (int) @filemtime( $abs_path ) ),
			'reasons'  => $reasons,
		);
	}

	/**
	 * Path relative to ABSPATH, normalised with forward slashes.
	 *
	 * @since 1.1.7
	 * @param string $abs_path Absolute path.
	 * @return string Relative path.
	 */
	private static function rel_path( $abs_path ) {
		return ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( (string) $abs_path ) ), '/' );
	}

	/**
	 * Scan a directory tree for spam files.
	 *
	 * @since 1.1.7
	 * @param string $base_dir     Directory to walk.
	 * @param array  $skip_dirs    Directory names to skip.
	 * @param bool   $is_code_dir  Whether these are plugin/theme files (stricter
	 *                             doorway-generator detection instead of CJK).
	 * @param int    $cap          Max files to inspect.
	 * @return array Spam files found.
	 */
	private static function scan_directory_for_spam( $base_dir, $skip_dirs, $is_code_dir, $cap ) {
		$spam_files  = array();
		$uploads_dir = wp_normalize_path( wp_upload_dir()['basedir'] );

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveCallbackFilterIterator(
					new RecursiveDirectoryIterator( $base_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
					function ( $current ) use ( $skip_dirs ) {
						if ( $current->isDir() ) {
							foreach ( $skip_dirs as $skip ) {
								if ( $current->getFilename() === $skip ) {
									return false;
								}
							}
						}
						return true;
					}
				)
			);

			$count = 0;
			foreach ( $iterator as $file ) {
				if ( $count > $cap ) {
					break;
				}
				if ( ! $file->isFile() ) {
					continue;
				}

				$ext = strtolower( $file->getExtension() );
				if ( ! in_array( $ext, array( 'php', 'html', 'htm', 'js' ), true ) ) {
					continue;
				}

				++$count;
				$path = wp_normalize_path( $file->getPathname() );

				// Skip trusted plugin data directories inside uploads (only
				// relevant to the non-code pass).
				if ( ! $is_code_dir ) {
					$rel_uploads = str_replace( $uploads_dir . '/', '', $path );
					if ( $rel_uploads !== $path && Turbo_Guard_Scanner::is_trusted_upload_path( $rel_uploads ) ) {
						continue;
					}
				}

				// Code dirs: trust files that exactly match the official
				// wordpress.org version of their plugin/theme (Wordfence-style
				// known-good verification). A known-good file is never spam, no
				// matter what code patterns it contains — this is the definitive
				// false-positive filter, not a hardcoded name list.
				if ( $is_code_dir && class_exists( 'Turbo_Guard_Known_Files' ) ) {
					$norm_real = wp_normalize_path( (string) realpath( $path ) );
					if ( 'known_good' === Turbo_Guard_Known_Files::check_file( $path, $norm_real ) ) {
						continue;
					}
				}

				// Read more for code dirs (the route hook and the payload can be
				// far apart in the file); 8KB is enough elsewhere.
				$read_len = $is_code_dir ? 262144 : 8192;
				$content  = @file_get_contents( $path, false, null, 0, $read_len ); // phpcs:ignore
				if ( ! $content ) {
					continue;
				}

				// Skip compiled Twig template cache files (e.g. WPML language
				// switcher templates). These are legitimate generated code and
				// never spam — they routinely contain words like "slot" that
				// overlap with our brand-keyword list. The "__TwigTemplate_"
				// class name is emitted by Twig's own compiler, so it is a
				// definitive, universal signature.
				if ( false !== strpos( $content, '__TwigTemplate_' ) ) {
					continue;
				}

				$reasons = array();

				// Code-dir files get a strict check: only a doorway spam generator
				// (numeric-ID route + Japanese or obfuscated payload) is flagged,
				// never translation text.
				if ( $is_code_dir ) {
					if ( self::looks_like_doorway_generator( $content ) ) {
						$reasons[] = 'Doorway spam generator (registers numeric-ID spam URLs)';
					}
				} elseif ( 'php' === $ext ) {
					// Detect WordPress standard placeholder files — always safe.
					if ( stripos( $content, 'Silence is golden' ) !== false ) {
						continue;
					}

					// CJK alone is only suspicious when the site is not CJK-language.
					// Require a spam keyword OR ≥5 distinct runs to avoid false positives
					// on files with a single translated word or stray CJK glyph.
					if ( ! self::is_cjk_site() ) {
						$cjk_kw   = self::has_spam_keyword( $content );
						$cjk_runs = self::count_distinct_cjk_runs( $content );
						if ( $cjk_kw || $cjk_runs >= 5 ) {
							$reasons[] = $cjk_kw
								? 'PHP file with CJK spam keyword in wp-content: ' . $cjk_kw
								: 'PHP file with Japanese/Chinese/Korean text in wp-content';
						}
					}
					if ( preg_match( '/eval\s*\(/i', $content ) ) {
						$reasons[] = 'PHP file with eval() in wp-content';
					}
					if ( preg_match( '/base64_decode\s*\(/i', $content ) ) {
						$reasons[] = 'PHP file with base64_decode() in wp-content';
					}
					if ( self::has_spam_keyword( $content ) ) {
						$reasons[] = 'PHP file with spam brand keywords in wp-content';
					}
				} elseif ( in_array( $ext, array( 'html', 'htm' ), true ) ) {
					if ( ! self::is_cjk_site() ) {
						$cjk_kw   = self::has_spam_keyword( $content );
						$cjk_runs = self::count_distinct_cjk_runs( $content );
						if ( $cjk_kw || $cjk_runs >= 5 ) {
							$reasons[] = $cjk_kw
								? 'HTML file with CJK spam keyword in wp-content: ' . $cjk_kw
								: 'HTML file with Japanese/Chinese text in wp-content';
						}
					}
					if ( self::has_spam_keyword( $content ) ) {
						$reasons[] = 'HTML file with spam keywords in wp-content';
					}
				} elseif ( 'js' === $ext ) {
					if ( ! self::is_cjk_site() ) {
						$cjk_kw   = self::has_spam_keyword( $content );
						$cjk_runs = self::count_distinct_cjk_runs( $content );
						if ( $cjk_kw || $cjk_runs >= 5 ) {
							$reasons[] = $cjk_kw
								? 'JS file with CJK spam keyword in wp-content: ' . $cjk_kw
								: 'JS file with Japanese/Chinese/Korean text in wp-content';
						}
					}
					if ( self::has_spam_keyword( $content ) ) {
						$reasons[] = 'JS file with spam keywords in wp-content';
					}
					if ( preg_match( '/eval\s*\(|base64_decode\s*\(|gzinflate\s*\(/i', $content ) ) {
						$reasons[] = 'JS file with obfuscated code in wp-content';
					}
				}

				if ( ! empty( $reasons ) ) {
					$rel_path = str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) );
					if ( self::is_ignored( 'files', $rel_path ) ) {
						continue;
					}

					$spam_files[] = array(
						'path'    => $rel_path,
						'size'    => size_format( $file->getSize() ),
						'modified'=> gmdate( 'Y-m-d H:i', $file->getMTime() ),
						'reasons' => $reasons,
					);
				}
			}
		} catch ( Exception $e ) {
			// Ignore filesystem errors.
		}

		return $spam_files;
	}

	/**
	 * Whether a PHP file looks like a doorway spam generator (the backdoor that
	 * injects numeric-ID spam URLs).
	 *
	 * Covers both common shapes:
	 *   - path doorway  (/whatever/98254733 via add_rewrite_rule / add_query_var)
	 *   - query doorway  (?items/123456.sthml via template_redirect / parse_request)
	 *
	 * A doorway generator either obfuscates its payload with Japanese/Chinese
	 * variable names (a definitive malware signature — legitimate code never
	 * does this), or handles a numeric-ID route/request and serves a Japanese or
	 * obfuscated payload. Translation files and normal plugins have none of
	 * these, so this stays specific and avoids false positives.
	 *
	 * @since 1.1.7
	 * @param string $content File content.
	 * @return bool
	 */
	private static function looks_like_doorway_generator( $content ) {
		// 1. Japanese/Chinese variable names (e.g. $假PNG头, $注入代码) — a
		//    definitive backdoor signature. Legitimate code never uses CJK
		//    variable names, so this alone is enough to flag.
		if ( preg_match( '/\$[\x{4E00}-\x{9FFF}\x{3400}-\x{4DBF}\x{3040}-\x{30FF}]{2,}/u', $content ) ) {
			return true;
		}

		// 1b. Dense CJK spam keyword cluster — a file containing 3 or more
		//     distinct entries from the CJK_SPAM_KEYWORDS dictionary is almost
		//     certainly a doorway content generator even if it has no numeric-ID
		//     route hooks. Each dictionary entry is counted once regardless of
		//     how many times it repeats in the file.
		$distinct_kw_matches = 0;
		foreach ( self::CJK_SPAM_KEYWORDS as $kw ) {
			if ( false !== mb_stripos( $content, $kw ) ) {
				++$distinct_kw_matches;
				if ( $distinct_kw_matches >= 3 ) {
					return true;
				}
			}
		}

		// 2. Numeric-ID doorway generation. Two shapes, with different confidence:
		//    (a) A rewrite RULE that maps a numeric-ID segment to a custom query
		//        var — the definitive path-doorway backdoor:
		//          add_rewrite_rule('^prize/([0-9]+)/?$', 'index.php?prize_id=$matches[1]', 'top')
		//          + add_filter('query_vars', ...) + add_action('template_redirect', ...)
		//        This is specific enough to flag on its own: legitimate plugins
		//        essentially never register a bare numeric-ID route, and security
		//        plugins (Wordfence, MalCare, …) never call add_rewrite_rule at
		//        all. The content it serves is usually cloaked (Googlebot-only)
		//        and fetched remotely or from the DB, so the file often has NO
		//        CJK text and NO base64/eval — requiring obfuscation here is what
		//        caused real doorway generators to be missed.
		//    (b) A request hook handling a numeric-ID query (?items/123456.html).
		//
		//    Shape (b) is weak on its own: template_redirect / parse_request /
		//    pre_get_posts hooks, \d+ regexes and base64_decode() strings are
		//    everywhere in legitimate security plugins because those plugins
		//    *detect* exactly those patterns. So shape (b) is only confirmed by
		//    actual Japanese/Chinese content — never by base64/eval alone.
		// Numeric route capture — [0-9]+ / [0-9]* / [0-9]{6,} / \d+ / \d{6,} etc.
		$numeric_route = '(?:\[0-9\][+*?]|\[0-9\]\{[0-9,]+\}|\\\\d[+*?]|\\\\d\{[0-9,]+\})';

		// WordPress core (class-wp-post-type.php) registers its own numeric
		// pagination rule ("…/{pagination_base}/([0-9]{1,})/?$"). That is a
		// legitimate numeric route, so exclude any rule built on the pagination
		// base before deciding this is a doorway.
		$numeric_rules = array();
		if ( preg_match_all(
			'/add_rewrite_rule\s*\(\s*([\'"])([^\'"]*?' . $numeric_route . '[^\'"]*?)\1/i',
			$content,
			$rule_matches
		) ) {
			foreach ( $rule_matches[2] as $numeric_rule ) {
				if ( false !== strpos( $numeric_rule, 'pagination_base' ) || false !== strpos( $numeric_rule, 'paged' ) ) {
					continue;
				}
				$numeric_rules[] = $numeric_rule;
			}
		}

		$has_numeric_rewrite = ! empty( $numeric_rules );
		if ( $has_numeric_rewrite ) {
			$has_handler = (bool) preg_match(
				'/add_query_var|query_vars|template_redirect|parse_request|pre_get_posts/i',
				$content
			);
			return $has_handler;
		}

		// Shape (b): query-string doorway — request hook + numeric, confirmed only
		// by real Japanese/Chinese content (see above).
		$has_numeric = (bool) preg_match( '/' . $numeric_route . '/', $content );
		if ( $has_numeric ) {
			$has_route = (bool) preg_match( '/add_query_var|template_redirect|parse_request|pre_get_posts/i', $content );
			if ( $has_route ) {
				$japanese_runs = (int) preg_match_all( self::CJK_RUN_REGEX, $content, $m );
				return $japanese_runs >= 3;
			}
		}

		return false;
	}

	/**
	 * Scan the site's own sitemap(s) for spam-looking URLs.
	 *
	 * Makes a local HTTP request to the site itself — no external service.
	 * Handles both a flat sitemap and a one-level sitemap index.
	 *
	 * Public so the GSC Cleanup page can reuse it for its zero-setup "scan your
	 * sitemap" mode (no Google OAuth required).
	 *
	 * @since 1.4.0
	 * @param bool $verify_content Whether to fetch a sample of doorway URLs to
	 *                             confirm they actually serve Japanese content.
	 *                             The full scan skips this for speed; the GSC
	 *                             cleanup page keeps it for accuracy.
	 * @return array Spam sitemap entries.
	 */
	public static function scan_sitemap( $verify_content = true ) {
		$entries = array();

		$candidates = array(
			'wp-sitemap.xml',
			'sitemap.xml',
			'sitemap_index.xml',
			'sitemap-index.xml',
			'page-sitemap.xml',
			'post-sitemap.xml',
		);

		$sitemap_url = '';
		foreach ( $candidates as $candidate ) {
			$url  = home_url( $candidate );
			$resp = wp_remote_get( $url, array( 'timeout' => 10, 'redirection' => 3 ) );

			if ( is_wp_error( $resp ) ) {
				continue;
			}

			$code = wp_remote_retrieve_response_code( $resp );
			$body = wp_remote_retrieve_body( $resp );
			if ( 200 !== (int) $code || empty( $body ) ) {
				continue;
			}

			if ( false !== stripos( $body, '<sitemapindex' ) || false !== stripos( $body, '<loc>' ) ) {
				$sitemap_url = $url;
				break;
			}
		}

		if ( ! $sitemap_url ) {
			return $entries;
		}

		$urls = self::extract_sitemap_urls( $sitemap_url, 0 );

		// Doorway candidates are collected so a small sample can be fetched and
		// verified for actual Japanese content below (prefix-agnostic signal).
		$doorway_candidates = array();

		foreach ( $urls as $entry_url ) {
			$path = (string) wp_parse_url( $entry_url, PHP_URL_PATH );
			if ( '' === $path ) {
				continue;
			}

			$reasons = array();

			if ( ! self::is_cjk_site() && preg_match( self::CJK_REGEX, rawurldecode( $path ) ) ) {
				$reasons[] = 'CJK characters in URL';
			}

			if ( self::is_doorway_spam_url( $entry_url ) ) {
				$reasons[]      = 'Auto-generated doorway spam URL (numeric ID signature)';
				$doorway_candidates[] = $entry_url;
			}

			$url_keyword = self::has_spam_keyword( rawurldecode( $path ) );
			if ( $url_keyword ) {
				$reasons[] = 'Spam keyword in URL: ' . $url_keyword;
			}

			if ( ! empty( $reasons ) ) {
				$entries[] = array(
					'url'     => $entry_url,
					'reasons' => $reasons,
				);
			}
		}

		// Content verification: fetch a small sample of doorway candidates and
		// confirm they actually serve Japanese keyword content. This is the
		// definitive signal and works no matter which prefix the campaign uses.
		if ( $verify_content ) {
			foreach ( self::verify_japanese_content( $doorway_candidates ) as $confirmed_url ) {
				$found = false;
				foreach ( $entries as &$entry ) {
					if ( $entry['url'] === $confirmed_url ) {
						$entry['reasons'][] = 'Confirmed: serves Japanese keyword content';
						$entry['reasons']   = array_unique( $entry['reasons'] );
						$found              = true;
						break;
					}
				}
				unset( $entry );

				if ( ! $found ) {
					$entries[] = array(
						'url'     => $confirmed_url,
						'reasons' => array( 'Confirmed: serves Japanese keyword content' ),
					);
				}
			}
		}

		// Bound the result set — doorway campaigns can inject thousands of URLs.
		return array_slice( $entries, 0, 500 );
	}

	/**
	 * Whether a URL matches the auto-generated "doorway" spam signature.
	 *
	 * Japanese/Chinese SEO spam campaigns auto-generate thousands of doorway
	 * URLs carrying a random numeric ID (e.g. /whatever/98254733, /x/163086450,
	 * /?foo/194927850). The word prefix changes between campaigns and even
	 * collides with legitimate slugs ("prize", "gift", "price", …), so the
	 * reliable signal is the large random numeric ID — never the word before it.
	 *
	 * @since 1.1.7
	 * @param string $url Full URL (path + query).
	 * @return bool
	 */
	private static function is_doorway_spam_url( $url ) {
		$url = strtolower( rawurldecode( (string) $url ) );

		// Standalone large numeric ID path segment: /whatever/98254733, /x/123456789/.
		// 6+ digits avoids year archives (/2024/) and ordinary 4-5 digit post IDs.
		if ( preg_match( '~/\d{6,}(?:[/?#]|$)~', $url ) ) {
			return true;
		}

		// Query-string doorway spam: /?whatever/194927850 or ?whatever=194927850.
		if ( preg_match( '#[?&][a-z0-9_-]+(?:/|=|%2f)\d{6,}#i', $url ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Fetch a sample of doorway candidates and confirm they serve Japanese
	 * keyword content (the definitive, prefix-agnostic signal).
	 *
	 * Uses a Googlebot user-agent to defeat user-agent cloaking (spam is often
	 * only served to crawlers). Returns the subset of URLs whose visible page
	 * text contains a run of CJK characters.
	 *
	 * A short per-request timeout keeps the scan responsive; the sample is
	 * capped so a huge doorway campaign doesn't hang the whole scan.
	 *
	 * @since 1.1.7
	 * @param array $urls Candidate doorway URLs.
	 * @return array Confirmed spam URLs.
	 */
	private static function verify_japanese_content( array $urls ) {
		$confirmed = array();
		if ( empty( $urls ) || self::is_cjk_site() ) {
			return $confirmed;
		}

		$urls = array_slice( array_values( $urls ), 0, 30 );

		foreach ( $urls as $url ) {
			$resp = wp_remote_get(
				$url,
				array(
					'timeout'     => 4,
					'redirection' => 2,
					'user-agent'  => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
				)
			);

			if ( is_wp_error( $resp ) ) {
				continue;
			}

			$body = wp_remote_retrieve_body( $resp );
			if ( empty( $body ) ) {
				continue;
			}

			// Match visible Japanese text only (strip markup/attributes).
			if ( preg_match( self::CJK_RUN_REGEX, wp_strip_all_tags( $body ) ) ) {
				$confirmed[] = $url;
			}
		}

		return $confirmed;
	}

	/**
	 * Recursively extract <loc> URLs from a sitemap or sitemap index.
	 *
	 * @since 1.4.0
	 * @param string $url   Sitemap URL.
	 * @param int    $depth Recursion depth.
	 * @return array URL strings.
	 */
	private static function extract_sitemap_urls( $url, $depth ) {
		$urls = array();

		if ( $depth > 1 ) {
			return $urls; // Only follow one level of sitemap index.
		}

		$resp = wp_remote_get( $url, array( 'timeout' => 10, 'redirection' => 3 ) );
		if ( is_wp_error( $resp ) ) {
			return $urls;
		}

		$code = wp_remote_retrieve_response_code( $resp );
		$body = wp_remote_retrieve_body( $resp );
		if ( 200 !== (int) $code || empty( $body ) ) {
			return $urls;
		}

		// Sitemap index: follow each child sitemap (limited to first 10).
		if ( false !== stripos( $body, '<sitemapindex' ) ) {
			preg_match_all( '/<loc>\s*(.*?)\s*<\/loc>/is', $body, $matches );
			$child_maps = array_slice( $matches[1], 0, 10 );
			foreach ( $child_maps as $child ) {
				$child = trim( html_entity_decode( $child ) );
				if ( $child ) {
					$urls = array_merge( $urls, self::extract_sitemap_urls( $child, $depth + 1 ) );
				}
			}
			return array_unique( $urls );
		}

		preg_match_all( '/<loc>\s*(.*?)\s*<\/loc>/is', $body, $matches );
		foreach ( $matches[1] as $loc ) {
			$loc = trim( html_entity_decode( $loc ) );
			if ( $loc ) {
				$urls[] = $loc;
			}
		}

		return array_unique( $urls );
	}

	/**
	 * Read the SEO-spam ignore list.
	 *
	 * @since 1.4.0
	 * @return array {posts:[], options:[], files:[]}
	 */
	public static function get_ignored() {
		$ignored = get_option( 'turbo_guard_seo_spam_ignored', array() );
		if ( ! is_array( $ignored ) ) {
			$ignored = array();
		}

		return wp_parse_args(
			$ignored,
			array(
				'posts'   => array(),
				'options' => array(),
				'files'   => array(),
			)
		);
	}

	/**
	 * Whether an item is on the SEO-spam ignore list.
	 *
	 * @since 1.4.0
	 * @param string $bucket 'posts', 'options', or 'files'.
	 * @param mixed  $key    Post ID (int), option name (string), or file path (string).
	 * @return bool
	 */
	private static function is_ignored( $bucket, $key ) {
		$ignored = self::get_ignored();
		if ( empty( $ignored[ $bucket ] ) || ! is_array( $ignored[ $bucket ] ) ) {
			return false;
		}

		if ( 'posts' === $bucket ) {
			// Post IDs arrive as strings from $wpdb but are stored as ints.
			$key = absint( $key );
			foreach ( $ignored[ $bucket ] as $ignored_key ) {
				if ( absint( $ignored_key ) === $key ) {
					return true;
				}
			}
			return false;
		}

		return in_array( (string) $key, array_map( 'strval', $ignored[ $bucket ] ), true );
	}

	/**
	 * Add an item to the SEO-spam ignore list and drop it from cached results.
	 *
	 * @since 1.4.0
	 * @param string $bucket 'posts', 'options', or 'files'.
	 * @param mixed  $key    Post ID (int), option name (string), or file path (string).
	 * @return bool Success.
	 */
	public static function ignore_item( $bucket, $key ) {
		$allowed = array( 'posts', 'options', 'files', 'core_files' );
		if ( ! in_array( $bucket, $allowed, true ) ) {
			return false;
		}

		if ( 'posts' === $bucket ) {
			$key = absint( $key );
			if ( ! $key ) {
				return false;
			}
		} else {
			$key = sanitize_text_field( $key );
			if ( '' === $key ) {
				return false;
			}
		}

		$ignored = self::get_ignored();
		if ( ! in_array( $key, $ignored[ $bucket ], true ) ) {
			$ignored[ $bucket ][] = $key;
		}

		update_option( 'turbo_guard_seo_spam_ignored', $ignored );

		// Remove from the current cached results so the item disappears immediately.
		if ( 'posts' === $bucket ) {
			self::remove_from_results( 'spam_posts', $key );
		} elseif ( 'options' === $bucket ) {
			self::remove_from_results( 'spam_options', $key );
		} elseif ( 'core_files' === $bucket ) {
			self::remove_from_results( 'spam_core_files', $key );
		} else {
			self::remove_from_results( 'spam_files', $key );
		}

		return true;
	}

	/**
	 * Remove an item from the cached scan results (used after delete/ignore).
	 *
	 * @since 1.4.0
	 * @param string $result_key One of spam_posts, spam_options, spam_files.
	 * @param mixed  $key        Identifier to match (id / option / path).
	 */
	private static function remove_from_results( $result_key, $key ) {
		$results = get_transient( 'turbo_guard_seo_spam_results' );
		if ( ! is_array( $results ) || empty( $results[ $result_key ] ) ) {
			return;
		}

		$id_field = 'spam_posts' === $result_key ? 'id' : ( 'spam_options' === $result_key ? 'option' : 'path' );

		$before = count( $results[ $result_key ] );
		$results[ $result_key ] = array_values(
			array_filter(
				$results[ $result_key ],
				function ( $item ) use ( $id_field, $key ) {
					return ( isset( $item[ $id_field ] ) && (string) $item[ $id_field ] !== (string) $key );
				}
			)
		);
		$after = count( $results[ $result_key ] );

		// Recalculate total.
		$results['total'] = max( 0, (int) $results['total'] - ( $before - $after ) );

		set_transient( 'turbo_guard_seo_spam_results', $results, 6 * HOUR_IN_SECONDS );
	}

	/**
	 * Number of spam posts a free user may clean (ceil 10%, minimum 1).
	 *
	 * @since 1.4.0
	 * @param int $total_spam_posts Total spam posts detected.
	 * @return int
	 */
	public static function free_deletable_count( $total_spam_posts ) {
		$total_spam_posts = absint( $total_spam_posts );
		if ( $total_spam_posts < 1 ) {
			return 0;
		}
		return max( 1, (int) ceil( $total_spam_posts * 0.10 ) );
	}

	/**
	 * Number of SEO spam files a free user has already deleted.
	 *
	 * @since 1.1.7
	 * @return int
	 */
	public static function free_file_deletions_used() {
		return (int) get_option( 'turbo_guard_seo_spam_files_deleted', 0 );
	}

	/**
	 * Number of SEO spam files a free user can still delete.
	 *
	 * The free tier can remove up to {@see FREE_FILE_DELETE_LIMIT} SEO spam files
	 * in total; Pro users are unlimited (handled by the caller via is_pro).
	 *
	 * @since 1.1.7
	 * @return int
	 */
	public static function free_file_deletions_remaining() {
		return max( 0, self::FREE_FILE_DELETE_LIMIT - self::free_file_deletions_used() );
	}

	/**
	 * Record a free-tier SEO spam file deletion against the quota.
	 *
	 * @since 1.1.7
	 */
	public static function increment_free_file_deletions() {
		update_option( 'turbo_guard_seo_spam_files_deleted', self::free_file_deletions_used() + 1 );
	}

	/**
	 * Number of infected CORE files a free user has already deleted.
	 *
	 * @since 1.5.1
	 * @return int
	 */
	public static function free_core_deletions_used() {
		return (int) get_option( 'turbo_guard_seo_spam_core_deleted', 0 );
	}

	/**
	 * Number of infected CORE files a free user can still delete.
	 *
	 * The free tier can remove up to {@see FREE_FILE_DELETE_LIMIT} infected core
	 * files in total; Pro users are unlimited (checked by the caller via is_pro).
	 *
	 * @since 1.5.1
	 * @return int
	 */
	public static function free_core_deletions_remaining() {
		return max( 0, self::FREE_FILE_DELETE_LIMIT - self::free_core_deletions_used() );
	}

	/**
	 * Record a free-tier infected core file deletion against the quota.
	 *
	 * @since 1.5.1
	 */
	public static function increment_free_core_deletions() {
		update_option( 'turbo_guard_seo_spam_core_deleted', self::free_core_deletions_used() + 1 );
	}

	/**
	 * Read the list of core files the admin marked as fixed.
	 *
	 * @since 1.5.1
	 * @return string[] Relative paths.
	 */
	public static function get_core_fixed() {
		$fixed = get_option( 'turbo_guard_seo_spam_core_fixed', array() );
		return is_array( $fixed ) ? array_values( array_map( 'strval', $fixed ) ) : array();
	}

	/**
	 * Whether a core file was marked as fixed.
	 *
	 * @since 1.5.1
	 * @param string $rel_path Path relative to ABSPATH.
	 * @return bool
	 */
	public static function is_core_fixed( $rel_path ) {
		$rel_path = ltrim( str_replace( '\\', '/', (string) $rel_path ), '/' );
		return '' !== $rel_path && in_array( $rel_path, self::get_core_fixed(), true );
	}

	/**
	 * Mark a core-file finding as fixed and drop it from the cached results.
	 *
	 * @since 1.5.1
	 * @param string $rel_path Path relative to ABSPATH.
	 * @return bool Success.
	 */
	public static function mark_core_fixed( $rel_path ) {
		$rel_path = ltrim( str_replace( '\\', '/', (string) $rel_path ), '/' );
		if ( '' === $rel_path ) {
			return false;
		}

		$fixed = self::get_core_fixed();
		if ( ! in_array( $rel_path, $fixed, true ) ) {
			$fixed[] = $rel_path;
			update_option( 'turbo_guard_seo_spam_core_fixed', $fixed );
		}

		self::remove_from_results( 'spam_core_files', $rel_path );
		return true;
	}

	/**
	 * Read the beginning of a core file flagged by the SEO spam scan.
	 *
	 * Used by the "View" action so the admin can inspect the injection before
	 * deciding to delete, ignore or restore the file.
	 *
	 * @since 1.5.1
	 * @param string $rel_path Path relative to ABSPATH.
	 * @param int    $limit    Max bytes to read.
	 * @return array|false { path, content, truncated } or false.
	 */
	public static function get_core_file_preview( $rel_path, $limit = 8192 ) {
		$rel_path = ltrim( str_replace( '\\', '/', (string) $rel_path ), '/' );
		if ( '' === $rel_path ) {
			return false;
		}

		$abs_path = wp_normalize_path( ABSPATH . $rel_path );
		if ( ! is_file( $abs_path ) || ! is_readable( $abs_path ) ) {
			return false;
		}

		$limit   = max( 1024, absint( $limit ) );
		$content = @file_get_contents( $abs_path, false, null, 0, $limit ); // phpcs:ignore
		if ( false === $content ) {
			return false;
		}

		return array(
			'path'      => $rel_path,
			'content'   => $content,
			'truncated' => @filesize( $abs_path ) > $limit, // phpcs:ignore
		);
	}

	/**
	 * Delete an infected WordPress core file flagged by the SEO spam scan.
	 *
	 * A genuine, unmodified core file is never deleted: the file must not match
	 * the official core checksum, and it must still be present in the cached
	 * scan results (so only files the scan actually flagged can be removed).
	 * A backup ZIP is created first, exactly like spam-file deletion.
	 *
	 * @since 1.5.1
	 * @param string $rel_path Path relative to ABSPATH.
	 * @return bool Success.
	 */
	public static function delete_core_file( $rel_path ) {
		$rel_path = ltrim( str_replace( '\\', '/', (string) $rel_path ), '/' );
		if ( '' === $rel_path ) {
			return false;
		}

		$abs_path = wp_normalize_path( ABSPATH . $rel_path );
		if ( ! is_file( $abs_path ) ) {
			return false;
		}

		$norm_real = wp_normalize_path( (string) realpath( $abs_path ) );
		if ( '' === $norm_real ) {
			return false;
		}

		// Never delete genuine core code.
		if ( self::is_pristine_core_file( $abs_path ) ) {
			return false;
		}

		// Only remove files the SEO spam scan actually flagged as core backdoors.
		$results = self::get_cached_results();
		$flagged = false;
		if ( is_array( $results ) && ! empty( $results['spam_core_files'] ) ) {
			foreach ( $results['spam_core_files'] as $core_file ) {
				if ( isset( $core_file['path'] ) && (string) $core_file['path'] === $rel_path ) {
					$flagged = true;
					break;
				}
			}
		}
		if ( ! $flagged ) {
			return false;
		}

		Turbo_Guard_Cleaner::backup_files( array( $abs_path ) );

		$deleted = wp_delete_file( $abs_path );
		$deleted = $deleted || ! file_exists( $abs_path );

		if ( $deleted ) {
			Turbo_Guard_Scanner::log_event(
				'seo_spam_core_file_deleted',
				'critical',
				sprintf(
					/* translators: %s: relative core file path */
					__( 'Infected WordPress core file deleted: %s', 'turbo-guard' ),
					$rel_path
				)
			);

			self::remove_from_results( 'spam_core_files', $rel_path );
		}

		return (bool) $deleted;
	}

	/**
	 * Delete a single SEO spam file found on disk.
	 *
	 * Safely resolves the (uploads-relative) path, verifies it was flagged by
	 * the current scan, creates a backup ZIP, then deletes the file and drops it
	 * from the cached results.
	 *
	 * @since 1.1.7
	 * @param string $rel_path Path relative to ABSPATH (as stored in scan results).
	 * @return bool Success.
	 */
	public static function delete_spam_file( $rel_path ) {
		$rel_path = ltrim( str_replace( '\\', '/', (string) $rel_path ), '/' );
		if ( '' === $rel_path ) {
			return false;
		}

		$abs_path = wp_normalize_path( ABSPATH . $rel_path );
		if ( ! is_file( $abs_path ) ) {
			return false;
		}

		// Safety: only delete inside wp-content, and never core files, our own
		// plugin, or a file that matches the official wordpress.org version of
		// its plugin/theme. Spam backdoors live in plugins/themes/mu-plugins as
		// well as uploads, so restricting to uploads made them undeletable.
		$file_real = wp_normalize_path( (string) realpath( $abs_path ) );
		if ( ! $file_real || ! self::is_safe_to_delete_file( $abs_path, $file_real ) ) {
			return false;
		}

		// Only remove files the SEO spam scan actually flagged.
		$results = self::get_cached_results();
		$flagged = false;
		if ( is_array( $results ) && ! empty( $results['spam_files'] ) ) {
			foreach ( $results['spam_files'] as $spam_file ) {
				if ( isset( $spam_file['path'] ) && (string) $spam_file['path'] === $rel_path ) {
					$flagged = true;
					break;
				}
			}
		}
		if ( ! $flagged ) {
			return false;
		}

		// Create a backup ZIP before deleting (ignored on failure — deletion proceeds).
		Turbo_Guard_Cleaner::backup_files( array( $abs_path ) );

		$deleted = wp_delete_file( $abs_path );
		$deleted = $deleted || ! file_exists( $abs_path );

		if ( $deleted ) {
			Turbo_Guard_Scanner::log_event(
				'seo_spam_file_deleted',
				'warning',
				sprintf(
					/* translators: %s: relative file path */
					__( 'SEO spam file deleted: %s', 'turbo-guard' ),
					$rel_path
				)
			);

			self::remove_from_results( 'spam_files', $rel_path );
		}

		return (bool) $deleted;
	}

	/**
	 * Whether a flagged file is safe to delete.
	 *
	 * Confines deletion to wp-content, and refuses to touch WordPress core
	 * files, the Turbo Guard plugin itself (and Pro), or any file that exactly
	 * matches the official wordpress.org version of its plugin/theme (the
	 * known-good index). This makes "delete" safe even if a false positive
	 * slips through the scan.
	 *
	 * @since 1.1.7
	 * @param string $abs_path  Absolute (non-resolved) path.
	 * @param string $norm_real Realpath, normalised with forward slashes.
	 * @return bool True if deletion is allowed.
	 */
	private static function is_safe_to_delete_file( $abs_path, $norm_real ) {
		// Must be inside wp-content — never core (wp-admin/wp-includes/wp-config.php…).
		$content_real = wp_normalize_path( (string) realpath( WP_CONTENT_DIR ) );
		if ( ! $content_real || 0 !== strpos( $norm_real, $content_real . '/' ) ) {
			return false;
		}

		// Never delete our own plugin files.
		$own_dirs = array();
		if ( defined( 'TURBO_GUARD_PLUGIN_DIR' ) ) {
			$own_dirs[] = wp_normalize_path( (string) realpath( TURBO_GUARD_PLUGIN_DIR ) );
		}
		if ( defined( 'TURBO_GUARD_PRO_PLUGIN_DIR' ) ) {
			$own_dirs[] = wp_normalize_path( (string) realpath( TURBO_GUARD_PRO_PLUGIN_DIR ) );
		}
		foreach ( $own_dirs as $own_dir ) {
			if ( $own_dir && 0 === strpos( $norm_real, $own_dir ) ) {
				return false;
			}
		}

		// Never delete a file that matches the official wordpress.org checksum
		// (a verified, unmodified plugin/theme file is never spam).
		if ( class_exists( 'Turbo_Guard_Known_Files' ) && 'known_good' === Turbo_Guard_Known_Files::check_file( $abs_path, $norm_real ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Send email alert about SEO spam findings (Pro).
	 *
	 * @since 1.4.0
	 * @param array $results Scan results.
	 */
	private static function send_seo_spam_alert( $results ) {
		$email = get_option( 'turbo_guard_notify_admin_email', get_option( 'admin_email' ) );
		if ( ! $email ) {
			return;
		}

		$subject = sprintf(
			/* translators: 1: site name, 2: count */
			__( '[%1$s] Turbo Guard: %2$d SEO Spam Indicators Found', 'turbo-guard' ),
			get_bloginfo( 'name' ),
			$results['total']
		);

		$body = sprintf(
			/* translators: %d: number of SEO spam indicators */
			__( "Turbo Guard SEO spam scan found %d issue(s):\n\n", 'turbo-guard' ),
			$results['total']
		);

		foreach ( $results['spam_posts'] as $post ) {
			$body .= sprintf( "Post: %s (ID %d) — %s\n", $post['title'], $post['id'], implode( ', ', $post['reasons'] ) );
		}

		foreach ( $results['spam_files'] as $file ) {
			$body .= sprintf( "File: %s — %s\n", $file['path'], implode( ', ', $file['reasons'] ) );
		}

		foreach ( $results['spam_core_files'] as $core_file ) {
			$body .= sprintf( "Core file: %s — %s\n", $core_file['path'], implode( ', ', $core_file['reasons'] ) );
		}

		$body .= "\n" . sprintf(
			/* translators: %s: URL to view SEO spam details */
			__( 'View details: %s', 'turbo-guard' ),
			admin_url( 'admin.php?page=turbo-guard-seo-spam' )
		);

		wp_mail( $email, $subject, $body );
	}

	/**
	 * Build a Google site: search URL so admin can manually check indexed pages.
	 *
	 * @since 1.2.0
	 * @return string Google search URL.
	 */
	private static function build_google_check_url() {
		$domain = wp_parse_url( home_url(), PHP_URL_HOST );
		// Search for site: indexed pages — admin clicks this to see what Google has.
		return 'https://www.google.com/search?q=site:' . rawurlencode( $domain );
	}

	/**
	 * Get cached SEO spam results.
	 *
	 * @since 1.2.0
	 * @return array|false
	 */
	public static function get_cached_results() {
		return get_transient( 'turbo_guard_seo_spam_results' );
	}

	/**
	 * Whether text contains a spam brand keyword, using whole-word matching.
	 *
	 * Only specific, high-signal luxury brands and prescription drugs are
	 * matched. Ambiguous common words ("coach", "pharmacy", "casino", "slot",
	 * "ugg", …) are deliberately NOT keywords — they are legitimate business
	 * categories and would flood template marketplaces, e-commerce and content
	 * sites with false positives.
	 *
	 * @since 1.1.7
	 * @param string $text Text to check.
	 * @return string|false The matched keyword, or false.
	 */
	/**
	 * Count non-overlapping CJK runs of 3+ consecutive CJK characters.
	 *
	 * A "distinct run" is each non-overlapping match returned by preg_match_all
	 * with CJK_RUN_REGEX. Used to apply a minimum-density threshold before
	 * flagging content that contains bare CJK characters (as opposed to content
	 * that contains an explicit CJK spam keyword).
	 *
	 * @since 1.5.0
	 * @param string $text Input text.
	 * @return int Number of distinct CJK runs found.
	 */
	private static function count_distinct_cjk_runs( $text ) {
		return (int) preg_match_all( self::CJK_RUN_REGEX, (string) $text );
	}

	public static function has_spam_keyword( $text ) {
		$text = (string) $text;
		if ( '' === $text ) {
			return false;
		}

		// Luxury brands — almost never legitimate on an unrelated site.
		foreach ( self::BRAND_KEYWORDS as $keyword ) {
			if ( preg_match( '/\b' . preg_quote( $keyword, '/' ) . '\b/i', $text ) ) {
				return $keyword;
			}
		}

		// Prescription drugs — essentially always spam.
		foreach ( self::PHARMA_KEYWORDS as $keyword ) {
			if ( preg_match( '/\b' . preg_quote( $keyword, '/' ) . '\b/i', $text ) ) {
				return $keyword;
			}
		}

		// CJK spam keywords (Japanese luxury brands, pharma, counterfeit/discount
		// phrases, and Chinese equivalents). mb_stripos is used instead of a regex
		// because CJK scripts have no concept of word boundaries (\b does not
		// apply to CJK codepoints).
		// This check applies even when is_cjk_site() returns true — the
		// is_cjk_site() bypass covers only bare CJK character presence, not
		// explicit spam keyword dictionary matching.
		foreach ( self::CJK_SPAM_KEYWORDS as $keyword ) {
			if ( false !== mb_stripos( $text, $keyword ) ) {
				return $keyword;
			}
		}

		return false;
	}

	/**
	 * Whether the site's own language is Japanese/Chinese/Korean.
	 *
	 * On CJK-language sites, Japanese/Chinese/Korean text is legitimate content,
	 * so the detector must NOT flag CJK text alone as spam — this prevents the
	 * most common false positive on shared hosting and international sites.
	 *
	 * @since 1.3.0
	 * @return bool
	 */
	private static function is_cjk_site() {
		// Manual override for sites with legitimate CJK content.
		if ( 'yes' === get_option( 'turbo_guard_seo_allow_cjk_content', 'no' ) ) {
			return true;
		}

		$locale = strtolower( get_locale() );
		return ( 0 === strpos( $locale, 'ja' )
			|| 0 === strpos( $locale, 'zh' )
			|| 0 === strpos( $locale, 'ko' ) );
	}

	/**
	 * Delete or trash a spam post.
	 *
	 * @since 1.2.0
	 * @since 1.4.0 Added $mode (trash|delete); trash is default and recoverable.
	 *
	 * @param int    $post_id WordPress post ID.
	 * @param string $mode    'trash' (default) or 'delete' (permanent, Pro).
	 * @return bool Success.
	 */
	public static function delete_spam_post( $post_id, $mode = 'trash' ) {
		$post_id = absint( $post_id );
		if ( ! $post_id ) {
			return false;
		}

		$mode = ( 'delete' === $mode ) ? 'delete' : 'trash';

		$result = ( 'delete' === $mode )
			? wp_delete_post( $post_id, true )
			: wp_trash_post( $post_id );

		if ( $result ) {
			Turbo_Guard_Scanner::log_event(
				'spam_post_deleted',
				'warning',
				sprintf(
					/* translators: 1: action taken, 2: post ID */
					__( 'Spam post %1$s: ID %2$d', 'turbo-guard' ),
					( 'delete' === $mode ? __( 'deleted permanently', 'turbo-guard' ) : __( 'moved to trash', 'turbo-guard' ) ),
					$post_id
				)
			);

			// Update cached results so the row disappears without a full re-scan.
			self::remove_from_results( 'spam_posts', $post_id );
		}

		return (bool) $result;
	}
}
